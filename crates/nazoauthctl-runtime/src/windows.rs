// Windows-native secure filesystem primitives.
//
// The controller must not use a shell-based ACL utility, environment-derived account names, or
// a check-then-open sequence for secrets.  This module keeps the security
// boundary in Win32: files are opened with `OPEN_REPARSE_POINT`, ACLs are
// written with `SetSecurityInfo`, and replacement is committed with
// `SetFileInformationByHandle(FileRenameInfo)`.

use std::{
    fs::{self, File},
    io::{self, Seek, SeekFrom, Write},
    mem::size_of,
    os::windows::{
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{self, null, null_mut},
};

use anyhow::{Context, bail};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE},
    Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo},
    Security::{
        ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAclInformation,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
        INHERIT_ONLY_ACE, InitializeAcl, InitializeSecurityDescriptor, MakeSelfRelativeSD,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        SE_DACL_PRESENT, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
        WinLocalSystemSid, WinWorldSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
        FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_CREATION_DISPOSITION,
        FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileRenameInfo, GetFileInformationByHandle, OPEN_EXISTING, OPEN_ALWAYS, READ_CONTROL,
        SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn wide(path: &Path) -> anyhow::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        bail!("path contains an embedded NUL: {}", path.display());
    }
    value.push(0);
    Ok(value)
}

fn win_error(context: &str) -> anyhow::Error {
    let code = unsafe { GetLastError() } as i32;
    anyhow::anyhow!(
        "{context}: {} (Win32 error {code})",
        io::Error::from_raw_os_error(code)
    )
}

fn check_bool(ok: i32, context: &str) -> anyhow::Result<()> {
    if ok == 0 {
        Err(win_error(context))
    } else {
        Ok(())
    }
}

fn check_code(code: u32, context: &str) -> anyhow::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{context}: Win32 error {code}"))
    }
}

fn current_user_sid() -> anyhow::Result<Vec<u8>> {
    let mut token: HANDLE = null_mut();
    check_bool(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        "OpenProcessToken",
    )?;
    let result = (|| {
        let mut needed = 0u32;
        let first = unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
        if first != 0
            || unsafe { GetLastError() }
                != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(win_error("GetTokenInformation(TokenUser size)"));
        }
        let mut buffer = vec![0u8; needed as usize];
        check_bool(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            },
            "GetTokenInformation(TokenUser)",
        )?;
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let sid_len = unsafe { windows_sys::Win32::Security::GetLengthSid(user.User.Sid) } as usize;
        if sid_len == 0 || unsafe { windows_sys::Win32::Security::IsValidSid(user.User.Sid) } == 0 {
            bail!("current TokenUser SID is invalid");
        }
        let mut sid = vec![0u8; sid_len];
        unsafe {
            ptr::copy_nonoverlapping(user.User.Sid.cast::<u8>(), sid.as_mut_ptr(), sid_len);
        }
        Ok(sid)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> anyhow::Result<Vec<u8>> {
    let mut needed = 0u32;
    let first = unsafe { CreateWellKnownSid(kind, null_mut(), null_mut(), &mut needed) };
    if first != 0
        || unsafe { GetLastError() } != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
    {
        return Err(win_error("CreateWellKnownSid size"));
    }
    let mut sid = vec![0u8; needed as usize];
    check_bool(
        unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut needed) },
        "CreateWellKnownSid",
    )?;
    sid.truncate(needed as usize);
    Ok(sid)
}

fn trusted_sids() -> anyhow::Result<[Vec<u8>; 3]> {
    Ok([
        current_user_sid()?,
        well_known_sid(WinLocalSystemSid)?,
        well_known_sid(WinBuiltinAdministratorsSid)?,
    ])
}

/// Translate the small Unix mode contract used by the controller into the
/// Windows access mask for one class of principals.  Writable owner files
/// retain the historical full-control grant (required for replacement and
/// ACL maintenance); read-only classes receive only the corresponding read or
/// execute rights.
fn mode_access_mask(bits: u32, owner: bool) -> u32 {
    let read = bits & 0o4 != 0;
    let write = bits & 0o2 != 0;
    let execute = bits & 0o1 != 0;
    if owner && write && read {
        return FILE_ALL_ACCESS;
    }
    let mut mask = 0;
    if read {
        mask |= FILE_GENERIC_READ;
    }
    if write {
        mask |= FILE_GENERIC_WRITE;
    }
    if execute {
        mask |= windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
    }
    mask
}

fn with_security_attributes<T>(
    mode: u32,
    is_directory: bool,
    operation: impl FnOnce(*mut SECURITY_ATTRIBUTES, *mut ACL) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    if mode & 0o022 != 0 {
        bail!("Windows secure ACL cannot grant non-owner write access");
    }
    let trusted = trusted_sids()?;
    let mut sids: Vec<Vec<u8>> = trusted.into_iter().collect();
    let trusted_mask = mode_access_mask((mode >> 6) & 0o7, true);
    let mut masks = vec![trusted_mask; sids.len()];
    let group_mask = mode_access_mask((mode >> 3) & 0o7, false);
    if group_mask != 0 {
        sids.push(well_known_sid(WinBuiltinUsersSid)?);
        masks.push(group_mask);
    }
    let other_mask = mode_access_mask(mode & 0o7, false);
    if other_mask != 0 {
        sids.push(well_known_sid(WinWorldSid)?);
        masks.push(other_mask);
    }
    let acl_size =
        (size_of::<ACL>() + sids.iter().map(|sid| 8usize + sid.len()).sum::<usize>()) as u32;
    let mut acl_bytes = vec![0u8; acl_size as usize];
    let acl = acl_bytes.as_mut_ptr().cast::<ACL>();
    check_bool(
        unsafe { InitializeAcl(acl, acl_size, ACL_REVISION) },
        "InitializeAcl",
    )?;
    let ace_flags = if is_directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    for (sid, mask) in sids.iter().zip(masks) {
        check_bool(
            unsafe {
                AddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, mask, sid.as_ptr() as PSID)
            },
            "AddAccessAllowedAceEx",
        )?;
    }
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    check_bool(
        unsafe {
            InitializeSecurityDescriptor((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(), 1)
        },
        "InitializeSecurityDescriptor",
    )?;
    check_bool(
        unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                acl,
                0,
            )
        },
        "SetSecurityDescriptorDacl",
    )?;
    check_bool(
        unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        },
        "SetSecurityDescriptorControl",
    )?;
    let mut descriptor_control = 0u16;
    let mut descriptor_revision = 0u32;
    check_bool(
        unsafe {
            GetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                &mut descriptor_control,
                &mut descriptor_revision,
            )
        },
        "GetSecurityDescriptorControl(create)",
    )?;
    if descriptor_control & SE_DACL_PROTECTED == 0 {
        bail!("failed to mark create-time DACL protected");
    }
    // CreateFileW/CreateDirectoryW consume a self-relative descriptor.  Passing
    // the stack-local absolute descriptor can preserve the ACEs while silently
    // dropping the protected-DACL control bit on the created object.
    let absolute = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    let mut relative_len = 0u32;
    let first = unsafe { MakeSelfRelativeSD(absolute, null_mut(), &mut relative_len) };
    if first != 0
        || unsafe { GetLastError() } != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
    {
        return Err(win_error("MakeSelfRelativeSD size"));
    }
    let mut relative = vec![0u8; relative_len as usize];
    check_bool(
        unsafe { MakeSelfRelativeSD(absolute, relative.as_mut_ptr().cast(), &mut relative_len) },
        "MakeSelfRelativeSD",
    )?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: relative.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    operation(&mut attributes, acl)
}

fn set_acl(handle: HANDLE, mode: u32) -> anyhow::Result<()> {
    let is_directory = {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        check_bool(
            unsafe { GetFileInformationByHandle(handle, &mut info) },
            "GetFileInformationByHandle(for ACL)",
        )?;
        info.dwFileAttributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
            != 0
    };
    with_security_attributes(mode, is_directory, |_attributes, acl| {
        check_code(
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut(),
                )
            },
            "SetSecurityInfo",
        )
    })
}

fn validate_descriptor(
    descriptor: *mut std::ffi::c_void,
    strict_owner: bool,
    private: bool,
) -> anyhow::Result<()> {
    if descriptor.is_null() {
        bail!("security descriptor is null");
    }
    let sids = trusted_sids()?;
    let sid = &sids[0];
    let mut owner: PSID = null_mut();
    let mut owner_defaulted = 0;
    check_bool(
        unsafe {
            windows_sys::Win32::Security::GetSecurityDescriptorOwner(
                descriptor,
                &mut owner,
                &mut owner_defaulted,
            )
        },
        "GetSecurityDescriptorOwner",
    )?;
    if owner.is_null() || (strict_owner && unsafe { EqualSid(owner, sid.as_ptr() as PSID) } == 0) {
        bail!("secure object owner is not the current TokenUser");
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    check_bool(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        "GetSecurityDescriptorControl",
    )?;
    if control & SE_DACL_PRESENT == 0 {
        bail!("secure object must have a present DACL");
    }
    if private && control & SE_DACL_PROTECTED == 0 {
        bail!("secure object must have a protected DACL");
    }
    let mut present = 0;
    let mut acl: *mut ACL = null_mut();
    let mut defaulted = 0;
    check_bool(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) },
        "GetSecurityDescriptorDacl",
    )?;
    if present == 0 || acl.is_null() {
        bail!("secure object has no DACL");
    }
    let mut size_info = ACL_SIZE_INFORMATION::default();
    check_bool(
        unsafe {
            GetAclInformation(
                acl,
                (&mut size_info as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                windows_sys::Win32::Security::AclSizeInformation,
            )
        },
        "GetAclInformation",
    )?;
    if private && size_info.AceCount != sids.len() as u32 {
        bail!("secure object DACL must contain only trusted ACEs");
    }
    let mut trusted_seen = [false; 3];
    for index in 0..size_info.AceCount {
        let mut ace_ptr: *mut std::ffi::c_void = null_mut();
        check_bool(
            unsafe { windows_sys::Win32::Security::GetAce(acl, index, &mut ace_ptr) },
            "GetAce",
        )?;
        if ace_ptr.is_null() {
            bail!("secure object DACL contains a null ACE");
        }
        let ace = unsafe { &*(ace_ptr.cast::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>()) };
        if private {
            if ace.Header.AceType != 0 || ace.Mask == 0 {
                bail!("secure object DACL contains a non-trusted or empty ACE");
            }
            let ace_sid = (&ace.SidStart as *const u32).cast::<std::ffi::c_void>() as PSID;
            let Some(index) = sids.iter().position(|candidate| unsafe {
                EqualSid(ace_sid, candidate.as_ptr() as PSID) != 0
            }) else {
                bail!("secure object DACL contains an untrusted principal");
            };
            if trusted_seen[index] {
                bail!("secure object DACL contains duplicate trusted ACEs");
            }
            trusted_seen[index] = true;
        } else if ace.Header.AceType == 0 && ace.Header.AceFlags & (INHERIT_ONLY_ACE as u8) == 0 {
            // A broad write ACE on an ancestor lets another account replace a
            // child between validation and open.  SYSTEM/Administrators are
            // intentionally not treated as broad principals here.
            let ace_sid = (&ace.SidStart as *const u32).cast::<std::ffi::c_void>() as PSID;
            if broad_principal(ace_sid)
                && ace.Mask & (FILE_ADD_FILE | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER)
                    != 0
            {
                bail!("secure ancestor grants broad write access");
            }
        }
    }
    Ok(())
}

fn broad_principal(sid: PSID) -> bool {
    // Everyone (S-1-1-0), Authenticated Users (S-1-5-11), and Users
    // (S-1-5-32-545).  These fixed binary SIDs avoid account-name lookups.
    const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const AUTHENTICATED_USERS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
    const USERS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
    unsafe {
        EqualSid(sid, EVERYONE.as_ptr() as PSID) != 0
            || EqualSid(sid, AUTHENTICATED_USERS.as_ptr() as PSID) != 0
            || EqualSid(sid, USERS.as_ptr() as PSID) != 0
    }
}

fn validate_acl_handle(file: &File, private: bool) -> anyhow::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    check_bool(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
        "GetFileInformationByHandle",
    )?;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        bail!("secure object is a directory or reparse point");
    }
    if info.nNumberOfLinks != 1 {
        bail!("secure file must have exactly one hard link");
    }
    let mut owner: PSID = null_mut();
    let mut group: PSID = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut sacl: *mut ACL = null_mut();
    let mut descriptor: *mut std::ffi::c_void = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut acl,
            &mut sacl,
            &mut descriptor,
        )
    };
    check_code(code, "GetSecurityInfo")?;
    let result = validate_descriptor(descriptor, true, private);
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(descriptor as HLOCAL);
    }
    result
}

fn validate_acl_handle_as_directory(file: &File, private: bool) -> anyhow::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    check_bool(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) },
        "GetFileInformationByHandle(directory)",
    )?;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        bail!("secure object is not a directory");
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("secure directory is a reparse point");
    }
    let mut owner: PSID = null_mut();
    let mut group: PSID = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut sacl: *mut ACL = null_mut();
    let mut descriptor: *mut std::ffi::c_void = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut acl,
            &mut sacl,
            &mut descriptor,
        )
    };
    check_code(code, "GetSecurityInfo(directory)")?;
    let result = validate_descriptor(descriptor, private, private);
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(descriptor as HLOCAL);
    }
    result
}

fn open_handle(
    path: &Path,
    desired: u32,
    disposition: FILE_CREATION_DISPOSITION,
) -> anyhow::Result<File> {
    open_handle_with_mode(path, desired, disposition, None)
}

fn open_handle_with_mode(
    path: &Path,
    desired: u32,
    disposition: FILE_CREATION_DISPOSITION,
    mode: Option<u32>,
) -> anyhow::Result<File> {
    let name = wide(path)?;
    let flags: FILE_FLAGS_AND_ATTRIBUTES =
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH;
    let open = |attributes: *mut SECURITY_ATTRIBUTES, _acl: *mut ACL| {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                desired,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                attributes.cast_const(),
                disposition,
                flags,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(win_error("CreateFileW"))
        } else {
            Ok(handle)
        }
    };
    let handle = match mode {
        Some(mode) => with_security_attributes(mode, false, open)?,
        None => open(null_mut(), null_mut())?,
    };
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    if let Some(mode) = mode {
        // Some Windows filesystem providers ignore the protected-control bit
        // from SECURITY_ATTRIBUTES while creating a file.  Reapply the exact
        // DACL on the still-empty handle before any caller can write bytes.
        set_acl(file.as_raw_handle(), mode)?;
    }
    Ok(file)
}

fn open_directory_handle(path: &Path, desired: u32) -> anyhow::Result<File> {
    let name = wide(path)?;
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(win_error("CreateFileW(directory)"));
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

pub fn open_secure_regular_file(path: &Path, _label: &str, private: bool) -> anyhow::Result<File> {
    let file = open_handle(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
            | windows_sys::Win32::Storage::FileSystem::READ_CONTROL,
        OPEN_EXISTING,
    )?;
    validate_acl_handle(&file, private)?;
    Ok(file)
}

pub fn validate_directory_path_acl(path: &Path, _label: &str, private: bool) -> anyhow::Result<()> {
    let file = open_directory_handle(path, windows_sys::Win32::Storage::FileSystem::READ_CONTROL)?;
    validate_acl_handle_as_directory(&file, private)?;
    drop(file);
    Ok(())
}

pub fn create_private_directory(path: &Path) -> io::Result<()> {
    let name =
        wide(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let result = with_security_attributes(0o700, true, |attributes, _acl| {
        let ok = unsafe { CreateDirectoryW(name.as_ptr(), attributes) };
        if ok != 0 {
            Ok(())
        } else {
            let code = unsafe { GetLastError() } as i32;
            Err(anyhow::Error::new(io::Error::from_raw_os_error(code)))
        }
    });
    result.map_err(|error| {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            io::Error::new(io_error.kind(), io_error.to_string())
        } else {
            io::Error::other(error.to_string())
        }
    })?;
    // Keep the create-time descriptor as the first-line protection and then
    // verify/reapply it through the opened directory handle.  This also covers
    // providers that drop the protected-control bit while materializing a new
    // directory from SECURITY_ATTRIBUTES.
    let file = open_directory_handle(
        path,
        windows_sys::Win32::Storage::FileSystem::READ_CONTROL
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    set_acl(file.as_raw_handle(), 0o700).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

/// Create each missing directory with the same protected owner/SYSTEM/
/// Administrators DACL used by private objects.  Path checks and creation are
/// performed one component at a time so a newly created intermediate never
/// exists with the ambient inherited ACL before it is usable by callers.
pub fn ensure_directory_chain(path: &Path) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    || !metadata.is_dir()
                {
                    bail!(
                        "directory path contains an unsafe component: {}",
                        current.display()
                    );
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.clone());
                let Some(parent) = current.parent() else {
                    bail!("directory path has no existing anchor: {}", path.display());
                };
                current = parent.to_path_buf();
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect directory {}", current.display()));
            }
        }
    }
    super::validate_directory_chain(&current)?;
    for directory in missing.into_iter().rev() {
        match create_private_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", directory.display()));
            }
        }
        let metadata = fs::symlink_metadata(&directory).with_context(|| {
            format!(
                "failed to inspect created directory {}",
                directory.display()
            )
        })?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            || !metadata.is_dir()
        {
            bail!(
                "created path component is not a regular directory: {}",
                directory.display()
            );
        }
    }
    super::validate_directory_chain(path)
}

pub fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    let file = if fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false) {
        open_directory_handle(
            path,
            windows_sys::Win32::Storage::FileSystem::READ_CONTROL
                | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
        )?
    } else {
        open_handle(
            path,
            windows_sys::Win32::Storage::FileSystem::READ_CONTROL
                | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
            OPEN_EXISTING,
        )?
    };
    set_file_mode(&file, mode)
}

pub fn set_file_mode(file: &File, mode: u32) -> anyhow::Result<()> {
    set_acl(file.as_raw_handle(), mode)
}

fn stage_path(target: &Path) -> anyhow::Result<std::path::PathBuf> {
    let name = target
        .file_name()
        .context("atomic target has no filename")?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{name}.nazoauth-{}.tmp", uuid::Uuid::now_v7())))
}

fn rename_replace(file: &File, parent: &File, target: &Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    // Keep the destination directory handle open without FILE_SHARE_DELETE so
    // a concurrent rename/remove of that directory cannot redirect the
    // absolute destination while the commit is in flight.  Win32 rejects a
    // non-null RootDirectory for some local filesystem providers, therefore
    // use the normalized absolute destination name here while retaining the
    // handle fence for the directory entry.
    let _parent_fence = parent.as_raw_handle();
    let target_name = target.as_os_str().to_string_lossy();
    let normalized_name = target_name.strip_prefix(r"\\?\").unwrap_or(&target_name);
    // The ordinary Win32 spelling is preferred because some local providers
    // reject the verbatim prefix in FILE_RENAME_INFO.  A long path must retain
    // that prefix, however, or the provider reports ERROR_FILENAME_EXCED_RANGE.
    let names = if normalized_name == target_name {
        vec![target_name.as_ref()]
    } else {
        vec![normalized_name, target_name.as_ref()]
    };
    for (attempt, name_text) in names.into_iter().enumerate() {
        let name: Vec<u16> = std::ffi::OsStr::new(name_text).encode_wide().collect();
        if name.len() > (u32::MAX as usize / 2) {
            bail!("atomic target path is too long");
        }
        let filename_offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let bytes_len = filename_offset + (name.len() + 1) * size_of::<u16>();
        let mut bytes = vec![0u8; bytes_len];
        let info = bytes.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len());
            (*info).Anonymous = FILE_RENAME_INFO_0 {
                ReplaceIfExists: true,
            };
            (*info).RootDirectory = null_mut();
            (*info).FileNameLength = (name.len() * 2) as u32;
            ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        }
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                bytes.len() as u32,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if attempt + 1 < 2
            && code == windows_sys::Win32::Foundation::ERROR_FILENAME_EXCED_RANGE
        {
            continue;
        }
        return Err(anyhow::anyhow!(
            "SetFileInformationByHandle(FileRenameInfo): {} (Win32 error {code})",
            io::Error::from_raw_os_error(code as i32)
        ));
    }
    bail!("SetFileInformationByHandle(FileRenameInfo) exhausted path forms")
}

fn commit_staged(
    staged: File,
    stage: &Path,
    parent: &File,
    target: &Path,
    mode: u32,
) -> anyhow::Result<()> {
    staged
        .sync_all()
        .with_context(|| format!("failed to persist staged {}", target.display()))?;
    rename_replace(&staged, parent, target)?;
    // A few Windows providers reconstruct the destination security
    // descriptor during an absolute same-directory rename.  Re-apply the
    // already validated ACL through the still-open object handle before
    // releasing it, so the committed file retains the protected DACL.
    set_acl(staged.as_raw_handle(), mode)?;
    drop(staged);
    let _ = fs::remove_file(stage);
    Ok(())
}

fn staging_mode(mode: u32) -> u32 {
    // A staged object must be writable by its owner until its bytes are
    // durable.  The requested mode is applied again after activation, so a
    // read-only final object (0400/0440) is still exposed with the exact
    // caller contract without ever creating an ambiently-accessible file.
    mode | 0o600
}

pub fn atomic_write(target: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let parent = target.parent().context("atomic target has no parent")?;
    super::ensure_directory_chain(parent)?;
    let parent_handle =
        open_directory_handle(parent, FILE_ADD_FILE | FILE_DELETE_CHILD | READ_CONTROL)?;
    validate_acl_handle_as_directory(&parent_handle, false)?;
    if let Ok(meta) = fs::symlink_metadata(target)
        && (meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0 || !meta.is_file())
    {
        bail!("atomic target is not a regular file: {}", target.display());
    }
    let stage = stage_path(target)?;
    let mut staged = open_handle_with_mode(
        &stage,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
        CREATE_NEW,
        Some(staging_mode(mode)),
    )?;
    staged
        .write_all(bytes)
        .with_context(|| format!("failed to write staged {}", target.display()))?;
    commit_staged(staged, &stage, &parent_handle, target, mode).inspect_err(|_e| {
        let _ = fs::remove_file(&stage);
    })
}

pub fn copy_atomic_from_file(source: &mut File, target: &Path, mode: u32) -> anyhow::Result<()> {
    source
        .seek(SeekFrom::Start(0))
        .context("failed to rewind validated source")?;
    let parent = target.parent().context("atomic target has no parent")?;
    super::ensure_directory_chain(parent)?;
    if let Ok(meta) = fs::symlink_metadata(target)
        && (meta.file_type().is_symlink()
            || meta.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            || !meta.is_file())
    {
        bail!("atomic target is not a regular file: {}", target.display());
    }
    let parent_handle =
        open_directory_handle(parent, FILE_ADD_FILE | FILE_DELETE_CHILD | READ_CONTROL)?;
    validate_acl_handle_as_directory(&parent_handle, false)?;
    let stage = stage_path(target)?;
    let mut staged = open_handle_with_mode(
        &stage,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
        CREATE_NEW,
        Some(staging_mode(mode)),
    )?;
    std::io::copy(source, &mut staged)
        .with_context(|| format!("failed to copy staged {}", target.display()))?;
    commit_staged(staged, &stage, &parent_handle, target, mode).inspect_err(|_e| {
        let _ = fs::remove_file(&stage);
    })
}

pub fn open_lock_file(path: &Path, label: &str) -> anyhow::Result<File> {
    match open_handle_with_mode(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
        CREATE_NEW,
        Some(0o600),
    ) {
        Ok(file) => {
            validate_acl_handle(&file, true)?;
            Ok(file)
        }
        Err(error)
            if error.to_string().contains("Win32 error 80")
                || error.to_string().contains("Win32 error 183") =>
        {
            open_secure_regular_file(path, label, true)
        }
        Err(error) => Err(error),
    }
}

pub fn open_append_file(path: &Path, label: &str) -> anyhow::Result<File> {
    let file = open_handle_with_mode(
        path,
        windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
            | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC,
        OPEN_ALWAYS,
        Some(0o600),
    )?;
    validate_acl_handle(&file, true)
        .with_context(|| format!("failed to validate {label} append file"))?;
    let mut file = file;
    file.seek(SeekFrom::End(0))?;
    Ok(file)
}
