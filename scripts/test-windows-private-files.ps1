[CmdletBinding()]
param(
    [switch] $KeepAccounts,
    # Use a machine-wide installation: a caller's private runtime is not
    # necessarily executable by either disposable account.
    [string] $PowerShellPath = (Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe')
)

$ErrorActionPreference = 'Stop'
if (-not [OperatingSystem]::IsWindows() -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw 'This integration check requires PowerShell 7 on Windows.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run in elevated PowerShell 7 to create two disposable ordinary accounts.'
}
if (-not (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
    throw 'The Microsoft.PowerShell.LocalAccounts module is required.'
}

# Build once as the invoking account; neither ordinary account needs Cargo.
$workspace = Split-Path -Parent $PSScriptRoot
$pwsh = (Get-Item -LiteralPath $PowerShellPath -ErrorAction Stop).FullName
Push-Location $workspace
try {
    $buildOutput = & cargo test -p nazoauthctl-runtime --test windows_private_files `
        --locked --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw "Rust fixture build failed: $LASTEXITCODE" }
    $executables = @($buildOutput | ForEach-Object {
        $message = $_ | ConvertFrom-Json
        if ($message.reason -eq 'compiler-artifact' -and
            $message.target.name -eq 'windows_private_files' -and $message.executable) {
            $message.executable
        }
    })
    if ($executables.Count -ne 1) { throw 'Expected exactly one Windows fixture executable.' }
}
finally { Pop-Location }

$tag = [Guid]::NewGuid().ToString('N')
$accountTag = $tag.Substring(0, 12)
$ownerName = "NazoA_$accountTag"
$otherName = "NazoB_$accountTag"
$ownerPassword = ConvertTo-SecureString "N!$tag-owner-7x" -AsPlainText -Force
$otherPassword = ConvertTo-SecureString "N!$tag-other-7x" -AsPlainText -Force
$testRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "nazoauthctl-test-$tag"
$createdAccounts = @()

function Set-TestDirectoryAcl {
    param([string] $Path, [Security.Principal.SecurityIdentifier] $WriterSid,
        [Security.Principal.SecurityIdentifier[]] $ReaderSids = @())
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @($identity.User,
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', $inherit, 'None', 'Allow'))
    }
    if ($WriterSid) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $WriterSid, 'FullControl', $inherit, 'None', 'Allow'))
    }
    foreach ($sid in $ReaderSids) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'ReadAndExecute', $inherit, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-AsUser {
    param([string] $User, [securestring] $Password, [string] $Command, [string] $Label)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $process = Start-Process -FilePath $pwsh -Credential ([PSCredential]::new(".\$User", $Password)) `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
        -WorkingDirectory $testRoot -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $testRoot "$Label.stdout") `
        -RedirectStandardError (Join-Path $testRoot "$Label.stderr")
    if ($process.ExitCode -ne 0) {
        $detail = Get-Content -LiteralPath (Join-Path $testRoot "$Label.stderr") -Raw
        throw "$Label failed with exit code $($process.ExitCode): $detail"
    }
}

try {
    $owner = New-LocalUser -Name $ownerName -Password $ownerPassword -AccountNeverExpires `
        -PasswordNeverExpires -UserMayNotChangePassword -Description 'NazoAuthCtl disposable filesystem owner'
    $createdAccounts += $ownerName
    $other = New-LocalUser -Name $otherName -Password $otherPassword -AccountNeverExpires `
        -PasswordNeverExpires -UserMayNotChangePassword -Description 'NazoAuthCtl disposable filesystem peer'
    $createdAccounts += $otherName
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users -Member $ownerName, $otherName

    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Set-TestDirectoryAcl -Path $testRoot -ReaderSids @($owner.SID, $other.SID)
    $ownerDirectory = Join-Path $testRoot 'owner'
    New-Item -ItemType Directory -Path $ownerDirectory | Out-Null
    Set-TestDirectoryAcl -Path $ownerDirectory -WriterSid $owner.SID
    $fixture = Join-Path $ownerDirectory 'secret'
    $executable = Join-Path $testRoot 'windows_private_files.exe'
    Copy-Item -LiteralPath $executables[0] -Destination $executable
    # Put the readable control behind the same non-listable parent so the
    # peer proves it can traverse that parent, not merely launch PowerShell.
    $control = Join-Path $ownerDirectory 'readable-control'
    Set-Content -LiteralPath $control -Value 'readable-control' -NoNewline
    $controlAcl = [Security.AccessControl.FileSecurity]::new()
    $controlAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.User, $owner.SID, $other.SID)) {
        $controlAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'Read', 'Allow'))
    }
    Set-Acl -LiteralPath $control -AclObject $controlAcl

    # Encoded commands preserve paths with spaces; credentials are not embedded.
    $quotedFixture = $fixture.Replace("'", "''")
    $quotedExecutable = $executable.Replace("'", "''")
    $quotedControl = $control.Replace("'", "''")
    $quotedOwnerDirectory = $ownerDirectory.Replace("'", "''")
    $ordinaryAccountCheck = @'
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 is required.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The fixture must run as an ordinary account.'
}
'@
    $createCommand = $ordinaryAccountCheck + @"

`$env:NAZO_WINDOWS_PRIVATE_FILES_FIXTURE = '$quotedFixture'
`$env:TEMP = '$quotedOwnerDirectory'
`$env:TMP = '$quotedOwnerDirectory'
& '$quotedExecutable' --exact windows_private_file_is_protected_before_first_write --nocapture
exit `$LASTEXITCODE
"@
    Invoke-AsUser -User $ownerName -Password $ownerPassword -Command $createCommand -Label 'owner-create'
    $probeCommand = $ordinaryAccountCheck + @"

if ([IO.File]::ReadAllText('$quotedControl') -ne 'readable-control') {
    throw 'Readable control failed; this is not evidence of secret-file isolation.'
}
foreach (`$mode in @('0400', '0440', '0444', '0600')) {
    `$target = '$quotedFixture' + '.' + `$mode
    try {
        [IO.File]::ReadAllBytes(`$target) | Out-Null
        throw "Foreign read unexpectedly succeeded: `$mode"
    }
    catch [UnauthorizedAccessException] { }
    try {
        [IO.File]::WriteAllText(`$target, 'foreign-write')
        throw "Foreign write unexpectedly succeeded: `$mode"
    }
    catch [UnauthorizedAccessException] { }
}
"@
    Invoke-AsUser -User $otherName -Password $otherPassword -Command $probeCommand -Label 'peer-probe'
    $verifyCommand = $ordinaryAccountCheck + @"

foreach (`$mode in @('0400', '0440', '0444', '0600')) {
    if ([IO.File]::ReadAllText('$quotedFixture' + '.' + `$mode) -ne 'cross-account-fixture') {
        throw "Owner could not read the intact fixture: `$mode"
    }
}
"@
    Invoke-AsUser -User $ownerName -Password $ownerPassword -Command $verifyCommand -Label 'owner-verify'
    Write-Host 'Windows private-file two-ordinary-account check passed (0400, 0440, 0444, 0600).'
}
finally {
    try {
        # Resolve and check the explicit disposable root before recursive cleanup.
        if (Test-Path -LiteralPath $testRoot) {
            $resolvedRoot = (Resolve-Path -LiteralPath $testRoot).Path
            if ($resolvedRoot -ne [IO.Path]::GetFullPath($testRoot) -or
                (Split-Path -Leaf $resolvedRoot) -ne "nazoauthctl-test-$tag") {
                throw 'Refusing cleanup of an unexpected test directory.'
            }
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
    finally {
        if (-not $KeepAccounts) {
            foreach ($account in $createdAccounts) { Remove-LocalUser -Name $account }
        }
    }
}
