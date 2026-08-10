use std::fs;

use super::*;

#[test]
fn providers_split_secrets_from_non_secret_connection_parameters() {
    let work = PrivateTempDir::new("nazoauth-provider-test").unwrap();
    let postgres = work.path().join("postgres");
    fs::write(
        &postgres,
        "postgresql://alice:p%40ss@db.example:5544/oauth?sslmode=require",
    )
    .unwrap();
    crate::filesystem::set_mode(&postgres, 0o600).unwrap();
    let provider = PostgresProvider::from_url_file(&postgres).unwrap();
    let service = fs::read_to_string(provider.service_file()).unwrap();
    let pass = fs::read_to_string(provider.password_file()).unwrap();
    assert!(!service.contains("p@ss"));
    assert!(service.contains("host=db.example\n"));
    assert!(service.contains("port=5544\n"));
    assert!(service.contains("dbname=oauth\n"));
    assert!(service.contains("user=alice\n"));
    assert!(service.contains("sslmode=require\n"));
    assert!(pass.ends_with(":p@ss\n"));

    let valkey = work.path().join("valkey");
    fs::write(&valkey, "rediss://default:s%3Aecret@cache.example:6380/2").unwrap();
    crate::filesystem::set_mode(&valkey, 0o600).unwrap();
    let provider = ValkeyProvider::from_url_file(&valkey).unwrap();
    assert_eq!(provider.host, "cache.example");
    assert_eq!(provider.password_stdin().as_slice(), b"s:ecret\n");
    assert!(provider.tls);
}

#[test]
fn postgres_provider_rejects_values_service_files_cannot_represent() {
    let work = PrivateTempDir::new("nazoauth-provider-invalid-service-test").unwrap();
    for (name, url) in [
        (
            "newline",
            "postgresql://alice:p%40ss@db.example/oauth?application_name=line%0Abreak",
        ),
        (
            "trailing-space",
            "postgresql://alice%20:p%40ss@db.example/oauth",
        ),
        (
            "nul",
            "postgresql://alice:p%40ss@db.example/oauth?application_name=a%00b",
        ),
    ] {
        let path = work.path().join(name);
        fs::write(&path, url).unwrap();
        crate::filesystem::set_mode(&path, 0o600).unwrap();
        let error = PostgresProvider::from_url_file(&path).err().unwrap();
        assert!(error.to_string().contains("cannot be represented safely"));
    }
}

#[test]
fn provider_rejects_encoded_newline_in_password_after_decoding() {
    let work = PrivateTempDir::new("nazoauth-provider-encoded-control-test").unwrap();
    let path = work.path().join("postgres");
    fs::write(&path, "postgresql://alice:p%0Ass@db.example/oauth").unwrap();
    crate::filesystem::set_mode(&path, 0o600).unwrap();
    let error = PostgresProvider::from_url_file(&path).err().unwrap();
    assert!(error.to_string().contains("cannot be represented safely"));
}

#[cfg(unix)]
#[test]
fn provider_rejects_symlink_and_group_writable_input() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauth-provider-secure-input-test").unwrap();
    let target = work.path().join("target");
    fs::write(&target, "rediss://default:secret@cache.example/1").unwrap();
    crate::filesystem::set_mode(&target, 0o600).unwrap();
    let link = work.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(ValkeyProvider::from_url_file(&link).is_err());

    crate::filesystem::set_mode(&target, 0o644).unwrap();
    assert!(ValkeyProvider::from_url_file(&target).is_err());

    crate::filesystem::set_mode(&target, 0o640).unwrap();
    assert!(ValkeyProvider::from_url_file(&target).is_ok());
}
