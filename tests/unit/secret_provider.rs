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
fn external_dependency_binding_canonicalizes_ports_and_rejects_alias_bypasses() {
    let binding = bind_external_dependency_credentials(
        "postgresql://runtime:runtime-secret@db.example/oauth?sslmode=require",
        "postgresql://migrator:migration-secret@db.example:5432/oauth",
        "postgres://backup:backup-secret@DB.EXAMPLE/oauth?sslmode=require",
        "rediss://runtime:runtime-secret@cache.example/0",
        "rediss://backup:backup-secret@CACHE.EXAMPLE:6379/0",
    )
    .unwrap();
    assert_eq!(binding.database_endpoint_sha256.len(), 64);
    assert_eq!(binding.valkey_endpoint_sha256.len(), 64);
    let downgraded_tls = bind_external_dependency_credentials(
        "postgresql://runtime:runtime-secret@db.example/oauth",
        "postgresql://migrator:migration-secret@db.example:5432/oauth",
        "postgres://backup:backup-secret@DB.EXAMPLE/oauth",
        "rediss://runtime:runtime-secret@cache.example/0",
        "rediss://backup:backup-secret@CACHE.EXAMPLE:6379/0",
    )
    .unwrap();
    assert_eq!(
        binding.valkey_endpoint_sha256,
        downgraded_tls.valkey_endpoint_sha256
    );
    assert_ne!(
        binding.database_endpoint_sha256,
        downgraded_tls.database_endpoint_sha256
    );
    assert_ne!(
        binding.database_runtime_endpoint_sha256,
        downgraded_tls.database_runtime_endpoint_sha256
    );
    assert_eq!(
        binding.migration_database_endpoint_sha256,
        downgraded_tls.migration_database_endpoint_sha256
    );
    let migration_downgrade = bind_external_dependency_credentials(
        "postgresql://runtime:runtime-secret@db.example/oauth?sslmode=require",
        "postgresql://migrator:migration-secret@db.example/oauth?sslmode=disable",
        "postgresql://backup:backup-secret@db.example/oauth?sslmode=require",
        "rediss://runtime:runtime-secret@cache.example/0",
        "rediss://backup:backup-secret@cache.example/0",
    )
    .unwrap();
    assert_eq!(
        binding.database_runtime_endpoint_sha256,
        migration_downgrade.database_runtime_endpoint_sha256
    );
    assert_ne!(
        binding.migration_database_endpoint_sha256,
        migration_downgrade.migration_database_endpoint_sha256
    );
    let runtime_downgrade = bind_external_dependency_credentials(
        "postgresql://runtime:runtime-secret@db.example/oauth?sslmode=disable",
        "postgresql://migrator:migration-secret@db.example/oauth",
        "postgresql://backup:backup-secret@db.example/oauth?sslmode=require",
        "rediss://runtime:runtime-secret@cache.example/0",
        "rediss://backup:backup-secret@cache.example/0",
    )
    .unwrap();
    assert_ne!(
        binding.database_runtime_endpoint_sha256,
        runtime_downgrade.database_runtime_endpoint_sha256
    );

    for input in [
        (
            "postgresql://runtime:runtime-secret@db.example/oauth",
            "postgresql://run%74ime:migration-secret@db.example/oauth",
            "postgresql://backup:backup-secret@db.example/oauth",
            "rediss://runtime:runtime-secret@cache.example/0",
            "rediss://backup:backup-secret@cache.example/0",
        ),
        (
            "postgresql://runtime:runtime-secret@db.example/oauth?application_name=nazoauth",
            "postgresql://migrator:migration-secret@db.example/oauth",
            "postgresql://backup:backup-secret@db.example/oauth",
            "rediss://runtime:runtime-secret@cache.example/0",
            "rediss://backup:backup-secret@cache.example/0",
        ),
        (
            "postgresql://runtime:runtime-secret@db.example/oauth",
            "postgresql://migrator:migration-secret@db.example/oauth",
            "postgresql://backup:backup-secret@db.example/oauth?sslmode=require&sslmode=require",
            "rediss://runtime:runtime-secret@cache.example/0",
            "rediss://backup:backup-secret@cache.example/0",
        ),
        (
            "postgresql://runtime:runtime-secret@db.example/oauth",
            "postgresql://migrator:migration-secret@other.example/oauth",
            "postgresql://backup:backup-secret@db.example/oauth",
            "rediss://runtime:runtime-secret@cache.example/0",
            "rediss://backup:backup-secret@cache.example/0",
        ),
        (
            "postgresql://runtime:runtime-secret@db.example/oauth",
            "postgresql://migrator:migration-secret@db.example/oauth",
            "postgresql://backup:backup-secret@db.example/oauth",
            "rediss://runtime:runtime-secret@cache.example/0",
            "redis://backup:backup-secret@cache.example/0",
        ),
    ] {
        assert!(
            bind_external_dependency_credentials(input.0, input.1, input.2, input.3, input.4)
                .is_err()
        );
    }
}

#[test]
fn dependency_url_parser_is_strict_about_percent_encoding_and_hosts() {
    let ipv6 = parse_dependency_url(
        "postgresql://runtime:secret@[2001:0DB8:0:0:0:0:0:1]/oauth?sslmode=require",
        "PostgreSQL runtime",
    )
    .unwrap();
    assert_eq!(ipv6.host, "2001:db8::1");
    let dns = parse_dependency_url(
        "postgresql://runtime:secret@DB.EXAMPLE/oauth",
        "PostgreSQL runtime",
    )
    .unwrap();
    assert_eq!(dns.host, "db.example");
    for input in [
        "postgresql://runtime:bad%@db.example/oauth",
        "postgresql://runtime:bad%0@db.example/oauth",
        "postgresql://runtime:bad%GG@db.example/oauth",
        "postgresql://runtime:secret@[not-ip]/oauth",
        "postgresql://runtime:secret@db\\example/oauth",
        "postgresql://runtime:secret@-db.example/oauth",
    ] {
        assert!(parse_dependency_url(input, "PostgreSQL runtime").is_err());
    }
}

#[test]
fn providers_pass_bare_canonical_ipv6_hosts_to_postgres_and_valkey() {
    let work = PrivateTempDir::new("nazoauth-provider-ipv6-host").unwrap();
    let postgres = work.path().join("postgres");
    fs::write(
        &postgres,
        "postgresql://alice:secret@[2001:0DB8:0:0:0:0:0:1]/oauth?sslmode=require",
    )
    .unwrap();
    crate::filesystem::set_mode(&postgres, 0o600).unwrap();
    let provider = PostgresProvider::from_url_file(&postgres).unwrap();
    assert!(
        fs::read_to_string(provider.service_file())
            .unwrap()
            .contains("host=2001:db8::1\n")
    );

    let valkey = work.path().join("valkey");
    fs::write(&valkey, "rediss://backup:secret@[2001:0DB8:0:0:0:0:0:1]/0").unwrap();
    crate::filesystem::set_mode(&valkey, 0o600).unwrap();
    let provider = ValkeyProvider::from_url_file(&valkey).unwrap();
    assert_eq!(provider.host, "2001:db8::1");
    assert!(provider.tls);
}

#[test]
fn backup_binding_reads_only_the_two_dedicated_credentials() {
    let work = PrivateTempDir::new("nazoauth-backup-credential-binding").unwrap();
    let database_backup = work.path().join("database-backup-url");
    let valkey_backup = work.path().join("valkey-backup-url");
    fs::write(
        &database_backup,
        "postgresql://backup:backup-secret@db.example/oauth?sslmode=require",
    )
    .unwrap();
    fs::write(
        &valkey_backup,
        "rediss://backup:backup-secret@cache.example/0",
    )
    .unwrap();
    crate::filesystem::set_mode(&database_backup, 0o600).unwrap();
    crate::filesystem::set_mode(&valkey_backup, 0o600).unwrap();

    let providers = read_external_backup_providers(&database_backup, &valkey_backup).unwrap();
    assert_eq!(providers.binding.database_endpoint_sha256.len(), 64);
    assert_eq!(providers.binding.valkey_endpoint_sha256.len(), 64);
}

#[test]
fn backup_providers_consume_the_single_verified_read_after_source_replacement() {
    let work = PrivateTempDir::new("nazoauth-backup-provider-single-read").unwrap();
    let database_backup = work.path().join("database-backup-url");
    let valkey_backup = work.path().join("valkey-backup-url");
    fs::write(
        &database_backup,
        "postgresql://backup:backup-secret@db.example/oauth?sslmode=require",
    )
    .unwrap();
    fs::write(
        &valkey_backup,
        "rediss://backup:backup-secret@cache.example/0",
    )
    .unwrap();
    crate::filesystem::set_mode(&database_backup, 0o600).unwrap();
    crate::filesystem::set_mode(&valkey_backup, 0o600).unwrap();

    let providers = read_external_backup_providers(&database_backup, &valkey_backup).unwrap();
    fs::write(
        &database_backup,
        "postgresql://backup:changed@other.example/oauth",
    )
    .unwrap();
    fs::write(&valkey_backup, "redis://backup:changed@other.example/0").unwrap();
    crate::filesystem::set_mode(&database_backup, 0o600).unwrap();
    crate::filesystem::set_mode(&valkey_backup, 0o600).unwrap();

    assert_eq!(providers.binding.database_endpoint_sha256.len(), 64);
    assert!(
        fs::read_to_string(providers.postgres.service_file())
            .unwrap()
            .contains("host=db.example")
    );
    assert_eq!(providers.valkey.host, "cache.example");
    assert!(providers.valkey.tls);
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
