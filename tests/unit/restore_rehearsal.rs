use super::*;
use crate::target::{
    DEFAULT_INSTANCE_IDENTITY_DIRECTORY, INSTANCE_DEPLOYMENT_STATEMENT_FILE,
    INSTANCE_IDENTITY_PUBLIC_FILE,
};
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};

fn write(path: &Path, bytes: impl AsRef<[u8]>) -> anyhow::Result<()> {
    crate::filesystem::atomic_write(path, bytes.as_ref(), 0o600)
}

#[test]
fn interrupted_rehearsal_reuses_its_snapshot_and_isolated_resources() -> anyhow::Result<()> {
    const TEST: &str = "target::backup_exec::restore_rehearsal_tests::interrupted_rehearsal_reuses_its_snapshot_and_isolated_resources";
    if let Some(root) = std::env::var_os("REHEARSAL_TEST_ROOT") {
        let root = PathBuf::from(root);
        let state: DeploymentState = serde_json::from_slice(&fs::read(root.join("state.json"))?)?;
        let operation = fs::read_to_string(root.join("operation"))?;
        let result = restore_test(&root.join("scope"), &state, &operation);
        assert!(
            std::env::var("REHEARSAL_TEST_PHASE")? == "resume",
            "first process must be killed at migration"
        );
        let error = result.unwrap_err();
        assert!(
            error.detail.contains("failed") || error.detail.contains("status"),
            "{error:?}"
        );
        return Ok(());
    }
    let temp = crate::filesystem::PrivateTempDir::new("restore-rehearsal-process")?;
    let root = temp.path();
    let mut state: DeploymentState =
        serde_json::from_slice(include_bytes!("../fixtures/persistence/v0.2.28/state.json"))?;
    state.runtime.kind = RuntimeBackendKind::Docker;
    let operation = Uuid::now_v7();
    let database = format!("nazo_restore_{}", operation.simple());
    write(&root.join("state.json"), serde_json::to_vec(&state)?)?;
    write(&root.join("operation"), operation.to_string())?;
    let source = root.join("source");
    let data = source.join("data");
    let secrets = source.join("secrets");
    let identity = data.join(DEFAULT_INSTANCE_IDENTITY_DIRECTORY);
    let key = nazo_crypto::ed25519::SigningKey::from_bytes(&[31; 32]);
    let key_id = nazo_operator_protocol::instance_key_id(&key.verifying_key());
    let statement = nazo_operator_protocol::DeploymentStatement {
        schema: nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA,
        product: nazo_operator_protocol::CONTROL_DISCOVERY_PRODUCT.into(),
        deployment_id: state.deployment_id.clone(),
        runtime_instance_id: "runtime-fixture".into(),
        issuer: state.issuer.clone(),
        release: "1.0.0".into(),
        control_protocol_versions: vec![nazo_operator_protocol::CONTROL_DISCOVERY_SCHEMA],
        operator_protocol_versions: vec![nazo_operator_protocol::PROTOCOL_VERSION],
        instance_key_id: key_id.clone(),
        issued_at: 1,
    };
    write(
        &identity.join(INSTANCE_IDENTITY_PUBLIC_FILE),
        nazo_operator_protocol::encode_instance_public_key(&key.verifying_key()),
    )?;
    write(
        &identity.join(INSTANCE_DEPLOYMENT_STATEMENT_FILE),
        nazo_operator_protocol::sign_deployment_statement(&statement, &key_id, &key)?,
    )?;
    for name in crate::target::install_exec::SECRET_PURPOSES {
        write(&secrets.join(name), name)?;
    }
    write(
        &secrets.join(SIGNING_KEY_ENCRYPTION_KEY_SECRET),
        URL_SAFE_NO_PAD.encode([8u8; 32]),
    )?;
    for name in ["database-lifecycle-url", "database-runtime-url"] {
        write(
            &secrets.join(name),
            "postgres://fixture:password@127.0.0.1/source",
        )?;
    }
    write(
        &secrets.join("valkey-url"),
        "redis://default:p%40ss%3A%2F%25%3F%2B@127.0.0.1:6379/0",
    )?;
    let config = source.join("config.yaml");
    let config_text = "DATABASE_URL: postgres://fixture:password@127.0.0.1/source\nVALKEY_STATE_EPOCH: original\nSIGNING_KEY_ENCRYPTION_KEY_FILE: /run/secrets/signing-key-encryption-key\nSIGNING_KEY_ENCRYPTION_KEY_ID: fixture\n";
    write(&config, config_text)?;
    let snapshot_id = Uuid::now_v7();
    let scope = root.join("scope");
    let snapshot = scope.join("backup/snapshots").join(snapshot_id.to_string());
    crate::filesystem::ensure_private_directory(&snapshot, "fixture snapshot")?;
    let archive_files = create_deployment_archive(
        &snapshot.join("deployment.tar"),
        &data,
        &secrets,
        &config,
        snapshot_id.to_string().as_bytes(),
    )?;
    write(&snapshot.join("postgresql.dump"), b"fixture dump")?;
    let mut manifest = SnapshotManifest {
        schema: backup::BACKUP_MANIFEST_SCHEMA,
        rollback_policy: None,
        deployment_id: state.deployment_id.clone(),
        snapshot_id: snapshot_id.to_string(),
        created_at: Utc::now(),
        runtime_artifact: ArtifactReference::Oci {
            image_reference: "example/fixture".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
        },
        release: state.current_release.clone().unwrap(),
        config_schema: state.config.schema.clone(),
        files: ["postgresql.dump", "deployment.tar"]
            .into_iter()
            .map(|name| snapshot_file(&snapshot.join(name), &snapshot))
            .collect::<anyhow::Result<_>>()?,
        archive_files,
        database_sentinel_sha256: backup::hex_digest(b"fixture-fact"),
        mfa_key_sha256: backup::hex_digest(b"mfa-totp-key"),
        runtime_instance_key_id: key_id,
        oidc_signing_key_ids: vec!["signing-key".into()],
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    backup::write_manifest(&scope, &manifest)?;
    // Exercise the real orchestration and OS process-loss boundary. Commands
    // emulate the external services so this test cannot touch a deployment.
    let program = r#"#!/usr/bin/python3
import json, os, pathlib, signal, sys
r=pathlib.Path(os.environ['REHEARSAL_TEST_ROOT']); args=sys.argv[1:]; name=pathlib.Path(sys.argv[0]).name
with (r/'calls').open('a') as f: f.write(json.dumps([name]+args)+'\n')
if name=='createdb':
    p=r/('db-'+args[-1]); assert not p.exists(); p.write_text('created')
elif name=='dropdb': (r/('db-'+args[-1])).unlink(missing_ok=True)
elif name=='psql':
    sys.stdin.read(); print('fixture-fact')
elif name=='valkey-cli':
    assert os.environ['REDISCLI_AUTH']=='p@ss:/%?+'
elif name=='docker':
    if args[0]=='container':
        print('Error: No such container', file=sys.stderr); sys.exit(1)
    assert args[0]=='run' and args[-1]=='migrate', args
    (r/'migration-url').write_text(os.environ['DATABASE_URL'])
    if os.environ['REHEARSAL_TEST_PHASE']=='crash': os.kill(os.getppid(), signal.SIGKILL)
    sys.exit(13)
elif name!='pg_restore': raise AssertionError(name)
"#;
    for name in [
        "docker",
        "createdb",
        "dropdb",
        "pg_restore",
        "psql",
        "valkey-cli",
    ] {
        fs::write(root.join(name), program)?;
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700))?;
    }
    let run = |phase| -> anyhow::Result<std::process::Output> {
        Ok(std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", TEST, "--nocapture"])
            .env("NAZOAUTHCTL_TESTING", "1")
            .env("REHEARSAL_TEST_ROOT", root)
            .env("REHEARSAL_TEST_PHASE", phase)
            .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
            .output()?)
    };
    let killed = run("crash")?;
    ensure!(
        killed.status.signal() == Some(9),
        "child did not reach kill: {} {}",
        String::from_utf8_lossy(&killed.stdout),
        String::from_utf8_lossy(&killed.stderr)
    );
    assert!(root.join(format!("db-{database}")).exists());
    let work = scope
        .join("backup/restore-tests")
        .join(operation.to_string())
        .join("work");
    let restored: YamlValue = yaml_serde::from_str(&fs::read_to_string(work.join("config.yaml"))?)?;
    assert!(
        restored["DATABASE_URL"]
            .as_str()
            .unwrap()
            .ends_with(&database)
    );
    assert_eq!(
        restored["VALKEY_STATE_EPOCH"].as_str(),
        Some(operation.to_string().as_str())
    );
    assert!(fs::read_to_string(root.join("migration-url"))?.ends_with(&database));
    assert_eq!(fs::read_to_string(&config)?, config_text);
    // A new latest snapshot must not redirect the interrupted operation.
    let original_hash = manifest.manifest_sha256.clone();
    manifest.snapshot_id = Uuid::now_v7().to_string();
    manifest.manifest_sha256 = manifest.computed_sha256()?;
    backup::write_manifest(&scope, &manifest)?;
    let resumed = run("resume")?;
    ensure!(
        resumed.status.success(),
        "{} {}",
        String::from_utf8_lossy(&resumed.stdout),
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(!root.join(format!("db-{database}")).exists());
    assert!(backup::load_receipt(&scope)?.is_none());
    let pinned =
        backup::load_manifest_at(&work.parent().unwrap().join(IMMUTABLE_MANIFEST_FILE))?.unwrap();
    assert_eq!(pinned.manifest_sha256, original_hash);
    let calls: Vec<Vec<String>> = fs::read_to_string(root.join("calls"))?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let db_calls: Vec<_> = calls
        .iter()
        .filter(|args| matches!(args[0].as_str(), "createdb" | "dropdb"))
        .collect();
    assert_eq!(
        db_calls
            .iter()
            .map(|args| args[0].as_str())
            .collect::<Vec<_>>(),
        ["createdb", "dropdb", "createdb", "dropdb"]
    );
    assert!(db_calls.iter().all(|args| args.last() == Some(&database)));
    assert!(calls.iter().any(|args| args[0] == "docker"
        && args.get(1).is_some_and(|arg| arg == "container")
        && args.contains(&candidate_name(&state.deployment_id, operation))));
    Ok(())
}

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[test]
#[ignore = "requires isolated Valkey with password p@ss:/%?+ and NAZOAUTHCTL_TEST_VALKEY_URL"]
fn cleanup_with_encoded_password_removes_only_the_selected_epoch() -> anyhow::Result<()> {
    let root = crate::filesystem::PrivateTempDir::new("valkey-cleanup")?;
    let url = std::env::var("NAZOAUTHCTL_TEST_VALKEY_URL")?;
    let url_file = root.path().join("valkey-url");
    write(&url_file, &url)?;
    let mut connection = Url::parse(&url)?;
    connection.set_password(None).unwrap();
    connection.set_username("").unwrap();
    let epoch = Uuid::now_v7().to_string();
    let selected = format!("nazo:state:v1:fixture:{epoch}:one");
    let other = format!("nazo:state:v1:fixture:other:{epoch}");
    let call = |args: &[&str]| -> anyhow::Result<String> {
        let output = crate::process::Process::new("valkey-cli")
            .args([
                "--no-auth-warning",
                "--user",
                "default",
                "-u",
                connection.as_str(),
            ])
            .args(args)
            .env("REDISCLI_AUTH", "p@ss:/%?+")
            .output()?;
        ensure!(output.status.success(), "fixture Valkey command failed");
        Ok(String::from_utf8(output.stdout)?.trim().into())
    };
    assert_eq!(call(&["SET", &selected, "selected"])?, "OK");
    assert_eq!(call(&["SET", &other, "other"])?, "OK");
    cleanup_valkey_namespace(&url_file, "fixture", &epoch)?;
    assert_eq!(call(&["EXISTS", &selected])?, "0");
    assert_eq!(call(&["GET", &other])?, "other");
    call(&["DEL", &other])?;
    Ok(())
}
