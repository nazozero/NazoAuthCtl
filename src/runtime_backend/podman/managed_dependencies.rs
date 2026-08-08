//! Podman-managed PostgreSQL and Valkey operations.

use std::{ffi::OsStr, thread, time::Duration};

use anyhow::{Context as _, bail};

use crate::process::Process;

use super::super::{
    ManagedDependencies, ManagedDependencyBackup, ManagedPostgresCommand, ManagedPostgresRestore,
    ManagedValkeyRestore, RuntimeDatabasePrivilegeProbe, container_shared,
};

pub(super) fn restore_postgres(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
) -> anyhow::Result<()> {
    container_shared::require_digest_pinned_image(&restore.image, "Podman")?;
    container_shared::assert_managed_labels(
        command,
        &["network", "inspect", restore.network.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        None,
        "network",
        &restore.identity.network_config_digest,
        "Podman",
    )?;
    container_shared::assert_managed_labels(
        command,
        &["inspect", restore.postgres_object.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "postgres",
        &restore.identity.postgres_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["inspect", restore.postgres_object.as_str()],
        &restore.postgres_image,
        "Podman",
    )?;
    Process::new(command)
        .args(["run", "--rm", "--network"])
        .arg(&restore.network)
        .args([
            "-e",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "-e",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "-v",
        ])
        .arg(format!(
            "{}:/backup:ro,Z",
            restore.backup_directory.display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            restore.service_file.display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            restore.password_file.display()
        ))
        .arg(&restore.image)
        .args([
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--dbname=service=nazoauth",
            "/backup/postgresql.dump",
        ])
        .run_quiet()
}

pub(super) fn restore_valkey(
    command: &OsStr,
    restore: &ManagedValkeyRestore,
) -> anyhow::Result<()> {
    container_shared::require_digest_pinned_image(&restore.image, "Podman")?;
    container_shared::assert_managed_labels(
        command,
        &["network", "inspect", restore.network.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        None,
        "network",
        &restore.identity.network_config_digest,
        "Podman",
    )?;
    container_shared::assert_managed_labels(
        command,
        &["inspect", restore.object_reference.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "valkey",
        &restore.identity.valkey_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["inspect", restore.object_reference.as_str()],
        &restore.image,
        "Podman",
    )?;
    container_shared::assert_managed_labels(
        command,
        &["volume", "inspect", restore.data_volume.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "valkey-volume",
        &restore.identity.valkey_volume_config_digest,
        "Podman",
    )?;
    Process::new(command)
        .args(["stop", restore.object_reference.as_str()])
        .run_quiet()?;
    let restored = Process::new(command)
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/data", restore.data_volume))
        .arg("-v")
        .arg(format!(
            "{}:/backup:ro,Z",
            restore.backup_directory.display()
        ))
        .arg(&restore.image)
        .args([
            "sh",
            "-eu",
            "-c",
            "test -s /backup/valkey-dump.rdb; rm -rf -- /data/appendonlydir; install -m 600 /backup/valkey-dump.rdb /data/dump.rdb",
        ])
        .run_quiet();
    let restarted = Process::new(command)
        .args(["start", restore.object_reference.as_str()])
        .run_quiet();
    restored?;
    restarted
}

pub(super) fn execute_postgres(
    command: &OsStr,
    operation: &ManagedPostgresCommand,
) -> anyhow::Result<()> {
    container_shared::assert_managed_labels(
        command,
        &["network", "inspect", operation.network.as_str()],
        &operation.identity.deployment_id,
        &operation.identity.control_authority,
        None,
        "network",
        &operation.identity.network_config_digest,
        "Podman",
    )?;
    container_shared::assert_managed_labels(
        command,
        &["inspect", operation.object_reference.as_str()],
        &operation.identity.deployment_id,
        &operation.identity.control_authority,
        Some(operation.identity.runtime_instance_id.as_str()),
        "postgres",
        &operation.identity.postgres_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["inspect", operation.object_reference.as_str()],
        &operation.image,
        "Podman",
    )?;
    Process::new(command)
        .args(["exec", "-i"])
        .arg(&operation.object_reference)
        .args(["psql", "--no-psqlrc", "--set", "ON_ERROR_STOP=1", "-U"])
        .arg(&operation.user)
        .arg("-d")
        .arg(&operation.database)
        .stdin_stdout(&operation.stdin)
        .map(|_| ())
}

pub(super) fn backup(command: &OsStr, backup: &ManagedDependencyBackup) -> anyhow::Result<()> {
    container_shared::require_digest_pinned_image(&backup.postgres_validation_image, "Podman")?;
    let identity = &backup.identity;
    container_shared::assert_managed_labels(
        command,
        &["network", "inspect", backup.network.as_str()],
        &identity.deployment_id,
        &identity.control_authority,
        None,
        "network",
        &identity.network_config_digest,
        "Podman",
    )?;
    for (object, role, digest, image) in [
        (
            backup.postgres_object.as_str(),
            "postgres",
            identity.postgres_config_digest.as_str(),
            backup.postgres_image.as_str(),
        ),
        (
            backup.valkey_object.as_str(),
            "valkey",
            identity.valkey_config_digest.as_str(),
            backup.valkey_image.as_str(),
        ),
    ] {
        container_shared::assert_managed_labels(
            command,
            &["inspect", object],
            &identity.deployment_id,
            &identity.control_authority,
            Some(identity.runtime_instance_id.as_str()),
            role,
            digest,
            "Podman",
        )?;
        container_shared::assert_container_image(command, &["inspect", object], image, "Podman")?;
    }
    for (volume, role, digest) in [
        (
            backup.postgres_volume.as_str(),
            "postgres-volume",
            identity.postgres_volume_config_digest.as_str(),
        ),
        (
            backup.valkey_volume.as_str(),
            "valkey-volume",
            identity.valkey_volume_config_digest.as_str(),
        ),
    ] {
        container_shared::assert_managed_labels(
            command,
            &["volume", "inspect", volume],
            &identity.deployment_id,
            &identity.control_authority,
            Some(identity.runtime_instance_id.as_str()),
            role,
            digest,
            "Podman",
        )?;
    }
    container_shared::backup_managed_dependencies(command, backup, true)
}

pub(super) fn ensure_network(
    command: &OsStr,
    network: &super::super::ManagedNetwork,
) -> anyhow::Result<std::net::IpAddr> {
    if Process::new(command)
        .args(["network", "inspect", network.name.as_str()])
        .succeeds()
    {
        container_shared::assert_managed_labels(
            command,
            &["network", "inspect", network.name.as_str()],
            &network.deployment_id,
            &network.control_authority,
            None,
            "network",
            &container_shared::network_config_digest(network),
            "Podman",
        )?;
    } else {
        let mut create = container_shared::append_managed_labels(
            Process::new(command).args(["network", "create"]),
            &network.deployment_id,
            &network.control_authority,
            None,
            "network",
            &container_shared::network_config_digest(network),
        );
        if let Some(subnet) = &network.subnet {
            create = create.args(["--subnet", subnet]);
        }
        create.arg(&network.name).run_quiet()?;
    }
    let document: serde_json::Value = serde_json::from_str(
        &Process::new(command)
            .args(["network", "inspect", network.name.as_str()])
            .stdout()?,
    )
    .context("Podman network inspection is not valid JSON")?;
    container_shared::network_gateway(&document)
        .context("Podman network has no inspectable gateway")
}

pub(super) fn ensure_dependencies(
    command: &OsStr,
    dependencies: &ManagedDependencies,
) -> anyhow::Result<()> {
    container_shared::require_digest_pinned_image(&dependencies.postgres_image, "Podman")?;
    container_shared::require_digest_pinned_image(&dependencies.valkey_image, "Podman")?;
    ensure_network(command, &dependencies.network)?;
    for volume in [
        (
            dependencies.postgres_volume.as_str(),
            "postgres-volume",
            dependencies.identity().postgres_volume_config_digest,
        ),
        (
            dependencies.valkey_volume.as_str(),
            "valkey-volume",
            dependencies.identity().valkey_volume_config_digest,
        ),
    ] {
        container_shared::ensure_volume(
            command,
            volume.0,
            &dependencies.network,
            &dependencies.runtime_instance_id,
            volume.1,
            &volume.2,
            "Podman",
        )?;
    }
    let identity = dependencies.identity();
    let postgres =
        Process::new(command).args(["run", "-d", "--name", dependencies.postgres_object.as_str()]);
    let postgres = container_shared::append_managed_labels(
        postgres,
        &identity.deployment_id,
        &identity.control_authority,
        Some(identity.runtime_instance_id.as_str()),
        "postgres",
        &identity.postgres_config_digest,
    )
    .args(["--restart", "unless-stopped", "--network"])
    .arg(&dependencies.network.name)
    .arg("--env")
    .arg(format!("POSTGRES_DB={}", dependencies.postgres_database))
    .arg("--env")
    .arg(format!("POSTGRES_USER={}", dependencies.postgres_user))
    .args([
        "--env",
        "POSTGRES_PASSWORD_FILE=/run/nazoauth-secrets/postgres-password",
        "--volume",
    ])
    .arg(format!(
        "{}:/var/lib/postgresql",
        dependencies.postgres_volume
    ))
    .arg("--volume")
    .arg(format!(
        "{}:/run/nazoauth-secrets/postgres-password:ro,Z",
        dependencies.postgres_password_file.display()
    ))
    .arg(&dependencies.postgres_image);
    container_shared::ensure_container(
        command,
        &dependencies.postgres_object,
        &dependencies.network,
        &dependencies.runtime_instance_id,
        "postgres",
        &identity.postgres_config_digest,
        &dependencies.postgres_image,
        postgres,
        "Podman",
    )?;

    let valkey =
        Process::new(command).args(["run", "-d", "--name", dependencies.valkey_object.as_str()]);
    let valkey = container_shared::append_managed_labels(
        valkey,
        &identity.deployment_id,
        &identity.control_authority,
        Some(identity.runtime_instance_id.as_str()),
        "valkey",
        &identity.valkey_config_digest,
    )
    .args(["--restart", "unless-stopped", "--network"])
    .arg(&dependencies.network.name)
    .arg("--volume")
    .arg(format!("{}:/data", dependencies.valkey_volume))
    .arg("--volume")
    .arg(format!(
        "{}:/run/nazoauth-secrets/valkey-password:ro,Z",
        dependencies.valkey_password_file.display()
    ))
    .arg("--volume")
    .arg(format!(
        "{}:/run/nazoauth-secrets/valkey.acl:ro,Z",
        dependencies.valkey_acl_file.display()
    ))
    .arg(&dependencies.valkey_image)
    .args([
        "valkey-server",
        "--aclfile",
        "/run/nazoauth-secrets/valkey.acl",
        "--appendonly",
        "yes",
        "--dir",
        "/data",
    ]);
    container_shared::ensure_container(
        command,
        &dependencies.valkey_object,
        &dependencies.network,
        &dependencies.runtime_instance_id,
        "valkey",
        &identity.valkey_config_digest,
        &dependencies.valkey_image,
        valkey,
        "Podman",
    )?;

    for _ in 0..60 {
        let postgres_ready = Process::new(command)
            .args([
                "exec",
                dependencies.postgres_object.as_str(),
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
            ])
            .arg(&dependencies.postgres_user)
            .arg("-d")
            .arg(&dependencies.postgres_database)
            .succeeds();
        let valkey_ready = Process::new(command)
            .args([
                "exec",
                dependencies.valkey_object.as_str(),
                "sh",
                "-eu",
                "-c",
            ])
            .arg("cat /run/nazoauth-secrets/valkey-password | valkey-cli --askpass PING")
            .succeeds();
        if postgres_ready && valkey_ready {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(1));
    }
    bail!("managed PostgreSQL or Valkey did not become ready through Podman")
}

pub(super) fn verify_database_privileges(
    command: &OsStr,
    probe: &RuntimeDatabasePrivilegeProbe,
) -> anyhow::Result<()> {
    Process::new(command)
        .args(["run", "--rm", "--network"])
        .arg(&probe.network)
        .args([
            "--env",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "--env",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "--volume",
        ])
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            probe.service_file.display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            probe.password_file.display()
        ))
        .arg(&probe.image)
        .args([
            "sh",
            "-eu",
            "-c",
            "if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TABLE nazoauth_runtime_ddl_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has persistent DDL permission' >&2; exit 1; fi; if psql --no-psqlrc --dbname='service=nazoauth' --set ON_ERROR_STOP=1 --command='BEGIN; CREATE TEMPORARY TABLE nazoauth_runtime_temp_probe(id integer); ROLLBACK;'; then echo 'runtime role unexpectedly has temporary DDL permission' >&2; exit 1; fi; exit 0",
        ])
        .run_quiet()
}
