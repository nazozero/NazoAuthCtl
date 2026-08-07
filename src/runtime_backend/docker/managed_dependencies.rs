//! Docker-managed PostgreSQL and Valkey lifecycle operations.

use std::{ffi::OsStr, thread, time::Duration};

use anyhow::{Context as _, bail};

use crate::process::Process;

use super::super::{
    ManagedDependencies, ManagedDependencyBackup, ManagedPostgresCommand, ManagedPostgresRestore,
    ManagedValkeyRestore, RuntimeDatabasePrivilegeProbe, container_shared,
};

pub(super) fn backup(command: &OsStr, backup: &ManagedDependencyBackup) -> anyhow::Result<()> {
    container_shared::backup_managed_dependencies(command, backup, false)
}

pub(super) fn restore_postgres(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
) -> anyhow::Result<()> {
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
        .arg(format!("{}:/backup:ro", restore.backup_directory.display()))
        .arg("-v")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro",
            restore.service_file.display()
        ))
        .arg("-v")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro",
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
    stop_container(command, &restore.object_reference)?;
    let restored = Process::new(command)
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/data", restore.data_volume))
        .arg("-v")
        .arg(format!(
            "{}:/backup:ro",
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
    let restarted = start_container(command, &restore.object_reference);
    restored?;
    restarted
}

pub(super) fn execute_postgres(
    command: &OsStr,
    operation: &ManagedPostgresCommand,
) -> anyhow::Result<()> {
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

pub(super) fn ensure_network(
    command: &OsStr,
    network: &super::super::ManagedNetwork,
) -> anyhow::Result<std::net::IpAddr> {
    if Process::new(command)
        .args(["network", "inspect", network.name.as_str()])
        .succeeds()
    {
        container_shared::assert_control_labels(
            command,
            &["network", "inspect", network.name.as_str()],
            &network.deployment_id,
            &network.control_authority,
            "Docker",
        )?;
    } else {
        let mut create = Process::new(command)
            .args(["network", "create", "--label"])
            .arg(format!(
                "io.nazoauth.deployment-id={}",
                network.deployment_id
            ))
            .arg("--label")
            .arg(format!(
                "io.nazoauth.control-authority={}",
                network.control_authority
            ));
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
    .context("Docker network inspection is not valid JSON")?;
    container_shared::network_gateway(&document)
        .context("Docker network has no inspectable gateway")
}

pub(super) fn ensure_dependencies(
    command: &OsStr,
    dependencies: &ManagedDependencies,
) -> anyhow::Result<()> {
    ensure_network(command, &dependencies.network)?;
    for volume in [
        dependencies.postgres_volume.as_str(),
        dependencies.valkey_volume.as_str(),
    ] {
        container_shared::ensure_volume(command, volume, &dependencies.network, "Docker")?;
    }
    let postgres = Process::new(command)
        .args(["run", "-d", "--name", dependencies.postgres_object.as_str()])
        .arg("--label")
        .arg(format!(
            "io.nazoauth.deployment-id={}",
            dependencies.network.deployment_id
        ))
        .arg("--label")
        .arg(format!(
            "io.nazoauth.control-authority={}",
            dependencies.network.control_authority
        ))
        .arg("--label")
        .arg(format!(
            "io.nazoauth.runtime-instance-id={}-postgres",
            dependencies.runtime_instance_id
        ))
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
            "{}:/run/nazoauth-secrets/postgres-password:ro",
            dependencies.postgres_password_file.display()
        ))
        .arg(&dependencies.postgres_image);
    container_shared::ensure_container(
        command,
        &dependencies.postgres_object,
        &dependencies.network,
        postgres,
        "Docker",
    )?;

    let valkey = Process::new(command)
        .args(["run", "-d", "--name", dependencies.valkey_object.as_str()])
        .arg("--label")
        .arg(format!(
            "io.nazoauth.deployment-id={}",
            dependencies.network.deployment_id
        ))
        .arg("--label")
        .arg(format!(
            "io.nazoauth.control-authority={}",
            dependencies.network.control_authority
        ))
        .arg("--label")
        .arg(format!(
            "io.nazoauth.runtime-instance-id={}-valkey",
            dependencies.runtime_instance_id
        ))
        .args(["--restart", "unless-stopped", "--network"])
        .arg(&dependencies.network.name)
        .arg("--volume")
        .arg(format!("{}:/data", dependencies.valkey_volume))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/valkey-password:ro",
            dependencies.valkey_password_file.display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/valkey.acl:ro",
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
        valkey,
        "Docker",
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
    bail!("managed PostgreSQL or Valkey did not become ready through Docker")
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
            "--mount",
        ])
        .arg(format!(
            "type=bind,src={},dst=/run/nazoauth-secrets/pg_service.conf,readonly",
            probe.service_file.display()
        ))
        .arg("--mount")
        .arg(format!(
            "type=bind,src={},dst=/run/nazoauth-secrets/pgpass,readonly",
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

fn start_container(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["start", object_reference])
        .run_quiet()
}

fn stop_container(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    Process::new(command)
        .args(["stop", object_reference])
        .run_quiet()
}
