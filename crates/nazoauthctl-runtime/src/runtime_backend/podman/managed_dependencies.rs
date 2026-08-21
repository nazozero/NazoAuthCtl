//! Podman-managed PostgreSQL and Valkey operations.

use std::{ffi::OsStr, thread, time::Duration};

use anyhow::{Context as _, bail};

use crate::process::Process;

use super::super::{
    ContainerRuntimePolicy, ManagedDependencies, ManagedDependencyBackup, ManagedPostgresCommand,
    ManagedPostgresRestore, ManagedValkeyRestore, RuntimeDatabasePrivilegeProbe, container_shared,
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
        &["container", "inspect", restore.postgres_object.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "postgres",
        &restore.identity.postgres_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["container", "inspect", restore.postgres_object.as_str()],
        &restore.postgres_image,
        "Podman",
    )?;
    container_shared::verify_oci_backup_artifacts(
        &restore.backup_directory,
        &restore.manifest_digest,
        &restore.completion_marker_digest,
    )?;
    let (journal_path, mut journal) = container_shared::load_dependency_restore_journal(
        &restore.backup_directory,
        "Podman",
        &restore.identity,
    )?;
    if matches!(
        journal.phase.as_str(),
        "postgres-swapped"
            | "valkey-prepared"
            | "valkey-old-quarantined"
            | "valkey-swapped"
            | "complete"
    ) {
        return Ok(());
    }
    if journal.phase != "started"
        && journal.phase != "postgres-prepared"
        && journal.phase != "postgres-old-quarantined"
    {
        bail!("Podman managed restore journal is not ready for PostgreSQL restore");
    }
    let database = container_shared::postgres_database_from_service_file(&restore.service_file)?;
    let temporary = journal
        .postgres_database
        .clone()
        .unwrap_or_else(|| format!("{database}_restore_{:016x}", rand::random::<u64>()));
    let quarantine = journal
        .postgres_quarantine_database
        .clone()
        .unwrap_or_else(|| format!("{database}_previous_{:016x}", rand::random::<u64>()));
    container_shared::validate_sql_identifier(&temporary, "temporary PostgreSQL database")?;
    container_shared::validate_sql_identifier(&quarantine, "PostgreSQL quarantine database")?;
    if temporary == database
        || quarantine == database
        || quarantine == temporary
        || !temporary.starts_with(&format!("{database}_restore_"))
        || !quarantine.starts_with(&format!("{database}_previous_"))
    {
        bail!("Podman managed restore journal contains unsafe PostgreSQL database names");
    }
    journal.postgres_database = Some(temporary.clone());
    journal.postgres_quarantine_database = Some(quarantine.clone());
    container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    if journal.phase == "started" {
        run_postgres_psql(
            command,
            restore,
            "postgres",
            &format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{temporary}'"
            ),
        )?;
        run_postgres_psql(
            command,
            restore,
            "postgres",
            &format!("DROP DATABASE IF EXISTS \"{temporary}\""),
        )?;
        run_postgres_psql(
            command,
            restore,
            "postgres",
            &format!("CREATE DATABASE \"{temporary}\""),
        )?;
        let temporary_credentials = container_shared::temporary_postgres_credentials(
            &restore.service_file,
            &restore.password_file,
            &temporary,
        )?;
        run_postgres_restore(command, restore, &temporary_credentials)?;
        run_postgres_psql_with_credentials(command, restore, &temporary_credentials, "SELECT 1")?;
        journal.phase = "postgres-prepared".to_owned();
        container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    }
    if journal.phase == "postgres-prepared" {
        let original_exists = postgres_database_exists(command, restore, &database)?;
        let quarantine_exists = postgres_database_exists(command, restore, &quarantine)?;
        if !original_exists && quarantine_exists {
            journal.phase = "postgres-old-quarantined".to_owned();
            container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
        } else if original_exists && !quarantine_exists {
            run_postgres_psql(
                command,
                restore,
                "postgres",
                &format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('{database}', '{temporary}') AND pid <> pg_backend_pid()"
                ),
            )?;
            run_postgres_psql(
                command,
                restore,
                "postgres",
                &format!("ALTER DATABASE \"{database}\" RENAME TO \"{quarantine}\""),
            )?;
            journal.phase = "postgres-old-quarantined".to_owned();
            container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
        } else {
            bail!("Podman PostgreSQL restore journal and database state disagree");
        }
    }
    if journal.phase == "postgres-old-quarantined" {
        let temporary_exists = postgres_database_exists(command, restore, &temporary)?;
        let original_exists = postgres_database_exists(command, restore, &database)?;
        if temporary_exists && !original_exists {
            run_postgres_psql(
                command,
                restore,
                "postgres",
                &format!("ALTER DATABASE \"{temporary}\" RENAME TO \"{database}\""),
            )?;
            journal.phase = "postgres-swapped".to_owned();
            container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
        } else if !temporary_exists && original_exists {
            journal.phase = "postgres-swapped".to_owned();
            container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
        } else {
            bail!("Podman PostgreSQL restore journal and temporary database state disagree");
        }
    }
    Ok(())
}

fn run_postgres_psql(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
    database: &str,
    sql: &str,
) -> anyhow::Result<()> {
    let credentials = container_shared::temporary_postgres_credentials(
        &restore.service_file,
        &restore.password_file,
        database,
    )?;
    run_postgres_psql_with_credentials(command, restore, &credentials, sql)
}

fn run_postgres_psql_with_credentials(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
    credentials: &container_shared::TemporaryPostgresCredentials,
    sql: &str,
) -> anyhow::Result<()> {
    container_shared::build_identity_process(command)
        .arg("--network")
        .arg(&restore.network)
        .args([
            "--env",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "--env",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "--volume",
        ])
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            credentials.service_file().display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            credentials.password_file().display()
        ))
        .arg(&restore.image)
        .args([
            "psql",
            "--no-psqlrc",
            "--set",
            "ON_ERROR_STOP=1",
            "--dbname=service=nazoauth",
            "--command",
        ])
        .arg(sql)
        .run_quiet()
}

fn run_postgres_restore(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
    credentials: &container_shared::TemporaryPostgresCredentials,
) -> anyhow::Result<()> {
    container_shared::build_identity_process(command)
        .arg("--network")
        .arg(&restore.network)
        .args([
            "--env",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "--env",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "--volume",
        ])
        .arg(format!(
            "{}:/backup:ro,Z",
            restore.backup_directory.display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            credentials.service_file().display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            credentials.password_file().display()
        ))
        .arg(&restore.image)
        .args([
            "pg_restore",
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
        &["container", "inspect", restore.object_reference.as_str()],
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "valkey",
        &restore.identity.valkey_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["container", "inspect", restore.object_reference.as_str()],
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
    container_shared::verify_oci_backup_artifacts(
        &restore.backup_directory,
        &restore.manifest_digest,
        &restore.completion_marker_digest,
    )?;
    let (journal_path, mut journal) = container_shared::load_dependency_restore_journal(
        &restore.backup_directory,
        "Podman",
        &restore.identity,
    )?;
    if matches!(journal.phase.as_str(), "valkey-swapped" | "complete") {
        return Ok(());
    }
    if !matches!(
        journal.phase.as_str(),
        "postgres-swapped" | "valkey-prepared" | "valkey-old-quarantined"
    ) {
        bail!("Podman managed restore journal is not ready for Valkey restore");
    }
    let temporary_volume = journal.valkey_temporary_volume.clone().unwrap_or_else(|| {
        format!(
            "{}-restore-{:016x}",
            restore.data_volume,
            rand::random::<u64>()
        )
    });
    let quarantine_volume = journal.valkey_quarantine_volume.clone().unwrap_or_else(|| {
        format!(
            "{}-previous-{:016x}",
            restore.data_volume,
            rand::random::<u64>()
        )
    });
    journal.valkey_temporary_volume = Some(temporary_volume.clone());
    journal.valkey_quarantine_volume = Some(quarantine_volume.clone());
    container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    ensure_restore_volume(command, restore, &temporary_volume)?;
    ensure_restore_volume(command, restore, &quarantine_volume)?;
    if journal.phase == "postgres-swapped" {
        restore_valkey_into_temporary(command, restore, &temporary_volume)?;
        validate_temporary_valkey(command, restore, &temporary_volume)?;
        journal.phase = "valkey-prepared".to_owned();
        container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    }
    if journal.phase == "valkey-prepared" {
        ensure_container_stopped(command, &restore.object_reference)?;
        if let Err(error) =
            copy_valkey_volume(command, restore, &restore.data_volume, &quarantine_volume)
        {
            let _ = ensure_container_started(command, &restore.object_reference);
            return Err(error);
        }
        journal.phase = "valkey-old-quarantined".to_owned();
        container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    }
    if journal.phase == "valkey-old-quarantined" {
        ensure_container_stopped(command, &restore.object_reference)?;
        if let Err(error) =
            copy_valkey_volume(command, restore, &temporary_volume, &restore.data_volume)
        {
            let _ = copy_valkey_volume(command, restore, &quarantine_volume, &restore.data_volume);
            let _ = ensure_container_started(command, &restore.object_reference);
            return Err(error);
        }
        if let Err(error) = ensure_container_started(command, &restore.object_reference) {
            let _ = copy_valkey_volume(command, restore, &quarantine_volume, &restore.data_volume);
            let _ = ensure_container_started(command, &restore.object_reference);
            return Err(error);
        }
        journal.phase = "valkey-swapped".to_owned();
        container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
        journal.phase = "complete".to_owned();
        container_shared::persist_dependency_restore_journal(&journal_path, &journal)?;
    }
    Ok(())
}

fn ensure_restore_volume(
    command: &OsStr,
    restore: &ManagedValkeyRestore,
    volume: &str,
) -> anyhow::Result<()> {
    let arguments = ["volume", "inspect", volume];
    if container_shared::inspect_document_optional(command, &arguments, "Podman")?.is_some() {
        return container_shared::assert_managed_labels(
            command,
            &arguments,
            &restore.identity.deployment_id,
            &restore.identity.control_authority,
            Some(restore.identity.runtime_instance_id.as_str()),
            "valkey-volume",
            &restore.identity.valkey_volume_config_digest,
            "Podman",
        );
    }
    container_shared::append_managed_labels(
        Process::new(command).args(["volume", "create"]),
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        "valkey-volume",
        &restore.identity.valkey_volume_config_digest,
    )
    .arg(volume)
    .run_quiet()
}

fn restore_valkey_into_temporary(
    command: &OsStr,
    restore: &ManagedValkeyRestore,
    volume: &str,
) -> anyhow::Result<()> {
    container_shared::build_identity_process(command)
    .args(["--network", "none"])
    .arg("--volume")
    .arg(format!("{volume}:/data:Z"))
    .arg("--volume")
    .arg(format!("{}:/backup:ro,Z", restore.backup_directory.display()))
    .arg(&restore.image)
    .args([
        "sh",
        "-eu",
        "-c",
        "test -s /backup/valkey-dump.rdb; find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; install -m 600 /backup/valkey-dump.rdb /data/dump.rdb",
    ])
    .run_quiet()
}

fn validate_temporary_valkey(
    command: &OsStr,
    restore: &ManagedValkeyRestore,
    volume: &str,
) -> anyhow::Result<()> {
    let container = format!("nazoauthctl-restore-check-{:016x}", rand::random::<u64>());
    let config_digest =
        container_shared::valkey_restore_check_config_digest(restore, volume, &container);
    container_shared::remove_managed_container_by_name(
        command,
        &container,
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        container_shared::VALKEY_RESTORE_CHECK_RESOURCE_KIND,
        &config_digest,
        "Podman",
    )?;
    let create = container_shared::append_managed_labels(
        container_shared::build_identity_process(command).args([
            "-d",
            "--name",
            &container,
            "--network",
            "none",
        ]),
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        container_shared::VALKEY_RESTORE_CHECK_RESOURCE_KIND,
        &config_digest,
    );
    create
        .arg("--volume")
        .arg(format!("{volume}:/data:Z"))
        .arg(&restore.image)
        .args([
            "valkey-server",
            "--save",
            "",
            "--appendonly",
            "no",
            "--port",
            "6379",
            "--protected-mode",
            "no",
        ])
        .run_quiet()?;
    let container_id = match container_shared::inspect_managed_container_id(
        command,
        &container,
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        container_shared::VALKEY_RESTORE_CHECK_RESOURCE_KIND,
        &config_digest,
        "Podman",
    ) {
        Ok(Some(container_id)) => container_id,
        Ok(None) => bail!("temporary Podman Valkey restore disappeared before validation"),
        Err(error) => {
            let cleanup = container_shared::remove_managed_container_by_name(
                command,
                &container,
                &restore.identity.deployment_id,
                &restore.identity.control_authority,
                Some(restore.identity.runtime_instance_id.as_str()),
                container_shared::VALKEY_RESTORE_CHECK_RESOURCE_KIND,
                &config_digest,
                "Podman",
            );
            if let Err(cleanup) = cleanup {
                return Err(error.context(format!(
                    "temporary Podman Valkey restore cleanup failed: {cleanup}"
                )));
            }
            return Err(error);
        }
    };
    let mut ready = false;
    for _ in 0..30 {
        if Process::new(command)
            .args(["exec", container_id.as_str(), "valkey-cli", "PING"])
            .succeeds()
        {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    let validation = ready
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("temporary Valkey restore failed readiness validation"));
    let cleanup = container_shared::remove_managed_container_by_id(
        command,
        &container_id,
        &restore.identity.deployment_id,
        &restore.identity.control_authority,
        Some(restore.identity.runtime_instance_id.as_str()),
        container_shared::VALKEY_RESTORE_CHECK_RESOURCE_KIND,
        &config_digest,
        "Podman",
    );
    match (validation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!(
            "temporary Podman Valkey restore cleanup failed: {cleanup}"
        ))),
    }
}

fn copy_valkey_volume(
    command: &OsStr,
    restore: &ManagedValkeyRestore,
    source: &str,
    destination: &str,
) -> anyhow::Result<()> {
    container_shared::build_managed_volume_copy_process(command)
    .arg("--volume")
    .arg(format!("{source}:/source:ro,Z"))
    .arg("--volume")
    .arg(format!("{destination}:/destination:Z"))
    .arg(&restore.image)
    .args([
        "sh",
        "-eu",
        "-c",
        "find /destination -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; cp -a /source/. /destination/",
    ])
    .run_quiet()
}

fn ensure_container_started(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    if container_shared::container_is_running(command, object_reference, "Podman")? {
        return Ok(());
    }
    Process::new(command)
        .args(["start", object_reference])
        .run_quiet()
}

fn postgres_database_exists(
    command: &OsStr,
    restore: &ManagedPostgresRestore,
    database: &str,
) -> anyhow::Result<bool> {
    let credentials = container_shared::temporary_postgres_credentials(
        &restore.service_file,
        &restore.password_file,
        "postgres",
    )?;
    let output = container_shared::build_identity_process(command)
        .arg("--network")
        .arg(&restore.network)
        .args([
            "--env",
            "PGSERVICEFILE=/run/nazoauth-secrets/pg_service.conf",
            "--env",
            "PGPASSFILE=/run/nazoauth-secrets/pgpass",
            "--volume",
        ])
        .arg(format!(
            "{}:/run/nazoauth-secrets/pg_service.conf:ro,Z",
            credentials.service_file().display()
        ))
        .arg("--volume")
        .arg(format!(
            "{}:/run/nazoauth-secrets/pgpass:ro,Z",
            credentials.password_file().display()
        ))
        .arg(&restore.image)
        .args([
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--dbname=service=nazoauth",
            "--command",
        ])
        .arg(format!(
            "SELECT 1 FROM pg_database WHERE datname = '{database}'"
        ))
        .stdout()?;
    match output.trim() {
        "" => Ok(false),
        "1" => Ok(true),
        _ => bail!("Podman PostgreSQL database existence probe returned invalid output"),
    }
}

fn ensure_container_stopped(command: &OsStr, object_reference: &str) -> anyhow::Result<()> {
    if !container_shared::container_is_running(command, object_reference, "Podman")? {
        return Ok(());
    }
    Process::new(command)
        .args(["stop", object_reference])
        .run_quiet()
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
        &["container", "inspect", operation.object_reference.as_str()],
        &operation.identity.deployment_id,
        &operation.identity.control_authority,
        Some(operation.identity.runtime_instance_id.as_str()),
        "postgres",
        &operation.identity.postgres_config_digest,
        "Podman",
    )?;
    container_shared::assert_container_image(
        command,
        &["container", "inspect", operation.object_reference.as_str()],
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
            &["container", "inspect", object],
            &identity.deployment_id,
            &identity.control_authority,
            Some(identity.runtime_instance_id.as_str()),
            role,
            digest,
            "Podman",
        )?;
        container_shared::assert_container_image(
            command,
            &["container", "inspect", object],
            image,
            "Podman",
        )?;
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
    let network_inspect = ["network", "inspect", network.name.as_str()];
    if container_shared::inspect_document_optional(command, &network_inspect, "Podman")?.is_some() {
        container_shared::assert_managed_labels(
            command,
            &network_inspect,
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
    let document: serde_json::Value = serde_json::from_str(&container_shared::command_stdout(
        command,
        &["network", "inspect", network.name.as_str()],
        "Podman",
    )?)
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
    let postgres_policy = ContainerRuntimePolicy::managed_postgres();
    let valkey_policy = ContainerRuntimePolicy::managed_valkey();
    if container_shared::inspect_document_optional(
        command,
        &[
            "container",
            "inspect",
            dependencies.postgres_object.as_str(),
        ],
        "Podman",
    )?
    .is_none()
    {
        container_shared::prepare_managed_volume_ownership(
            command,
            &dependencies.postgres_volume,
            &dependencies.postgres_image,
            "/var/lib/postgresql",
            "999:999",
            "Podman",
        )?;
    }
    if container_shared::inspect_document_optional(
        command,
        &["container", "inspect", dependencies.valkey_object.as_str()],
        "Podman",
    )?
    .is_none()
    {
        container_shared::prepare_managed_volume_ownership(
            command,
            &dependencies.valkey_volume,
            &dependencies.valkey_image,
            "/data",
            "999:1000",
            "Podman",
        )?;
    }
    let postgres_password_source = dependencies
        .postgres_password_file
        .to_string_lossy()
        .into_owned();
    let postgres = Process::new(command).args([
        "run",
        "-d",
        "--pull=never",
        "--name",
        dependencies.postgres_object.as_str(),
    ]);
    let postgres = container_shared::append_container_policy(
        container_shared::append_managed_labels(
            postgres,
            &identity.deployment_id,
            &identity.control_authority,
            Some(identity.runtime_instance_id.as_str()),
            "postgres",
            &identity.postgres_config_digest,
        ),
        &postgres_policy,
    )
    .args(["--network"])
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
        &postgres_policy,
        &[
            (
                "/var/lib/postgresql",
                false,
                Some(dependencies.postgres_volume.as_str()),
            ),
            (
                "/run/nazoauth-secrets/postgres-password",
                true,
                Some(postgres_password_source.as_str()),
            ),
        ],
        &[
            ("POSTGRES_DB", dependencies.postgres_database.as_str()),
            ("POSTGRES_USER", dependencies.postgres_user.as_str()),
            (
                "POSTGRES_PASSWORD_FILE",
                "/run/nazoauth-secrets/postgres-password",
            ),
        ],
    )?;
    container_shared::reconcile_bound_file(
        command,
        &dependencies.postgres_object,
        &dependencies.postgres_password_file,
        "/run/nazoauth-secrets/postgres-password",
        "Podman PostgreSQL",
    )?;

    let valkey = Process::new(command).args([
        "run",
        "-d",
        "--pull=never",
        "--name",
        dependencies.valkey_object.as_str(),
    ]);
    let valkey_password_source = dependencies
        .valkey_password_file
        .to_string_lossy()
        .into_owned();
    let valkey_acl_source = dependencies.valkey_acl_file.to_string_lossy().into_owned();
    let valkey = container_shared::append_container_policy(
        container_shared::append_managed_labels(
            valkey,
            &identity.deployment_id,
            &identity.control_authority,
            Some(identity.runtime_instance_id.as_str()),
            "valkey",
            &identity.valkey_config_digest,
        ),
        &valkey_policy,
    )
    .args(["--network"])
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
        &valkey_policy,
        &[
            ("/data", false, Some(dependencies.valkey_volume.as_str())),
            (
                "/run/nazoauth-secrets/valkey-password",
                true,
                Some(valkey_password_source.as_str()),
            ),
            (
                "/run/nazoauth-secrets/valkey.acl",
                true,
                Some(valkey_acl_source.as_str()),
            ),
        ],
        &[],
    )?;
    container_shared::reconcile_bound_file(
        command,
        &dependencies.valkey_object,
        &dependencies.valkey_password_file,
        "/run/nazoauth-secrets/valkey-password",
        "Podman Valkey",
    )?;
    container_shared::reconcile_bound_file(
        command,
        &dependencies.valkey_object,
        &dependencies.valkey_acl_file,
        "/run/nazoauth-secrets/valkey.acl",
        "Podman Valkey",
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
            .arg("exec valkey-cli --user \"$1\" --askpass PING < /run/nazoauth-secrets/valkey-password")
            .arg("_")
            .arg(&dependencies.valkey_user)
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
    container_shared::build_identity_process(command)
    .arg("--network")
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
