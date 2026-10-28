//! Uninstall only ctl-owned, deployment-scoped resources.
//!
//! Plan first, then execute:
//!
//! * the deletion plan is generated from the LIVE DeploymentState and lists
//!   exactly the managed+deployment resources plus the runtime object and
//!   config file; external/shared resources are printed as kept — they have
//!   zero-delete paths by construction;
//! * execution requires explicit confirmation; the target derives deletions
//!   from its own authoritative state rather than trusting a duplicated plan;
//!   container runtime identity remains bound by the deployment label;
//! * completion removes ONLY this instance's InstanceRecord — never the
//!   HostRecord and never sibling instances on the same host;
//! * local Controller Key material is deleted with the local InstanceRecord;
//!   Controller Slot rows remain inside any external database the plan keeps.

use anyhow::{Context as _, bail};

use super::{LifecycleContext, resolve_instance_target};
use crate::controller_identity::store::ControllerKeyStore;
use crate::file_lock::FileLock;
use crate::target::{
    HostOperation, HostOperationBody, HostOutcome, InstanceInspection, ResourceOwnership,
    ResourceScope, StateMutationPayload,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedUninstall {
    schema: u32,
    operation: HostOperation,
    alias: String,
}

fn read_pending(path: &std::path::Path) -> anyhow::Result<(HostOperation, Option<String>)> {
    let bytes = crate::filesystem::read_secure_regular_file(
        path,
        "pending uninstall",
        false,
        crate::target::MAX_HOST_OPERATION_BYTES as u64 + 1024,
    )?;
    // TODO: remove the bare HostOperation reader when all pre-completion-marker
    // controller versions and their pending uninstall files are retired.
    if let Ok(operation) = crate::target::parse_host_operation(&bytes) {
        return Ok((operation, None));
    }
    let completed: CompletedUninstall = serde_json::from_slice(&bytes)?;
    if completed.schema != 1 {
        bail!("unsupported completed uninstall schema");
    }
    let operation = crate::target::parse_host_operation(&crate::target::encode_host_operation(
        &completed.operation,
    )?)?;
    Ok((operation, Some(completed.alias)))
}

pub(super) fn clear_completed_for_existing_deployment(
    path: &std::path::Path,
    deployment_id: &str,
) -> anyhow::Result<bool> {
    if !path.try_exists()? {
        return Ok(false);
    }
    let (operation, completed) = read_pending(path)?;
    if completed.is_some()
        && operation.deployment_id.as_deref() == Some(deployment_id)
        && matches!(
            operation.operation,
            HostOperationBody::StateMutate {
                mutation: StateMutationPayload::Uninstall {}
            }
        )
    {
        crate::filesystem::remove_file_durable(path)?;
        return Ok(true);
    }
    Ok(false)
}

fn finish_local_cleanup(
    registry: &crate::registry::RegistryStore,
    keys: &ControllerKeyStore,
    deployment_id: &str,
    pending_path: &std::path::Path,
) -> anyhow::Result<()> {
    keys.remove_instance(deployment_id)?;
    if registry.instance_by_deployment(deployment_id)?.is_some() {
        registry.forget_instance_by_deployment(deployment_id)?;
    }
    crate::filesystem::remove_file_durable(pending_path)
}

struct LifecycleLocks {
    _bind: FileLock,
    _controller_recovery: FileLock,
    _data_recovery: FileLock,
    _transfer: FileLock,
}

impl LifecycleLocks {
    fn acquire(instance_dir: &std::path::Path) -> anyhow::Result<Self> {
        crate::filesystem::ensure_private_directory(
            instance_dir,
            "controller instance lifecycle directory",
        )?;
        let locks = Self {
            _bind: FileLock::acquire(&instance_dir.join("bind.lock"))?,
            _controller_recovery: FileLock::acquire(&instance_dir.join("recovery.lock"))?,
            _data_recovery: FileLock::acquire(&instance_dir.join("recovery-plan.lock"))?,
            _transfer: FileLock::acquire(&instance_dir.join("backup-transfer.lock"))?,
        };
        ensure_no_pending_remote_cleanup(instance_dir)?;
        Ok(locks)
    }
}

/// One uninstall plan: exact deletions plus everything deliberately kept.
pub(crate) struct UninstallPlan {
    pub(crate) deployment_id: String,
    pub(crate) alias: String,
    pub(crate) host_alias: String,
    pub(crate) revision: u64,
    pub(crate) managed_deletions: Vec<(String, String, String)>, // id, kind, locator
    pub(crate) runtime_object: String,
    pub(crate) config_reference: String,
    pub(crate) kept_external: Vec<(String, String, String)>,
}

/// Render the human-readable plan. The plan precedes any destructive action;
/// nothing has been touched when this string is all the user asked for.
impl UninstallPlan {
    pub(crate) fn render(&self) -> String {
        let mut text = crate::ui::message!(
            "uninstall plan for '{}' (deployment {}, host '{}')\n",
            "实例“{}”的卸载计划\n\n部署：{}\n主机：{}\n",
            self.alias,
            self.deployment_id,
            self.host_alias
        );
        text.push_str(crate::ui::text(
            "deletions (managed + deployment-scoped only):\n",
            "将删除（由 ctl 管理且仅属于此部署）：\n",
        ));
        text.push_str(&crate::ui::message!(
            "  - runtime object '{}' (target-owned runtime identity)\n",
            "  - 运行实例“{}”\n",
            self.runtime_object
        ));
        for (id, kind, locator) in &self.managed_deletions {
            text.push_str(&format!("  - {id} ({kind}): {locator}\n"));
        }
        text.push_str(&crate::ui::message!(
            "  - config file {}\n  - ctl state document (journal retained)\n",
            "  - 配置文件 {}\n  - ctl 部署状态（保留操作日志）\n",
            self.config_reference
        ));
        if self.kept_external.is_empty() {
            text.push_str(crate::ui::text("kept: none declared\n", "保留资源：无\n"));
        } else {
            text.push_str(crate::ui::text(
                "kept (external/shared — ZERO DELETE):\n",
                "保留以下外部或共享资源：\n",
            ));
            for (id, kind, locator) in &self.kept_external {
                text.push_str(&format!("  - {id} ({kind}): {locator}\n"));
            }
        }
        text.push_str(crate::ui::text(
            "untouched: HostRecord and sibling instances on this host\n",
            "主机注册记录与此主机的其他实例保持不变。\n",
        ));
        text.push_str(
            crate::ui::text("Controller Slots in kept external data are unchanged; revoke them before uninstall if required\n", "外部数据库中的控制器授权会保留；如需撤销，请在卸载前操作。\n"),
        );
        text.push_str(
            crate::ui::text("local cleanup after target success: InstanceRecord and this deployment's controller key material\n", "目标卸载成功后，清理此实例的本地注册记录与控制器密钥。\n"),
        );
        text
    }
}

/// Generate the exact deletion plan from live facts (read-only).
#[cfg(test)]
pub(crate) fn plan_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<UninstallPlan> {
    let (record, host, _, inspection) =
        super::resolve_live_instance(context, selector, "uninstall")?;
    Ok(uninstall_plan(&record, &host, inspection))
}

fn uninstall_plan(
    record: &crate::registry::InstanceRecord,
    host: &crate::registry::HostRecord,
    inspection: InstanceInspection,
) -> UninstallPlan {
    let mut managed_deletions = Vec::new();
    let mut kept_external = Vec::new();
    for resource in inspection.resources {
        // Container-kind resources are deleted through the dedicated runtime
        // surface object (ownership label + digest re-confirmation), never as
        // a second deletion entry — declaring them here would double-delete.
        if resource.kind == "container" {
            continue;
        }
        let entry = (resource.resource_id, resource.kind, resource.locator);
        match (resource.ownership, resource.scope) {
            (ResourceOwnership::Managed, ResourceScope::Deployment) => {
                managed_deletions.push(entry)
            }
            _ => kept_external.push(entry),
        }
    }
    UninstallPlan {
        deployment_id: inspection.deployment_id,
        alias: record.alias.clone(),
        host_alias: host.alias.clone(),
        revision: inspection.revision,
        managed_deletions,
        runtime_object: inspection.runtime.object,
        config_reference: inspection.config_reference,
        kept_external,
    }
}

/// Execute a previously shown plan. `confirmed` must be an explicit operator
/// decision; without it only the plan is rendered. Confirmed execution reuses
/// the same live read and relies on the target-side revision CAS for drift.
pub(crate) fn run_uninstall(
    context: &LifecycleContext,
    controller_keys: &ControllerKeyStore,
    selector: Option<&str>,
    confirmed: bool,
) -> anyhow::Result<String> {
    let action = "uninstall";
    // A committed target receipt is enough to finish local cleanup even when
    // the target is no longer reachable. Keep the existing registry record
    // until the key material and marker have been handled.
    if let Ok(record) = crate::fleet::resolve_instance(&context.registry, selector, action) {
        let _guard = super::HostIntent::open(
            &context.registry,
            controller_keys,
            &record.deployment_id,
            action,
        )?;
        let path = controller_keys
            .instance_dir(&record.deployment_id)?
            .with_extension("uninstall.json");
        if path.try_exists()? {
            let (operation, completed) = read_pending(&path)?;
            if completed.is_some()
                && operation.deployment_id.as_deref() == Some(record.deployment_id.as_str())
                && matches!(
                    operation.operation,
                    HostOperationBody::StateMutate {
                        mutation: StateMutationPayload::Uninstall {}
                    }
                )
            {
                let _locks =
                    LifecycleLocks::acquire(&controller_keys.instance_dir(&record.deployment_id)?)?;
                finish_local_cleanup(
                    &context.registry,
                    controller_keys,
                    &record.deployment_id,
                    &path,
                )?;
                return Ok(format!(
                    "uninstall of '{}' ({}) was completed; remaining local cleanup is complete",
                    record.alias, record.deployment_id
                ));
            }
        }
    }
    let resolved = resolve_instance_target(context, selector, action);
    let (record, host, target) = match resolved {
        Ok(value) => value,
        Err(error) => {
            if let Some(deployment_id) = selector
                && let Ok(instance_dir) = controller_keys.instance_dir(deployment_id)
                && context
                    .registry
                    .instance_by_deployment(deployment_id)?
                    .is_none()
            {
                let _guard = super::HostIntent::open(
                    &context.registry,
                    controller_keys,
                    deployment_id,
                    action,
                )?;
                let path = instance_dir.with_extension("uninstall.json");
                if path.try_exists()? {
                    let (operation, completed) = read_pending(&path)?;
                    if let Some(alias) = completed
                        && operation.deployment_id.as_deref() == Some(deployment_id)
                        && matches!(
                            operation.operation,
                            HostOperationBody::StateMutate {
                                mutation: StateMutationPayload::Uninstall {}
                            }
                        )
                    {
                        let _locks = LifecycleLocks::acquire(&instance_dir)?;
                        finish_local_cleanup(
                            &context.registry,
                            controller_keys,
                            deployment_id,
                            &path,
                        )?;
                        return Ok(format!(
                            "uninstall of '{alias}' ({deployment_id}) was completed; remaining local cleanup is complete"
                        ));
                    }
                }
            }
            return Err(error.context("if uninstall completed but local cleanup was interrupted, retry using the deployment id"));
        }
    };
    let _intent_guard = super::HostIntent::open(
        &context.registry,
        controller_keys,
        &record.deployment_id,
        action,
    )?;
    let instance_dir = controller_keys.instance_dir(&record.deployment_id)?;
    // Outside the key directory: this exact confirmed operation must survive
    // key cleanup if forgetting the local registry record subsequently fails.
    let pending_path = instance_dir.with_extension("uninstall.json");
    let pending = if pending_path.try_exists()? {
        let (operation, _) = read_pending(&pending_path)?;
        if operation.deployment_id.as_deref() != Some(record.deployment_id.as_str())
            || !matches!(
                operation.operation,
                HostOperationBody::StateMutate {
                    mutation: StateMutationPayload::Uninstall {}
                }
            )
        {
            bail!("pending uninstall does not match this deployment");
        }
        Some(operation)
    } else {
        None
    };
    let operation = if let Some(operation) = pending {
        operation
    } else {
        let inspection = target.inspect_instance(&record.deployment_id)?;
        let plan = uninstall_plan(&record, &host, inspection);
        if !confirmed {
            use std::io::IsTerminal as _;
            if !crate::ui::json_mode()
                && std::io::stdin().is_terminal()
                && std::io::stderr().is_terminal()
            {
                crate::ui::print_report(&plan.render());
                if !cliclack::confirm(crate::ui::text(
                    "Delete the resources listed above?",
                    "确认删除以上列出的资源？",
                ))
                .initial_value(false)
                .interact()?
                {
                    return Ok(crate::ui::text(
                        "Uninstall cancelled; no resources deleted.",
                        "已取消卸载，未删除资源。",
                    )
                    .into());
                }
            } else {
                return Ok(crate::ui::message!(
                    "{}\nre-run with explicit confirmation (--yes at the CLI boundary) to execute",
                    "{}\n以上仅为计划，尚未删除资源。确认后添加 --yes 重新运行。",
                    plan.render()
                ));
            }
        }
        HostOperation::state_mutate(
            uuid::Uuid::now_v7().to_string(),
            plan.deployment_id,
            Some(plan.revision),
            StateMutationPayload::Uninstall {},
        )
    };
    // All instance-scoped long-running flows take one of these outer locks
    // before entering the shared key/journal lock. Holding them in that same
    // order makes uninstall a single linearized lifecycle action without a
    // second recovery framework.
    let _locks = LifecycleLocks::acquire(&instance_dir)?;

    // Another confirmed invocation may have acquired these same lifecycle
    // locks first. Reuse its saved operation rather than replacing its identity.
    let operation = if pending_path.try_exists()? {
        read_pending(&pending_path)?.0
    } else {
        crate::filesystem::atomic_write(
            &pending_path,
            &crate::target::encode_host_operation(&operation)?,
            0o600,
        )?;
        operation
    };
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        HostOutcome::Completed { .. } => {}
        HostOutcome::Failed { code, detail } => {
            if code == crate::error_codes::CONFIG_REVISION_MISMATCH {
                // The target rejects stale plans before deletion. A fresh
                // invocation must show and confirm the new resource plan.
                crate::filesystem::remove_file_durable(&pending_path)?;
            }
            bail!("{action} failed on the target: {code}: {detail}")
        }
    }

    crate::filesystem::atomic_write(
        &pending_path,
        &serde_json::to_vec(&CompletedUninstall {
            schema: 1,
            operation,
            alias: record.alias.clone(),
        })?,
        0o600,
    )?;

    // Completion removes this instance's two local ownership records. HostRecord
    // and siblings stay. Controller Slot rows are part of an external database
    // and therefore follow the plan's explicit keep decision.
    finish_local_cleanup(&context.registry, controller_keys, &record.deployment_id, &pending_path)
        .with_context(|| format!("instance '{}' was uninstalled but local cleanup remains pending; retry using deployment id '{}'", record.alias, record.deployment_id))?;
    Ok(crate::ui::message!(
        "uninstalled instance '{}' (deployment {})\n\
         managed resources removed per plan; external/shared resources were never touched\n\
         Controller Slots in kept external data were unchanged\n\
         InstanceRecord and local controller key material removed; HostRecord '{}' and sibling instances remain\n",
        "实例“{}”已卸载（部署 {}）\n\n已按计划删除托管资源，保留外部和共享资源及其控制器授权。\n已清理本地实例记录和控制器密钥；主机“{}”及其其他实例保持不变。\n",
        record.alias,
        record.deployment_id,
        host.alias,
    ))
}

fn ensure_no_pending_remote_cleanup(instance_dir: &std::path::Path) -> anyhow::Result<()> {
    for (file, operation) in [
        ("recovery-plan.json", "disaster recovery"),
        ("backup-transfer.json", "off-host backup transfer"),
    ] {
        let path = instance_dir.join(file);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                bail!(
                    "cannot uninstall while this instance has an incomplete {operation}; resume that operation so its remote staging is cleaned first"
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }
    Ok(())
}
