//! G06 — uninstall that touches only ctl-owned deployment-scoped resources
//! (goal plan 07 §7).
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

use super::{LifecycleContext, resolve_live_instance};
use crate::controller_identity::store::ControllerKeyStore;
use crate::file_lock::FileLock;
use crate::target::{
    ExecutionTarget, HostOperation, HostOutcome, ResourceOwnership, ResourceScope,
    StateMutationPayload,
};

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
    Ok(prepare_uninstall(context, selector)?.0)
}

fn prepare_uninstall(
    context: &LifecycleContext,
    selector: Option<&str>,
) -> anyhow::Result<(UninstallPlan, Box<dyn ExecutionTarget + Send>)> {
    let (record, host, target, inspection) = resolve_live_instance(context, selector, "uninstall")?;
    let mut managed_deletions = Vec::new();
    let mut kept_external = Vec::new();
    for resource in &inspection.resources {
        // Container-kind resources are deleted through the dedicated runtime
        // surface object (ownership label + digest re-confirmation), never as
        // a second deletion entry — declaring them here would double-delete.
        if resource.kind == "container" {
            continue;
        }
        let entry = (
            resource.resource_id.clone(),
            resource.kind.clone(),
            resource.locator.clone(),
        );
        match (resource.ownership, resource.scope) {
            (ResourceOwnership::Managed, ResourceScope::Deployment) => {
                managed_deletions.push(entry)
            }
            _ => kept_external.push(entry),
        }
    }
    Ok((
        UninstallPlan {
            deployment_id: inspection.deployment_id.clone(),
            alias: record.alias.clone(),
            host_alias: host.alias.clone(),
            revision: inspection.revision,
            managed_deletions,
            runtime_object: inspection.runtime.object.clone(),
            config_reference: inspection.config_reference.clone(),
            kept_external,
        },
        target,
    ))
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
    let (plan, target) = prepare_uninstall(context, selector)?;
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
    let instance_dir = controller_keys.instance_dir(&plan.deployment_id)?;
    crate::filesystem::ensure_private_directory(
        &instance_dir,
        "controller instance lifecycle directory",
    )?;
    // All instance-scoped long-running flows take one of these outer locks
    // before entering the shared key/journal lock. Holding them in that same
    // order makes uninstall a single linearized lifecycle action without a
    // second recovery framework.
    let _bind_lock = FileLock::acquire(&instance_dir.join("bind.lock"))?;
    let _controller_recovery_lock = FileLock::acquire(&instance_dir.join("recovery.lock"))?;
    let _data_recovery_lock = FileLock::acquire(&instance_dir.join("recovery-plan.lock"))?;
    let _transfer_lock = FileLock::acquire(&instance_dir.join("backup-transfer.lock"))?;
    ensure_no_pending_remote_cleanup(controller_keys, &plan.deployment_id)?;

    let operation = HostOperation::state_mutate(
        uuid::Uuid::now_v7().to_string(),
        plan.deployment_id.clone(),
        Some(plan.revision),
        StateMutationPayload::Uninstall {},
    );
    let result = target.execute_host_operation(&operation)?;
    match result.outcome {
        HostOutcome::Completed { .. } => {}
        HostOutcome::Failed { code, detail } => {
            bail!("{action} failed on the target: {code}: {detail}")
        }
    }

    // Completion removes this instance's two local ownership records. HostRecord
    // and siblings stay. Controller Slot rows are part of an external database
    // and therefore follow the plan's explicit keep decision.
    controller_keys
        .remove_instance(&plan.deployment_id)
        .with_context(|| {
            format!(
                "instance '{}' was uninstalled, but its local controller key cleanup failed; the InstanceRecord was retained so cleanup can be retried",
                plan.alias
            )
        })?;
    context
        .registry
        .forget_instance_by_deployment(&plan.deployment_id)
        .with_context(|| {
            format!(
                "instance '{}' was uninstalled and its local controller keys were removed, but its stale InstanceRecord could not be forgotten",
                plan.alias
            )
        })?;

    Ok(crate::ui::message!(
        "uninstalled instance '{}' (deployment {})\n\
         managed resources removed per plan; external/shared resources were never touched\n\
         Controller Slots in kept external data were unchanged\n\
         InstanceRecord and local controller key material removed; HostRecord '{}' and sibling instances remain\n",
        "实例“{}”已卸载（部署 {}）\n\n已按计划删除托管资源，保留外部和共享资源及其控制器授权。\n已清理本地实例记录和控制器密钥；主机“{}”及其其他实例保持不变。\n",
        plan.alias,
        plan.deployment_id,
        plan.host_alias,
    ))
}

fn ensure_no_pending_remote_cleanup(
    controller_keys: &ControllerKeyStore,
    deployment_id: &str,
) -> anyhow::Result<()> {
    let instance_dir = controller_keys.instance_dir(deployment_id)?;
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
