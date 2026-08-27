//! The fixed target-side stdio executor: `nazauthctl remote exec` (task C04).
//!
//! This is not a daemon. It never listens on a socket and never starts a
//! background process: it reads exactly one bounded HostOperation JSON
//! document from stdin, executes it against the local adapters through the
//! same dispatch as [`LocalTarget`], journals it under the target state root
//! (task C07), and writes exactly one bounded HostResult JSON document to
//! stdout. User input never enters a shell — the command line of this process
//! is fixed; every caller-supplied byte travels inside the typed payload.
//!
//! Exit contract: exit 0 with one HostResult on stdout means "the operation
//! was answered" (including `failed` outcomes). Any other exit writes nothing
//! to stdout and explains the protocol failure on stderr, so the control side
//! can treat non-zero exits strictly as transport errors.

use std::io::Read as _;

use anyhow::{Context, bail};

use super::{
    LocalTarget, TargetJournal, target_state_root,
    wire::{RejectionCode, encode_host_result, parse_host_operation},
};

/// CLI entry point: wire real stdin/stdout into [`serve`]. The state root is
/// the formalized [`super::target_state_root`] (task F01).
pub(crate) fn run_stdio() -> anyhow::Result<()> {
    let raw = read_bounded_stdin()?;
    let mut stdout = std::io::stdout().lock();
    serve(&raw, &mut stdout, &target_state_root()?)
}

/// Answer exactly one HostOperation from `input` with one HostResult on
/// `output`. Split out from real stdio so tests can drive the full protocol
/// in memory.
pub(crate) fn serve(
    input: &[u8],
    output: &mut impl std::io::Write,
    state_root: &std::path::Path,
) -> anyhow::Result<()> {
    if input.len() > super::wire::MAX_HOST_OPERATION_BYTES {
        bail!(
            "{}: stdin exceeds the {}-byte HostOperation limit",
            RejectionCode::OperationOversize.as_str(),
            super::wire::MAX_HOST_OPERATION_BYTES
        );
    }
    // Typed parse: closed kinds, deny_unknown_fields at both nesting levels,
    // schema discriminator, UUIDv7 id, per-kind payload validation.
    let operation =
        parse_host_operation(input).map_err(|rejection| anyhow::anyhow!("{rejection}"))?;

    let journal = TargetJournal::open(state_root)?;
    let target = LocalTarget::with_state_root(state_root);
    let result = target.execute_journaled(&operation, &journal)?;

    output.write_all(&encode_host_result(&result)?)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn read_bounded_stdin() -> anyhow::Result<Vec<u8>> {
    let stdin = std::io::stdin();
    let mut buffer = Vec::new();
    (&stdin)
        .take((super::wire::MAX_HOST_OPERATION_BYTES as u64) + 1)
        .read_to_end(&mut buffer)
        .context("failed to read the HostOperation from stdin")?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::PrivateTempDir;
    use crate::target::wire::{MAX_HOST_OPERATION_BYTES, OPERATION_ID_CONFLICT, parse_host_result};
    use uuid::Uuid;

    fn temp_state() -> anyhow::Result<(PrivateTempDir, std::path::PathBuf)> {
        let temp = PrivateTempDir::new("nazauthctl-remote-exec-test")?;
        let root = temp.path().join("state");
        Ok((temp, root))
    }

    fn ping_input(nonce: &str) -> Vec<u8> {
        serde_json::to_vec(&crate::target::HostOperation::ping(
            Uuid::now_v7().to_string(),
            nonce,
        ))
        .unwrap()
    }

    #[test]
    fn serves_exactly_one_json_line_per_operation() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;
        let mut output = Vec::new();
        serve(&ping_input("once"), &mut output, &root)?;

        let text = String::from_utf8(output)?;
        assert_eq!(text.lines().count(), 1, "{text}");
        let result = parse_host_result(text.trim_end().as_bytes())?;
        match result.outcome {
            crate::target::HostOutcome::Completed { .. } => {}
            _ => panic!("expected a completed answer"),
        }
        Ok(())
    }

    #[test]
    fn oversize_and_unparsable_inputs_fail_without_stdout() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;
        let mut output = Vec::new();

        let oversized = vec![b'a'; MAX_HOST_OPERATION_BYTES + 1];
        let error = serve(&oversized, &mut output, &root).expect_err("oversize");
        assert!(
            error.to_string().contains("HOST_OPERATION_OVERSIZE"),
            "{error}"
        );
        assert!(output.is_empty(), "no stdout on protocol failure");

        let error = serve(b"{not json", &mut output, &root).expect_err("malformed");
        assert!(
            error.to_string().contains("HOST_OPERATION_MALFORMED"),
            "{error}"
        );
        assert!(output.is_empty());

        let unknown = format!(
            r#"{{"schema":1,"operation_id":"{}","operation":{{"kind":"teleport","x":1}}}}"#,
            Uuid::now_v7()
        );
        let error = serve(unknown.as_bytes(), &mut output, &root).expect_err("unknown kind");
        assert!(
            error.to_string().contains("HOST_OPERATION_KIND_UNKNOWN"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn replays_answer_identically_through_the_journal() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;
        let input = ping_input("retry");
        let mut first = Vec::new();
        serve(&input, &mut first, &root)?;
        let mut second = Vec::new();
        serve(&input, &mut second, &root)?;
        assert_eq!(first, second, "the stored result is replayed byte-for-byte");

        // A different payload reusing the id is answered with the stable
        // conflict code instead of executing again.
        let mut operation: crate::target::HostOperation = serde_json::from_slice(&input)?;
        operation.operation = crate::target::wire::HostOperationBody::Ping {
            nonce: "tampered".to_owned(),
        };
        let mut output = Vec::new();
        serve(&serde_json::to_vec(&operation)?, &mut output, &root)?;
        let result = parse_host_result(&output)?;
        match result.outcome {
            crate::target::HostOutcome::Failed { code, .. } => {
                assert_eq!(code, OPERATION_ID_CONFLICT);
            }
            _ => panic!("expected the conflict outcome"),
        }
        Ok(())
    }

    #[test]
    fn hello_answers_with_the_local_helper_identity() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;
        let input = serde_json::to_vec(&crate::target::HostOperation::hello(
            Uuid::now_v7().to_string(),
        ))?;
        let mut output = Vec::new();
        serve(&input, &mut output, &root)?;
        let result = parse_host_result(&output)?;
        let crate::target::HostOutcome::Completed {
            body: crate::target::HostCompletionBody::Hello { hello },
        } = result.outcome
        else {
            panic!("expected a hello completion");
        };
        crate::target::verify_remote_hello(&hello).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    // ---------- F01/F04 end-to-end over the remote exec protocol ----------

    use crate::target::deployment_state::{
        ArtifactRefs, CONFIG_REVISION_MISMATCH, DEPLOYMENT_UNKNOWN, Resource, ResourceOwnership,
        ResourceScope, RuntimeSurface, StateMutationPayload,
    };
    use crate::target::{HostCompletionBody as Body, HostOperation};

    fn bootstrap_input() -> anyhow::Result<Vec<u8>> {
        let operation = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            None,
            StateMutationPayload::Bootstrap {
                issuer: "https://auth.example.com".to_owned(),
                runtime: RuntimeSurface::new("podman", "nazoauth-main")?,
                artifact: Some(ArtifactRefs {
                    current: Some("sha256:abcdef0123456789".to_owned()),
                    previous: None,
                }),
                config_reference: "/etc/nazauth/config.toml".to_owned(),
                config_schema: "nazauth-config-v1".to_owned(),
                resources: vec![
                    Resource::new(
                        "app-container",
                        "container",
                        "nazoauth-main",
                        ResourceOwnership::Managed,
                        ResourceScope::Deployment,
                    )?,
                    Resource::new(
                        "shared-db",
                        "postgres",
                        "pg-main.example.internal:5432",
                        ResourceOwnership::External,
                        ResourceScope::Shared,
                    )?,
                ],
                install: None,
            },
        );
        Ok(serde_json::to_vec(&operation)?)
    }

    fn apply_config_input(expected_revision: u64) -> anyhow::Result<Vec<u8>> {
        let operation = HostOperation::state_mutate(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
            Some(expected_revision),
            StateMutationPayload::ApplyConfig {
                reference: "/etc/nazauth/config-v2.toml".to_owned(),
                schema: "nazauth-config-v2".to_owned(),
            },
        );
        Ok(serde_json::to_vec(&operation)?)
    }

    fn inspect_input() -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&HostOperation::state_inspect(
            Uuid::now_v7().to_string(),
            "deploy-alpha",
        ))?)
    }

    fn answered(input: &[u8], root: &std::path::Path) -> anyhow::Result<crate::target::HostResult> {
        let mut output = Vec::new();
        serve(input, &mut output, root)?;
        parse_host_result(&output).map_err(|rejection| anyhow::anyhow!("{rejection}"))
    }

    #[test]
    fn state_kinds_flow_end_to_end_through_the_remote_exec_contract() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;

        // Bootstrap creates the target-side authority document.
        let bootstrapped = answered(&bootstrap_input()?, &root)?;
        let crate::target::HostOutcome::Completed {
            body: Body::StateMutateApplied { revision },
        } = bootstrapped.outcome
        else {
            panic!("expected a bootstrap completion: {bootstrapped:?}");
        };
        assert_eq!(revision, 1);

        // A stale CAS expectation is refused without last-write-wins.
        let stale = answered(&apply_config_input(99)?, &root)?;
        let crate::target::HostOutcome::Failed { code, .. } = stale.outcome else {
            panic!("expected the CAS failure: {stale:?}");
        };
        assert_eq!(code, CONFIG_REVISION_MISMATCH);

        // The matching expectation applies and bumps exactly one revision.
        let applied = answered(&apply_config_input(1)?, &root)?;
        let crate::target::HostOutcome::Completed {
            body: Body::StateMutateApplied { revision },
        } = applied.outcome
        else {
            panic!("expected an applied completion: {applied:?}");
        };
        assert_eq!(revision, 2);

        // Inspection reports the live document through the same contract.
        let inspected = answered(&inspect_input()?, &root)?;
        let crate::target::HostOutcome::Completed {
            body: Body::StateInspect { inspection },
        } = inspected.outcome
        else {
            panic!("expected an inspection: {inspected:?}");
        };
        assert_eq!(inspection.deployment_id, "deploy-alpha");
        assert_eq!(inspection.revision, 2);
        assert_eq!(inspection.config_reference, "/etc/nazauth/config-v2.toml");
        assert_eq!(inspection.resources.len(), 2);
        let external = inspection
            .resources
            .iter()
            .find(|resource| resource.resource_id == "shared-db")
            .expect("declared resource");
        assert_eq!(external.ownership, ResourceOwnership::External);

        // Unknown deployments answer with the stable code.
        let missing = serde_json::to_vec(&HostOperation::state_inspect(
            Uuid::now_v7().to_string(),
            "deploy-ghost",
        ))?;
        let failed = answered(&missing, &root)?;
        let crate::target::HostOutcome::Failed { code, .. } = failed.outcome else {
            panic!("expected a failed inspection");
        };
        assert_eq!(code, DEPLOYMENT_UNKNOWN);
        Ok(())
    }

    #[test]
    fn state_list_sweeps_deployments_over_the_remote_exec_contract() -> anyhow::Result<()> {
        let (_temp, root) = temp_state()?;

        // A fresh target answers with an empty listing.
        let empty = answered(
            &serde_json::to_vec(&HostOperation::state_list(Uuid::now_v7().to_string()))?,
            &root,
        )?;
        let crate::target::HostOutcome::Completed {
            body: Body::StateListed { deployments },
        } = empty.outcome
        else {
            panic!("expected a listing completion: {empty:?}");
        };
        assert!(deployments.is_empty(), "{deployments:?}");

        // After one bootstrap the sweep reports exactly that deployment with
        // its authoritative facts.
        serve(&bootstrap_input()?, &mut Vec::new(), &root)?;
        let swept = answered(
            &serde_json::to_vec(&HostOperation::state_list(Uuid::now_v7().to_string()))?,
            &root,
        )?;
        let crate::target::HostOutcome::Completed {
            body: Body::StateListed { deployments },
        } = swept.outcome
        else {
            panic!("expected a listing completion: {swept:?}");
        };
        assert_eq!(deployments.len(), 1);
        assert_eq!(deployments[0].deployment_id, "deploy-alpha");
        assert_eq!(deployments[0].issuer, "https://auth.example.com");
        assert_eq!(deployments[0].runtime.kind, "podman");
        assert_eq!(deployments[0].resources.len(), 2);

        // A bound sweep is rejected at admission: the helper exits nonzero
        // without writing stdout, exactly like any other protocol failure.
        let mut bound = HostOperation::state_list(Uuid::now_v7().to_string());
        bound.deployment_id = Some("deploy-alpha".to_owned());
        let mut output = Vec::new();
        let error = serve(&serde_json::to_vec(&bound)?, &mut output, &root)
            .expect_err("bound sweep refused");
        assert!(
            error.to_string().contains("state-list must not carry"),
            "{error}"
        );
        assert!(output.is_empty(), "no stdout on admission failure");
        Ok(())
    }

    #[test]
    fn interrupted_state_mutations_resume_without_double_applying() -> anyhow::Result<()> {
        use crate::target::journal::{JournalLine, JournalStatus, TargetJournal};
        use crate::target::wire::{HOST_ERR_OPERATION_INVALID, canonical_operation_hash};
        use std::io::Write as _;

        let (_temp, root) = temp_state()?;
        serve(&bootstrap_input()?, &mut Vec::new(), &root)?;

        // Simulate a crash after acceptance but before execution: the
        // pending line exists, no terminal result does.
        let operation: HostOperation = serde_json::from_slice(&apply_config_input(1)?)?;
        let journal = TargetJournal::open(&root)?;
        let pending = serde_json::to_string(&JournalLine {
            schema: crate::target::journal::JOURNAL_SCHEMA,
            operation_id: operation.operation_id.clone(),
            operation_hash: canonical_operation_hash(&operation)?,
            action: "state-mutate".to_owned(),
            recorded_at: chrono::Utc::now(),
            status: JournalStatus::Pending,
            result: None,
        })?;
        let journal_path = root
            .join("deployments")
            .join("deploy-alpha")
            .join("operations.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&journal_path)?;
        file.write_all(pending.as_bytes())?;
        file.write_all(b"\n")?;
        drop(file);
        drop(journal);

        let resumed = answered(&serde_json::to_vec(&operation)?, &root)?;
        match resumed.outcome {
            crate::target::HostOutcome::Completed {
                body: Body::StateMutateApplied { revision },
            } => assert_eq!(revision, 2, "resume applies exactly once"),
            other => panic!("expected the resumed apply to complete: {other:?}"),
        }

        // The journal now carries bootstrap(pending+terminal), the crashed
        // pending line, the resume pending line, and the terminal result.
        let raw = std::fs::read_to_string(
            root.join("deployments")
                .join("deploy-alpha")
                .join("operations.jsonl"),
        )?;
        assert_eq!(raw.lines().count(), 5, "{raw}");

        // And a replay of the same bytes returns the stored terminal result.
        let replayed = answered(&serde_json::to_vec(&operation)?, &root)?;
        assert_eq!(replayed.outcome, resumed.outcome);

        // Sanity: bootstrap over existing state is refused even via resume.
        let clash = answered(&bootstrap_input()?, &root)?;
        let crate::target::HostOutcome::Failed { code, detail } = clash.outcome else {
            panic!("expected DEPLOYMENT_EXISTS");
        };
        assert_ne!(code, HOST_ERR_OPERATION_INVALID);
        assert!(detail.contains("never overwrites"), "{detail}");
        Ok(())
    }
}
