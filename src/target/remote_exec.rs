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
    LocalTarget, TargetJournal,
    wire::{RejectionCode, encode_host_result, parse_host_operation},
};

/// Interim target state root for the operation journal until F01 formalizes
/// DeploymentState storage. Target administrators may relocate it with
/// `NAZOAUTHCTL_TARGET_STATE_ROOT`; the journal path layout beneath the root
/// is owned by [`TargetJournal`] alone.
fn interim_target_state_root() -> anyhow::Result<std::path::PathBuf> {
    if let Some(root) = std::env::var_os("NAZOAUTHCTL_TARGET_STATE_ROOT") {
        return Ok(std::path::PathBuf::from(root));
    }
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData")
            .context("ProgramData is not set; cannot locate the target state root")?;
        Ok(std::path::PathBuf::from(program_data)
            .join("nazoauthctl")
            .join("target-state"))
    }
    #[cfg(not(windows))]
    {
        Ok(std::path::PathBuf::from(
            "/var/lib/nazoauthctl/target-state",
        ))
    }
}

/// CLI entry point: wire real stdin/stdout into [`serve`].
pub(crate) fn run_stdio() -> anyhow::Result<()> {
    let raw = read_bounded_stdin()?;
    let mut stdout = std::io::stdout().lock();
    serve(&raw, &mut stdout, &interim_target_state_root()?)
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
    let result = LocalTarget::new().execute_journaled(&operation, &journal)?;

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
    use crate::target::wire::{
        HOST_ERR_OPERATION_CONFLICT, MAX_HOST_OPERATION_BYTES, parse_host_result,
    };
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
                assert_eq!(code, HOST_ERR_OPERATION_CONFLICT);
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
}
