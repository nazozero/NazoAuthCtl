use std::path::PathBuf;

use anyhow::{Context, bail};

use super::super::types::{ConformanceCommand, ConformanceLeaseCommand};
use super::common::{
    no_arguments, parse_candidate_target, parse_named_options_for,
    parse_named_options_for_with_optional, parse_yes, take_yes,
};

pub(super) fn parse_conformance(mut values: Vec<String>) -> anyhow::Result<ConformanceCommand> {
    let lease_index = values
        .iter()
        .position(|value| value == "lease")
        .context("conformance requires the lease resource")?;
    let candidate_values = values.drain(..lease_index).collect::<Vec<_>>();
    let candidate = parse_candidate_target(candidate_values)?;
    if values.first().map(String::as_str) != Some("lease") {
        bail!("conformance requires the lease resource");
    }
    values.remove(0);
    let operation = values
        .first()
        .cloned()
        .context("conformance lease requires an operation")?;
    values.remove(0);
    let lease = match operation.as_str() {
        "list" => {
            no_arguments(&values, "conformance lease list")?;
            ConformanceLeaseCommand::List
        }
        "create" => {
            let (values, yes) = take_yes(values)?;
            let values = parse_named_options_for_with_optional(
                values,
                &["--profile", "--material", "--ttl-seconds"],
                &[
                    "--dynamic-registration-token-file",
                    "--ciba-automated-decision-token-file",
                ],
                "conformance lease create",
            )?;
            let ttl_seconds = values["--ttl-seconds"]
                .parse::<u64>()
                .context("--ttl-seconds must be an integer")?;
            if !(60..=86_400).contains(&ttl_seconds) {
                bail!("--ttl-seconds must be between 60 and 86400");
            }
            ConformanceLeaseCommand::Create {
                profile: values["--profile"].clone(),
                material: PathBuf::from(&values["--material"]),
                dynamic_registration_token_file: values
                    .get("--dynamic-registration-token-file")
                    .map(PathBuf::from),
                ciba_automated_decision_token_file: values
                    .get("--ciba-automated-decision-token-file")
                    .map(PathBuf::from),
                ttl_seconds,
                yes,
            }
        }
        "revoke" => {
            let (values, yes) = take_yes(values)?;
            let values =
                parse_named_options_for(values, &["--lease-id"], "conformance lease revoke")?;
            let lease_id = values["--lease-id"].clone();
            uuid::Uuid::parse_str(&lease_id).context("--lease-id must be a UUID")?;
            ConformanceLeaseCommand::Revoke { lease_id, yes }
        }
        "cleanup" => {
            let yes = parse_yes(values, "conformance lease cleanup")?;
            ConformanceLeaseCommand::Cleanup { yes }
        }
        _ => bail!("unsupported conformance lease operation or arguments"),
    };
    Ok(ConformanceCommand { lease, candidate })
}
