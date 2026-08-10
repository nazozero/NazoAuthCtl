use super::*;

pub(crate) fn validate_retirement_probe_audit_evidence(value: &str) -> anyhow::Result<()> {
    let encoded = value
        .strip_prefix("evidence-v1.")
        .context("controller retirement probe evidence prefix is invalid")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("controller retirement probe evidence is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        bail!("controller retirement probe evidence is not canonical base64url")
    }
    let evidence: RetirementProbeAuditEvidence = serde_json::from_slice(&bytes)
        .context("controller retirement probe evidence is not strict JSON")?;
    match evidence {
        RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema,
            previous_controller_key_id,
            active_controller_key_id,
            probe_sha256,
            controller_verified_target,
            application_reported_embedded_identity,
        } => {
            if schema != 1
                || !safe_identity_component(&previous_controller_key_id)
                || !safe_identity_component(&active_controller_key_id)
                || !valid_sha256(&probe_sha256)
                || application_reported_embedded_identity.protocol
                    != nazo_operator_protocol::PROTOCOL_VERSION
                || application_reported_embedded_identity.release.is_empty()
                || application_reported_embedded_identity.revision.is_empty()
                || application_reported_embedded_identity.build_id.is_empty()
            {
                bail!("controller retirement probe evidence is invalid")
            }
            match controller_verified_target {
                RuntimeTargetClaim::OciImage {
                    image_ref,
                    image_digest,
                } if !image_ref.is_empty()
                    && image_digest
                        .strip_prefix("sha256:")
                        .is_some_and(valid_sha256) => {}
                RuntimeTargetClaim::HostBinary { path, sha256 }
                    if Path::new(&path).is_absolute() && valid_sha256(&sha256) => {}
                _ => bail!("controller retirement probe target evidence is invalid"),
            }
        }
        RetirementProbeAuditEvidence::NotIssued {
            schema,
            previous_controller_key_id,
            previous_controller_public_sha256,
            reason,
        } => {
            if schema != 1
                || !safe_identity_component(&previous_controller_key_id)
                || !valid_sha256(&previous_controller_public_sha256)
                || reason != "controller-private-unavailable"
            {
                bail!("controller retirement probe non-issuance evidence is invalid")
            }
        }
    }
    Ok(())
}

pub(crate) fn encode_retirement_probe_audit_evidence(
    evidence: &RetirementProbeAuditEvidence,
) -> anyhow::Result<String> {
    Ok(format!(
        "evidence-v1.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(evidence)?)
    ))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn verify_trust_transitions(config: &UpdateConfig) -> anyhow::Result<()> {
    let directory = config.operator.audit_directory.join("trust-transitions");
    if !is_real_directory_or_missing(&directory, "trust-transition directory")? {
        return Ok(());
    }
    let mut paths = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let mut expected_previous: Option<(String, String, String)> = None;
    for entry in paths {
        if !is_regular_non_symlink(&entry.path())?
            || entry.path().extension().and_then(|value| value.to_str()) != Some("jws")
        {
            bail!("trust transition directory contains an unexpected entry");
        }
        let compact = read_audit_text(&entry.path(), "trust transition")?;
        let header = protected_header(&compact)?;
        let key = if header.kid.starts_with("break-glass-") {
            trusted_break_glass_key(config, &header.kid)?
        } else {
            trusted_controller_key(config, &header.kid)?
        };
        let transition = verify_trust_transition(&compact, &header.kid, &key)?;
        if transition.deployment_id != config.operator.deployment_id
            || expected_previous
                .as_ref()
                .is_some_and(|(controller, audit, break_glass)| {
                    controller != &transition.previous_key_id
                        || audit != &transition.previous_audit_key_id
                        || break_glass != &transition.previous_break_glass_key_id
                })
        {
            bail!("controller trust transition chain is discontinuous");
        }
        let next = trusted_controller_key(config, &transition.next_key_id)?;
        if encode_hex(&Sha256::digest(next.to_bytes())) != transition.next_public_key_sha256 {
            bail!("controller trust transition public key digest mismatch");
        }
        let next_audit = trusted_audit_key(config, &transition.next_audit_key_id)?;
        if encode_hex(&Sha256::digest(next_audit.to_bytes()))
            != transition.next_audit_public_key_sha256
        {
            bail!("audit trust transition public key digest mismatch");
        }
        let next_break_glass =
            trusted_break_glass_key(config, &transition.next_break_glass_key_id)?;
        if encode_hex(&Sha256::digest(next_break_glass.to_bytes()))
            != transition.next_break_glass_public_key_sha256
        {
            bail!("break-glass trust transition public key digest mismatch");
        }
        match transition.authorization {
            TransitionAuthorization::Controller if header.kid != transition.previous_key_id => {
                bail!("normal controller rotation was not signed by the previous controller")
            }
            TransitionAuthorization::BreakGlass
                if header.kid != transition.previous_break_glass_key_id =>
            {
                bail!("break-glass recovery was not signed by the break-glass identity")
            }
            _ => {}
        }
        expected_previous = Some((
            transition.next_key_id,
            transition.next_audit_key_id,
            transition.next_break_glass_key_id,
        ));
    }
    if let Some((controller, audit, break_glass)) = expected_previous
        && (controller != config.operator.controller_key_id
            || audit != config.operator.audit_key_id
            || break_glass != config.operator.break_glass_key_id)
    {
        bail!("controller trust transition chain does not terminate at the active identity");
    }
    Ok(())
}
