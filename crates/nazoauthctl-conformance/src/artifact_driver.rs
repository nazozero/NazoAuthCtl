use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{ArtifactError, OIDF_DRIVER_ENGINE_PROTOCOL};

pub const OIDF_DRIVER_SCHEMA_VERSION: u32 = 1;
pub const MAX_ARTIFACT_DRIVER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverProgram {
    pub schema: u32,
    pub engine_protocol: u32,
    pub handlers: Vec<OidfDriverHandler>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverHandler {
    pub id: String,
    pub automation: OidfDriverAutomation,
    pub lane: OidfDriverLane,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum OidfDriverAutomation {
    None,
    Browser,
    Openid4vci,
    Openid4vp { haip: bool },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OidfDriverLane {
    Parallel,
    Ciba,
}

pub(crate) fn validate_oidf_driver(
    bytes: &[u8],
    signed_schema: u32,
    signed_size: u64,
    signed_sha256: &str,
    engine_protocol: u32,
) -> Result<OidfDriverProgram, ArtifactError> {
    if bytes.is_empty()
        || bytes.len() > MAX_ARTIFACT_DRIVER_BYTES
        || bytes.len() as u64 != signed_size
        || digest(bytes) != signed_sha256
    {
        return Err(ArtifactError::DriverPolicy(
            "driver bytes do not match the signed identity",
        ));
    }
    let program: OidfDriverProgram =
        serde_json::from_slice(bytes).map_err(|_| ArtifactError::MalformedDriver)?;
    if program.schema != OIDF_DRIVER_SCHEMA_VERSION
        || program.schema != signed_schema
        || program.engine_protocol != OIDF_DRIVER_ENGINE_PROTOCOL
        || program.engine_protocol != engine_protocol
        || program.handlers.is_empty()
        || program.handlers.len() > 128
    {
        return Err(ArtifactError::DriverPolicy(
            "driver header is outside controller policy",
        ));
    }
    let mut handler_ids = BTreeSet::new();
    for handler in &program.handlers {
        crate::artifact::validate_identifier(&handler.id, 128)
            .map_err(ArtifactError::DriverPolicy)?;
        if !handler_ids.insert(handler.id.as_str()) {
            return Err(ArtifactError::DriverPolicy(
                "driver handler identifiers must be unique",
            ));
        }
        if handler.lane == OidfDriverLane::Ciba
            && handler.automation != OidfDriverAutomation::Browser
        {
            return Err(ArtifactError::DriverPolicy(
                "CIBA lanes require real browser approval automation",
            ));
        }
    }
    Ok(program)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_is_declarative_bounded_and_requires_browser_for_ciba() {
        let program = OidfDriverProgram {
            schema: OIDF_DRIVER_SCHEMA_VERSION,
            engine_protocol: OIDF_DRIVER_ENGINE_PROTOCOL,
            handlers: vec![OidfDriverHandler {
                id: "oidc-browser".to_owned(),
                automation: OidfDriverAutomation::Browser,
                lane: OidfDriverLane::Ciba,
            }],
        };
        let bytes = serde_json::to_vec(&program).expect("driver");
        assert_eq!(
            validate_oidf_driver(
                &bytes,
                OIDF_DRIVER_SCHEMA_VERSION,
                bytes.len() as u64,
                &digest(&bytes),
                OIDF_DRIVER_ENGINE_PROTOCOL,
            )
            .expect("valid driver"),
            program
        );

        let mut invalid = program;
        invalid.handlers[0].automation = OidfDriverAutomation::None;
        let bytes = serde_json::to_vec(&invalid).expect("driver");
        assert!(matches!(
            validate_oidf_driver(
                &bytes,
                OIDF_DRIVER_SCHEMA_VERSION,
                bytes.len() as u64,
                &digest(&bytes),
                OIDF_DRIVER_ENGINE_PROTOCOL,
            ),
            Err(ArtifactError::DriverPolicy(_))
        ));

        let unknown = br#"{"schema":1,"engine_protocol":1,"handlers":[],"command":"curl"}"#;
        assert!(matches!(
            validate_oidf_driver(
                unknown,
                OIDF_DRIVER_SCHEMA_VERSION,
                unknown.len() as u64,
                &digest(unknown),
                OIDF_DRIVER_ENGINE_PROTOCOL,
            ),
            Err(ArtifactError::MalformedDriver)
        ));
    }
}
