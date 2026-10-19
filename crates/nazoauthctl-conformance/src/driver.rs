use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidfDriverProgram {
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
