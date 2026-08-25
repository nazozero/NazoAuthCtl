use std::path::PathBuf;

use anyhow::{Context, bail};

use super::super::legacy_types::KeysCommand;
use super::common::{parse_named_options, take_yes};

pub(super) fn parse_keys(values: Vec<String>) -> anyhow::Result<KeysCommand> {
    let mut values = values.into_iter();
    let command = values.next().context("keys requires an operation")?;
    let values = values.collect::<Vec<_>>();
    match command.as_str() {
        "list" if values.is_empty() => Ok(KeysCommand::List),
        "validate" if values.is_empty() => Ok(KeysCommand::Validate),
        "export-openid4vc-trust" => {
            let values = parse_named_options(values, &["--output"])?;
            Ok(KeysCommand::ExportOpenid4vcTrust {
                output: PathBuf::from(&values["--output"]),
            })
        }
        "generate-local" => {
            let (values, yes) = take_yes(values)?;
            let values = parse_named_options(values, &["--alg", "--purposes"])?;
            Ok(KeysCommand::GenerateLocal {
                alg: values["--alg"].clone(),
                purposes: values["--purposes"].split(',').map(str::to_owned).collect(),
                yes,
            })
        }
        "register-external" => {
            let (values, yes) = take_yes(values)?;
            let values =
                parse_named_options(values, &["--kid", "--alg", "--key-ref", "--public-jwk"])?;
            Ok(KeysCommand::RegisterExternal {
                kid: values["--kid"].clone(),
                alg: values["--alg"].clone(),
                key_ref: values["--key-ref"].clone(),
                public_jwk: PathBuf::from(&values["--public-jwk"]),
                yes,
            })
        }
        _ => bail!("unsupported keys operation or arguments"),
    }
}
