use anyhow::{Context, bail};

use super::super::legacy_types::UpdateOptions;
use super::common::validate_version;

pub(super) fn parse_update_options(values: Vec<String>) -> anyhow::Result<UpdateOptions> {
    let mut version = None;
    let mut plan = false;
    let mut yes = false;
    let mut accept_migration_barrier = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--plan" => {
                if plan {
                    bail!("--plan may be specified only once");
                }
                plan = true;
                index += 1;
            }
            "--yes" => {
                if yes {
                    bail!("--yes may be specified only once");
                }
                yes = true;
                index += 1;
            }
            "--accept-migration-barrier" => {
                if accept_migration_barrier {
                    bail!("--accept-migration-barrier may be specified only once");
                }
                accept_migration_barrier = true;
                index += 1;
            }
            "--to" => {
                if version.is_some() {
                    bail!("--to may be specified only once");
                }
                let value = values.get(index + 1).context("--to requires VERSION")?;
                validate_version(value)?;
                version = Some(value.clone());
                index += 2;
            }
            other => bail!("unknown update option {other}"),
        }
    }
    if plan && (yes || accept_migration_barrier) {
        bail!("update --plan cannot be combined with mutation authorization flags");
    }
    Ok(UpdateOptions {
        version,
        plan,
        yes,
        accept_migration_barrier,
    })
}
