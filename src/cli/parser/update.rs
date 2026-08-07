use anyhow::{Context, bail};

use super::super::types::UpdateOptions;
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
                plan = true;
                index += 1;
            }
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--accept-migration-barrier" => {
                accept_migration_barrier = true;
                index += 1;
            }
            "--to" => {
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
