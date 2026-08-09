use std::path::PathBuf;

use anyhow::{Context, bail};

pub(super) fn parse_transaction_resume(values: Vec<String>) -> anyhow::Result<(bool, bool)> {
    let mut yes = false;
    let mut accept_migration_barrier = false;
    for value in values {
        match value.as_str() {
            "--yes" if !yes => yes = true,
            "--accept-migration-barrier" if !accept_migration_barrier => {
                accept_migration_barrier = true;
            }
            "--yes" => bail!("transaction resume --yes may be specified only once"),
            "--accept-migration-barrier" => {
                bail!("transaction resume --accept-migration-barrier may be specified only once")
            }
            other => bail!("unknown transaction resume option {other}"),
        }
    }
    Ok((yes, accept_migration_barrier))
}

pub(super) fn parse_transaction_evidence(values: Vec<String>) -> anyhow::Result<(PathBuf, bool)> {
    let mut file = None;
    let mut yes = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--yes" => {
                if yes {
                    bail!("transaction evidence --yes may be specified only once");
                }
                yes = true;
                index += 1;
            }
            "--file" => {
                let value = values
                    .get(index + 1)
                    .context("transaction evidence --file requires PATH")?;
                if file.replace(PathBuf::from(value)).is_some() {
                    bail!("transaction evidence --file may be specified only once");
                }
                index += 2;
            }
            other => bail!("unknown transaction evidence option {other}"),
        }
    }
    Ok((
        file.context("transaction evidence requires --file PATH")?,
        yes,
    ))
}
