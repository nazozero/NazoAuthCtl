use std::path::PathBuf;

use anyhow::{Context, bail};

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
