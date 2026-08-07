use super::types::HelpTopic;

pub(crate) fn help_topic(args: &[String]) -> Option<HelpTopic> {
    if !args
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        return None;
    }
    let mut values = args.iter().skip(1);
    let first = values.next()?;
    let command = if first == "--config" {
        values.next()?;
        values.next().map(String::as_str)
    } else {
        Some(first.as_str())
    };
    Some(match command {
        Some("install") => HelpTopic::Install,
        Some("bootstrap-admin") => HelpTopic::BootstrapAdmin,
        Some(
            "update" | "check" | "rollback" | "recover" | "recover-update" | "recover-identity"
            | "migrate",
        ) => HelpTopic::Update,
        Some("keys") => HelpTopic::Keys,
        Some("conformance") => HelpTopic::Conformance,
        Some("audit") => HelpTopic::Audit,
        Some("identity") => HelpTopic::Identity,
        Some("break-glass") => HelpTopic::BreakGlass,
        Some("self") => HelpTopic::Controller,
        _ => HelpTopic::TopLevel,
    })
}
