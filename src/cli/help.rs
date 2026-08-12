use super::types::HelpTopic;

pub(crate) fn help_topic(args: &[String]) -> Option<HelpTopic> {
    let values = args.get(1..)?;
    let globals = super::parse_global_options(values).ok()?;
    if !values[globals.consumed..]
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        return None;
    }
    let command = values.get(globals.consumed).map(String::as_str);
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
