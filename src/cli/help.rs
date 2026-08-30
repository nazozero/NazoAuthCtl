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
        Some("host") => HelpTopic::Host,
        Some("instance") => HelpTopic::Instance,
        Some("controller") => HelpTopic::Controller,
        Some("install") => HelpTopic::Install,
        Some("update" | "rollback" | "uninstall" | "verify") => HelpTopic::Update,
        Some("tls") => HelpTopic::Tls,
        Some("self") => HelpTopic::SelfUpdate,
        Some("admin") => HelpTopic::Admin,
        _ => HelpTopic::TopLevel,
    })
}
