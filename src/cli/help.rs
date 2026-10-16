use super::types::HelpTopic;

pub(crate) fn help_topic(args: &[String], globals: &super::GlobalOptions) -> Option<HelpTopic> {
    let values = &args.get(1..)?[globals.consumed..];
    if !values
        .iter()
        .any(|value| matches!(value.as_str(), "-h" | "--help"))
    {
        return None;
    }
    let command = values.first().map(String::as_str);
    Some(match command {
        Some("host") => HelpTopic::Host,
        Some("instance") => HelpTopic::Instance,
        Some("controller") => HelpTopic::Controller,
        Some("install") => HelpTopic::Install,
        Some("update" | "rollback" | "uninstall" | "verify") => HelpTopic::Update,
        Some("tls") => HelpTopic::Tls,
        Some("self") => HelpTopic::SelfUpdate,
        Some("admin") => HelpTopic::Admin,
        Some("status" | "doctor" | "logs" | "operation") => HelpTopic::Read,
        Some("backup") => HelpTopic::Backup,
        Some("recover") => HelpTopic::Recover,
        Some("policy") => HelpTopic::Policy,
        Some("bind") => HelpTopic::Bind,
        Some("discover") => HelpTopic::Discover,
        Some("remote") => HelpTopic::Remote,
        _ => HelpTopic::TopLevel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_flag_used_as_a_global_value_does_not_request_help() {
        let args = ["nazoauthctl", "--instance", "--help", "status"].map(str::to_owned);
        assert_eq!(
            help_topic(
                &args,
                &super::super::parse_global_options(&args[1..]).unwrap()
            ),
            None
        );
        let args = ["nazoauthctl", "--instance", "--help", "status", "--help"].map(str::to_owned);
        assert_eq!(
            help_topic(
                &args,
                &super::super::parse_global_options(&args[1..]).unwrap()
            ),
            Some(HelpTopic::Read)
        );
    }
}
