/// Human-facing CLI language. Empty locale variables do not override the next one.
pub fn chinese_output() -> bool {
    chinese_locale(
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
            .as_deref(),
    )
}

fn chinese_locale(locale: Option<&str>) -> bool {
    locale
        .unwrap_or_default()
        .split(['-', '_', '.', '@', ':'])
        .next()
        .unwrap_or_default()
        .eq_ignore_ascii_case("zh")
}

pub(crate) fn text(english: &'static str, chinese: &'static str) -> &'static str {
    if chinese_output() { chinese } else { english }
}

pub(crate) fn chinese_help(topic: super::HelpTopic) -> String {
    use super::HelpTopic;
    if matches!(topic, HelpTopic::TopLevel) {
        return "nazoauthctl — 管理本机和 SSH 主机上的 NazoAuth

用法：
  nazoauthctl [--instance SELECTOR] [--json] <command> [options]

常用命令：
  host        主机注册与检查（add/list/show/check/forget）
  instance    实例管理（list/show/register/rename/forget/relocate）
  controller  控制器密钥管理（list/add/rotate/revoke/recover）
  install     安装实例
  discover    发现目标主机上的部署
  bind        绑定实例的控制器密钥
  status      查看实例状态；--all 查看所有实例
  logs        查看已脱敏的最近日志（--limit 1-500）
  doctor      健康与安全诊断；支持 --all
  verify      检查公网 DNS、TLS 和 OIDC
  update      更新至经过验证的官方版本
  rollback    回滚至上一制品和配置
  operation   查看操作记录
  policy      设置更新前备份策略
  backup      创建、检查和恢复验证备份
  recover     从快照恢复数据和密钥
  oidf        OIDF 一致性测试
  uninstall   卸载实例所管理的资源

开始使用：
  nazoauthctl host add server-a --ssh prod-a --privilege sudo
  nazoauthctl install --help
  nazoauthctl admin create --instance production
  nazoauthctl bind --instance production --label operations
  nazoauthctl status
  nazoauthctl status --all

只有一个已注册实例时自动选择；多个实例时使用 --instance 指定。
绑定需要管理员登录并完成 MFA；控制器密钥在注册后 30 天到期。

维护：
  self check|update|rollback   检查、更新或回滚 nazoauthctl
  admin create                创建管理员
  tls certificate|acme ...     管理部署的 TLS 证书
  remote exec                 OpenSSH 使用的内部执行入口

恢复：
  nazoauthctl recover [SELECTOR] [--to VERSION] [--recovery-secret-file PATH]
  快照提供数据和密钥；所选发行版提供运行程序。省略 --to 时选择最新官方发行版。

运行 nazoauthctl <command> --help 查看具体选项。
status 默认显示汇总表；--json 输出完整结构化数据。"
            .to_owned();
    }
    // Command syntax stays authoritative in the existing help; only prose is translated.
    let syntax = crate::help_text(topic)
        .split("\n\n")
        .next()
        .unwrap_or_default();
    let description = match topic {
        HelpTopic::Host => {
            "host add 会先验证目标执行器再保存记录。host check 重新检查主机。host forget 仅删除本地注册记录，不卸载目标或撤销控制器。"
        }
        HelpTopic::Instance => {
            "instance register 接管目标主机上已发现的部署。instance forget 仅删除本地实例记录和密钥引用，不修改目标部署或撤销控制器。删除资源使用 uninstall；撤销控制器使用 controller revoke。"
        }
        HelpTopic::Controller => {
            "身份变更需要管理员重新完成 MFA 并批准本次操作。未提供批准令牌时会交互登录；--credentials-file 可提供仅当前用户可读的凭据文件。密钥注册后 30 天到期。revoke 只撤销指定控制器；recover 使用离线恢复密钥重新建立绑定，--rotate-secret 在重新批准后更换恢复密钥。"
        }
        HelpTopic::Install => {
            "使用指定的外部 PostgreSQL 和 Valkey，以及已有的数据库运行与生命周期角色。密码从文件读取，不写入日志。安装完成后，依次运行 admin create、bind 和 verify；安装不自动生成备份或执行公网验证。"
        }
        HelpTopic::Update => {
            "update 验证官方制品后迁移并更新；中断后重试会继续原操作。rollback 恢复制品和配置引用，数据恢复使用 recover。uninstall 未指定 --yes 时只显示删除计划；外部和共享资源不删除。"
        }
        HelpTopic::SelfUpdate => {
            "检查、更新或回滚控制器自身。更新仅使用已签名的 NazoAuthCtl 发行制品，不修改 NazoAuth 实例的密钥或状态。"
        }
        HelpTopic::Tls => {
            "通过外部文件提供器配置部署的 TLS 证书：验证证书链、域名与私钥，切换证书并重新加载提供器，再执行公网验证。recover 恢复之前或已提交的证书代次。ACME issue 需要 --agree-terms。"
        }
        HelpTopic::Admin => {
            "通过目标部署创建管理员。交互输入凭据，或通过 --credentials-stdin 提供严格 JSON；凭据不进入命令行参数、日志或控制器持久状态。每次调用记录为一个目标操作；已知失败后可重试。"
        }
        HelpTopic::TopLevel => unreachable!(),
    };
    format!(
        "用法：{}\n\n{description}",
        syntax.strip_prefix("Usage:").unwrap_or(syntax)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translated_help_preserves_command_syntax() {
        use crate::cli::HelpTopic;
        for topic in [
            HelpTopic::Host,
            HelpTopic::Instance,
            HelpTopic::Controller,
            HelpTopic::Install,
            HelpTopic::Update,
            HelpTopic::SelfUpdate,
            HelpTopic::Tls,
            HelpTopic::Admin,
        ] {
            let english = crate::help_text(topic);
            let syntax = english
                .split("\n\n")
                .next()
                .unwrap()
                .strip_prefix("Usage:")
                .unwrap();
            let chinese = chinese_help(topic);
            assert!(chinese.starts_with("用法：") && chinese.contains(syntax));
        }
    }

    #[test]
    fn locale_language_and_fallback() {
        for locale in ["zh_CN.UTF-8", "zh-TW", "ZH_hans", "zh"] {
            assert!(chinese_locale(Some(locale)));
        }
        for locale in [None, Some(""), Some("C.UTF-8"), Some("en_US.UTF-8")] {
            assert!(!chinese_locale(locale));
        }
    }
}
