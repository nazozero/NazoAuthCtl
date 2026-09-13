# NazoAuthCtl v0.2.30

The CLI now applies the selected English or Chinese language across command help,
parser messages, lifecycle results, controller identity workflows, backups, TLS,
self-maintenance and OIDF artifact commands. Human failures include localized
explanations of known error codes and preserve original diagnostics separately.

Host, instance, status and operation lists use readable tables. Installation,
update and rollback summaries emphasize version, health and next steps instead
of internal digests. Update reports actual artifact rollback availability rather
than claiming the previous artifact is always preserved. TLS and OIDF metadata
use human-readable fields by default; `--json` retains machine metadata.

Uninstall presents its concrete deletion plan before terminal confirmation;
confirmation defaults to No. Required inputs reject blank answers. Recovery
secrets are never displayed before checking for interactive input and output;
pipes and JSON mode require `--output-secret-file`.

State formats, automatic compatibility migrations, artifact verification,
operation journals and wire protocols are unchanged. The v0.2.29 compatibility
and interrupted self-update recovery checks remain in effect.

See [CLI language and interaction](cli-presentation.md) for locale precedence,
JSON behavior, examples and the original-diagnostic boundary.
