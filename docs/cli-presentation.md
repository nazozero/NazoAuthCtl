# CLI language and presentation

Human output follows the first nonempty `LC_ALL`, `LC_MESSAGES`, or `LANG` value.
A `zh` language prefix selects Chinese; other values use English. Commands, option
names, instance names, paths, URLs, protocol identifiers and error codes retain
their exact values. This also applies to noninteractive terminals and redirected
human output.

```sh
LANG=zh_CN.UTF-8 nazoauthctl status --all
LC_ALL=en_US.UTF-8 nazoauthctl update --help
nazoauthctl --json status --all
nazoauthctl --json self verify-state
```

Default output presents results, relevant fields, and next steps. Host, instance,
status and operation listings use tables that account for Chinese character width.
Update and rollback show the release version, health and configuration revision;
the update report derives rollback availability from the resulting target state.
Internal SHA digests are omitted from ordinary summaries. They remain part of
artifact verification and structured metadata.

Every command family has English and Chinese help. TLS and OIDF artifact commands
default to readable fields rather than a JSON dump. `--json`, placed before the
command, retains structured metadata without localized keys or values. Commands
whose result was previously only prose return a `schema: 1, message: ...` object
in JSON mode. Intermediate approval previews are omitted from JSON stdout,
so the terminal result remains one document. Help remains text. Core errors are JSON on stderr; OIDF errors retain
their existing JSON stdout contract. Raw service logs, external diagnostics and
protocol payloads keep their original text. Human error envelopes explain known
failure codes in Chinese and retain the original diagnostic separately.

Uninstall shows its concrete deletion plan before asking for confirmation, with
No selected initially. A pipe cannot answer this prompt: use `--yes` explicitly
for scripted deletion, or omit it to inspect the plan. Required interactive inputs
reject blank answers without restarting the operation. Recovery-secret delivery
requires an interactive input and output terminal; JSON and pipeline callers must
use `--output-secret-file`. No secret is printed before that check. The terminal
asks the operator to type `STORED` after saving the displayed secret.

Progress indicators are limited to interactive terminals. Redirected output has
no animation or terminal color escapes. OIDF retains its phase and result display;
its retained-record notices and configure/artifact paths use the same language.

The binary integration suite exercises all public command families in both
languages, locale precedence, parse failures, empty registries, JSON invariance,
and user names that resemble status tokens. It runs in isolated state directories
without contacting a service. Core tests separately cover lifecycle results,
resource retention, controller expiry and persistent-state compatibility.
