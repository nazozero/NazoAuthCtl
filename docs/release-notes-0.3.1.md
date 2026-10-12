# NazoAuthCtl v0.3.1

Add `nazoauthctl version` and `V` to show the installed controller and registered
NazoAuth instance versions together. `-V`, `--version`, instance selection and
JSON output are supported. Missing instances and detection failures are reported
explicitly without hiding the controller version or triggering an update.

Improve interrupted OIDF cleanup, independent state inspection, backup transfer
and TLS recovery. Preserve released backup sentinel hashes and validate required
schema relations. New helpers reuse a bounded backup-transfer connection; helpers
older than 0.3.1 retain the established one-operation transport.

Keep WebDriver removed and NazoAuth independent of OIDF orchestration. Operator
protocol 3 and host wire protocol 11 remain unchanged. Shared protocol and crypto
sources are pinned to immutable revisions.

Fix a parallel Unix CI race by executing the SSH test double from an immutable
checked-in script, with independent data per test. Production SSH behavior and
password-interaction assertions are unchanged.

See [compatibility](compatibility.md) and [development verification](development.md).
