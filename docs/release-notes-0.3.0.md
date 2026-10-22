# NazoAuthCtl v0.3.0

Remove the local WebDriver/browser dependency from OIDF execution. The official
Suite owns browser interaction and HTML review evidence; controller HTTP drivers
complete authorization, CIBA, credential-offer and presentation flows. Fix the
second issuer-initiated offer, VP result completion and HAIP PAR handling.

Harden secret transport, PostgreSQL TLS preservation, subprocess and filesystem
boundaries, OCI ownership, persistent port reservations and recoverable Suite
cleanup. Backup validation supports the current server issuance schema while
retaining frozen historical persistence readers.

Operator protocol 3, release-manifest schema 7 and host wire protocol 11 remain
unchanged. The immutable protocol dependency remains pinned; matching product
version numbers do not replace compatibility verification.

See [security verification and remaining boundaries](security-cloud-20261011.md),
[compatibility](compatibility.md), and [OIDF evidence](oidf-no-webdriver-20261011.md).
The linked Suite records identify their tested revisions and original outcomes.
