mod adoption;
mod backup;
mod cli;
mod conformance;
mod coordination;
mod deployment;
mod discovery;
mod governance;
mod install;
mod lifecycle;
mod model;
mod operator;
mod release;
mod runtime;
mod runtime_backend;
mod secret_provider;

pub(crate) use nazoauthctl_runtime::filesystem;
pub(crate) use nazoauthctl_runtime::process;

pub use conformance::{ConformanceMatrix, ConformanceOnboarding, ConformanceSession};

#[cfg(all(test, unix))]
#[path = "../tests/unit/support.rs"]
mod test_support;

pub fn main_entry() {
    let args = match std::env::args_os()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command-line arguments must be valid UTF-8")
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(error) => {
            eprintln!("nazoauthctl: argument parsing failed: {error}");
            std::process::exit(2);
        }
    };
    if let Some(topic) = cli::help_topic(&args) {
        print_help(topic);
        return;
    }
    let cli = match cli::Cli::parse(args) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print_help(cli::HelpTopic::TopLevel);
            return;
        }
        Err(error) => {
            eprintln!("nazoauthctl: {error:#}");
            std::process::exit(2);
        }
    };
    let result = if controller::uses_legacy_lock(&cli.command) {
        controller::acquire_lock(&cli.command).and_then(|_lock| controller::run(cli))
    } else {
        controller::run(cli)
    };
    if let Err(error) = result {
        eprintln!("nazoauthctl: {error:#}");
        std::process::exit(1);
    }
}

fn print_help(topic: cli::HelpTopic) {
    println!("{}", help_text(topic));
}

fn help_text(topic: cli::HelpTopic) -> &'static str {
    match topic {
        cli::HelpTopic::TopLevel => {
            "nazoauthctl — install and safely operate NazoAuth

Usage:
  nazoauthctl [--deployment ID_OR_ALIAS] [--config PATH] <command> [options]

Start here:
  nazoauthctl discover
  nazoauthctl adopt --target BACKEND:OBJECT [--lifecycle PATH] --plan
  nazoauthctl adopt --target BACKEND:OBJECT [--lifecycle PATH] --yes
  nazoauthctl deployments list
  nazoauthctl --deployment ID transaction show
  nazoauthctl --deployment ID transaction evidence --file PATH --yes
  nazoauthctl --deployment ID transaction resume --yes [--accept-migration-barrier]
  nazoauthctl --deployment ID permissions set --capability runtime=delegated --yes
  nazoauthctl --deployment ID relinquish --capability runtime --yes
  nazoauthctl --deployment ID reconcile
  nazoauthctl install --public-url https://auth.example
  nazoauthctl [--config PATH] bootstrap-admin
  nazoauthctl [--config PATH] status
  nazoauthctl [--config PATH] doctor
  nazoauthctl [--config PATH] update --plan
  nazoauthctl [--config PATH] update --yes
  nazoauthctl [--config PATH] conformance run
  nazoauthctl conformance artifact verify --trust-policy PATH --manifest PATH --matrix PATH
  nazoauthctl [--deployment ID] development activate --artifact IMAGE_OR_BINARY --yes

Commands:
  discover      Read-only local Podman, Docker, systemd and process discovery
  adopt         Verify and transactionally register an explicitly selected target
  deployments   List registered deployment control domains
  transaction   Inspect, provide evidence to, or resume a deployment-bound transaction
  permissions   Transactionally change explicitly selected capability grants
  relinquish    Return capabilities to external ownership without deleting resources
  reconcile     Report external drift and fail closed on managed drift
  install       Fresh Podman, Docker, or host installation
  bootstrap-admin  Securely create the first administrator
  status        Machine-readable deployment and identity state
  doctor        Read-only health and security diagnostics
  check         Resolve and verify a candidate Release
  update        Plan or perform a signed transactional update
  development   Explicitly activate an immutable local development artifact
  rollback      Roll back the application artifact within the declared schema boundary
  recover       Restore the declared database backup and previous artifact
  recover-update    Explicitly resume or unwind an interrupted update
  recover-identity  Explicitly finish an interrupted identity transition
  migrate       Run the signed migration operation
  keys          List, validate, export OpenID4VC trust, generate, or register signing keys
  conformance   Verify OIDF artifacts, run official tests, or manage time-bounded leases
  audit         Show or verify the management audit chain
  identity      Rotate controller and audit identities
  break-glass   Recover after controller-key loss or suspected theft
  self          Independently check, update, or roll back nazoauthctl

Run `nazoauthctl <command> --help` for exact options."
        }
        cli::HelpTopic::Install => {
            "Usage:
  nazoauthctl [--config PATH] install [options]

Options:
  --runtime auto|podman|docker|host   Default: auto (Podman, then Docker)
  --public-url URL                    Public issuer origin; default is local trial mode
  --profile baseline|standards-full   Default: baseline
  --profile-material PATH             Required only for standards-full
  --trusted-proxy-cidr HOST/32|HOST/128
                                      Required only for standards-full; one explicit proxy host
  --data-root PATH                    Default: /var/lib/nazoauth
  --control-root PATH                 Default: /var/lib/nazoauthctl
  --recovery-root PATH                Default: /var/lib/nazoauth-recovery; must be a separate mount
                                      and owns durable backups plus break-glass material
  --port PORT                         Default: 8000
  --network-subnet CIDR               Optional fixed container subnet; requires --runtime-ip
  --runtime-ip ADDRESS                Optional fixed application IP; requires --network-subnet
  --to VERSION                        Immutable vSemVer Release; default: latest
  --external-dependencies             Use operator-owned PostgreSQL and Valkey
  --secrets-stdin                     Read the three dependency URLs as strict JSON from stdin
  --secret-fd FD                      Read the same JSON from an already-open FD (Linux)
  --profile-secrets-stdin             Read standards-full profile bearer secrets as strict JSON from stdin
  --profile-secret-fd FD              Read the same profile JSON from an already-open FD (Linux)

With managed dependencies and standards-full profile, identities and service-owned
secrets are generated automatically and persisted in the installation secret store.
Profile secret input is optional and is intended only for importing an existing
secret during a controlled recovery or migration.
External JSON keys: database_url, migration_database_url, valkey_url.
Profile JSON keys: dynamic_registration_initial_access_token,
ciba_automated_decision_token, openid4vci_management_token,
openid4vp_management_token. Profile secret input is accepted only for standards-full.
The two stdin modes are mutually exclusive; use separate inherited FDs when both inputs are needed.
Secret values are rejected in argv and ordinary environment variables."
        }
        cli::HelpTopic::BootstrapAdmin => {
            "Usage:
  nazoauthctl [--config PATH] bootstrap-admin [--yes]
  nazoauthctl [--config PATH] bootstrap-admin --credentials-stdin --yes

Interactive mode prompts for the administrator email and reads the password without
echo. Non-interactive mode accepts only strict JSON on stdin with keys `email` and
`password`. The private one-time bootstrap token is read from the exact managed
runtime-owned mount and sent only in the HTTPS request body; it never enters argv, environment,
configuration, logs, audit records, or command output."
        }
        cli::HelpTopic::Update => {
            "Usage:
  nazoauthctl [--config PATH] check [--to VERSION]
  nazoauthctl [--config PATH] update --plan [--to VERSION]
  nazoauthctl [--config PATH] update --yes [--to VERSION] [--accept-migration-barrier]
  nazoauthctl [--config PATH] rollback --yes
  nazoauthctl [--config PATH] recover --yes
  nazoauthctl [--config PATH] recover-update --yes
  nazoauthctl [--config PATH] recover-identity --yes
  nazoauthctl [--config PATH] migrate [candidate target options] --yes

`update --plan` is read-only and reports artifact rollback, schema-compatible
rollback, backup/PITR recovery, and any irreversible migration barrier separately.
`recover` restores a declared database backup; it is not update-journal recovery.
Interrupted update and identity transitions are changed only by their explicit
recovery commands. Other commands fail closed while either transition is pending.
An unreleased OCI candidate migration requires all four candidate target bindings
shown by `nazoauthctl conformance --help`; the active digest and embedded identity
must match exactly. `--yes` skips only the prompt; it never skips verification, backup, health, replay,
audit, or rollback protection."
        }
        cli::HelpTopic::Keys => {
            "Usage:
  nazoauthctl [--config PATH] keys list
  nazoauthctl [--config PATH] keys validate
  nazoauthctl [--config PATH] keys export-openid4vc-trust --output ABSOLUTE_PATH
  nazoauthctl [--config PATH] keys generate-local --alg ALG --purposes CSV --yes
  nazoauthctl [--config PATH] keys register-external --kid KID --alg ALG \
    --key-ref REF --public-jwk PATH --yes

`keys export-openid4vc-trust` is available only for standards-full managed installs.
It verifies the managed atomic OpenID4VC bundle and writes only its CA:TRUE trust
anchor(s) to a regular absolute destination using an fsync+rename transition. It
never exports a leaf certificate or private key."
        }
        cli::HelpTopic::Conformance => {
            "Usage:
  nazoauthctl conformance artifact verify --trust-policy PATH \
    --manifest PATH --matrix PATH [--capability NAME ...]
  nazoauthctl [--deployment ID] [--config PATH] conformance run [--suite URL]
    [--token TOKEN|--token-file PATH|--token-stdin|--token-fd FD]
    [--webdriver URL] [--evidence-dir PATH] [--group ID] [--plan ID]
  nazoauthctl [--config PATH] conformance lease create --profile PROFILE \
    --material PUBLIC_MANIFEST \
    [--dynamic-registration-token-file PATH] \
    [--ciba-automated-decision-token-file PATH] \
    --ttl-seconds SECONDS --yes
  nazoauthctl [--config PATH] conformance lease list
  nazoauthctl [--config PATH] conformance lease revoke --lease-id UUID --yes
  nazoauthctl [--config PATH] conformance lease cleanup --yes

`conformance artifact verify` is read-only and deployment-independent. It emits a
verified identity only after checking the local trust policy, ES256 signature,
source, validity window, Suite identity, strict matrix schema, digest, size,
resource bounds, and every caller-supplied available capability. It does not
discover or grant target capabilities and does not execute the Suite.

`conformance run` validates the deployment, authenticates to the official Suite by
default, obtains the deployment Matrix, creates an atomic lease/onboarding bundle,
runs the Matrix-selected official plans, preserves official PASS/FAIL values, and
always attempts Suite and deployment cleanup. In a TTY, a missing API token is read
without echo and can be stored securely per Suite origin. `--token` is supported for
automation but is visible in argv and shell history. Progress is item-count based on
stderr; the final structured report is written to stdout without secrets.

For an unreleased OCI candidate, insert all four target bindings before `lease`:
  --candidate-release vX.Y.Z --candidate-revision GIT_SHA \
  --candidate-build-id BUILD_ID --candidate-oci-digest sha256:HEX

The lease stores only the SHA-256 digest of the public onboarding manifest. When
`--dynamic-registration-token-file` is supplied, nazoauthctl reads a bounded private
file and sends only its lowercase SHA-256 digest; the token plaintext and digest are
not printed or included in receipt summaries. The optional
`--ciba-automated-decision-token-file` follows the same rule and is only valid for
`oidc-fapi-ciba`. Private keys and plaintext client secrets remain with the
conformance runner. Expired or
revoked clients fail closed immediately; cleanup physically deletes their database
records and retains only the non-secret lease tombstone. Candidate mode is limited
to explicit migration and conformance operations and binds the operator task to the
exact active OCI digest and embedded identity; ordinary operations still require the
signed active Release.
TTL is 60 through 86400 seconds."
        }
        cli::HelpTopic::Audit => {
            "Usage:
  nazoauthctl [--config PATH] audit verify
  nazoauthctl [--config PATH] audit show [--request-id ID]"
        }
        cli::HelpTopic::Identity => {
            "Usage:
  nazoauthctl [--config PATH] identity rotate --yes

Rotation is a signed, journaled transition. The old identity cannot authorize new work
after the transition commits."
        }
        cli::HelpTopic::BreakGlass => {
            "Usage:
  nazoauthctl [--config PATH] break-glass recover-controller --reason lost|stolen --yes
  nazoauthctl [--config PATH] break-glass controller-availability
  nazoauthctl [--config PATH] break-glass rehearse-controller-loss --yes

This requires the separately stored recovery private key and rotates controller,
audit, and break-glass identities in one audited transition. `controller-availability`
reports only whether this file provider can currently use the active controller key;
it does not claim to prove a key was not copied. `rehearse-controller-loss` performs
the real recovery transition while forbidding controller signing reads after its
in-memory probe key is prepared; it proves simulated provider unavailability, not
physical key loss or non-copy."
        }
        cli::HelpTopic::Controller => {
            "Usage:
  nazoauthctl self check [--to VERSION]
  nazoauthctl self update [--to VERSION] --yes
  nazoauthctl self rollback --yes

Controller updates consume only signed NazoAuthCtl Release binaries and provenance.
They use a global controller lock, transaction, signed audit chain, and rollback slot;
they do not select or borrow keys or state from a NazoAuth deployment. A NazoAuth
server Release cannot replace the controller."
        }
    }
}

mod controller;

#[cfg(test)]
#[path = "../tests/unit/entrypoint.rs"]
mod tests;
