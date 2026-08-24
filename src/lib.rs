mod adoption;
mod backup;
mod cli;
mod conformance;
mod coordination;
mod deployment;
mod discovery;
mod fleet;
mod governance;
mod install;
mod lifecycle;
mod model;
mod operator;
pub mod registry;
mod release;
mod runtime;
mod runtime_backend;
mod secret_provider;
pub mod target;
pub mod tenant_resources;
mod tls;

pub(crate) use nazoauthctl_runtime::filesystem;
pub(crate) use nazoauthctl_runtime::process;

pub use conformance::{
    ConformanceDeploymentEvidence, ConformanceRuntimeEvidence, ConformanceSession,
};

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
  nazoauthctl conformance artifact resolve --trust-policy PATH --manifest-url URL --cache-dir PATH
  nazoauthctl conformance artifact verify --trust-policy PATH --manifest PATH --matrix PATH
  nazoauthctl [--deployment ID] development activate --artifact IMAGE_OR_BINARY --yes
  nazoauthctl host add server-a --ssh prod-a --privilege sudo
  nazoauthctl host list|show|check|forget <alias>
  nazoauthctl instance list
  nazoauthctl instance show|rename|forget [--instance SELECTOR]
  nazoauthctl instance observe --host HOST --deployment-id ID --issuer URL --output PATH
  nazoauthctl instance register --from-discovery PATH
  nazoauthctl instance relocate [--instance SELECTOR] --to-host HOST

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
  host          Register and inspect managed hosts (add/list/show/check/forget)
  instance      Register and select NazoAuth instances (list/show/observe/register/rename/forget/relocate)
  conformance   Verify signed OIDF artifacts and run official tests through ordinary resources
  audit         Show or verify the management audit chain
  identity      Rotate controller and audit identities
  break-glass   Recover after controller-key loss or suspected theft
  self          Independently check, update, or roll back nazoauthctl
  remote        Internal stdio executor invoked over SSH on target hosts (no daemon)

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
  --candidate-image IMAGE             Explicitly use an already-present local OCI image; requires
                                      all four --candidate-* identity bindings below
  --candidate-release VERSION         Candidate vSemVer release identity
  --candidate-revision SHA            Full lowercase Git revision
  --candidate-build-id source:SHA     Must exactly bind the full candidate revision
  --candidate-oci-digest sha256:DIGEST Expected local OCI manifest digest
                                      Local OCI candidates are managed-only and reject
                                      --external-dependencies
  --external-dependencies             Use operator-owned runtime, migration, and backup PostgreSQL/Valkey
  --secrets-stdin                     Read five dependency URLs plus dedicated-instance Valkey backup scope as strict JSON from stdin; binds canonical endpoints and usernames, never passwords
  --secret-fd FD                      Read the same JSON from an already-open FD (Linux)
  --profile-secrets-stdin             Read standards-full profile bearer secrets as strict JSON from stdin
  --profile-secret-fd FD              Read the same profile JSON from an already-open FD (Linux)

With managed dependencies and standards-full profile, identities and service-owned
secrets are generated automatically and persisted in the installation secret store.
Profile secret input is optional and is intended only for importing an existing
secret during a controlled recovery or migration.
External JSON keys: database_url, migration_database_url, database_backup_url,
valkey_url, valkey_backup_url, valkey_backup_scope (must be dedicated-instance).
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
An unreleased OCI candidate install requires all five candidate target bindings
shown above, uses only fresh Ctl-managed dependencies, and rejects external
dependencies. Its active digest and embedded identity must match exactly, and
public completion additionally requires a nonce-bound control JWS verified
against the descriptor-mounted instance identity. `--yes` skips only the prompt;
it never skips verification, backup, health, replay, audit, or rollback protection."
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
  nazoauthctl conformance artifact resolve --trust-policy PATH \
    --manifest-url HTTPS_URL --cache-dir PATH [--capability NAME ...]
  nazoauthctl conformance artifact verify --trust-policy PATH \
    --manifest PATH --matrix PATH [--capability NAME ...]
  nazoauthctl [--deployment ID] [--config PATH] conformance run [--suite URL]
    [--token TOKEN|--token-file PATH|--token-stdin|--token-fd FD]
    [--webdriver URL] [--evidence-dir PATH] [--group ID] [--plan ID]
`conformance artifact resolve` fetches a bounded stable-channel manifest without
redirects, verifies it before following the signed matrix URL, verifies the exact
matrix bytes, and commits an immutable owner-only cache entry. The verified record
is written last as the cache commit marker; an incomplete entry is never accepted.

`conformance artifact verify` is read-only and deployment-independent. It emits a
verified identity only after checking the local trust policy, ES256 signature,
source, validity window, Suite identity, strict matrix schema, digest, size,
resource bounds, and every caller-supplied available capability. It does not
discover or grant target capabilities and does not execute the Suite.

`conformance run` validates the deployment and signed artifact, authenticates to the
official Suite by default, applies an auditable ordinary tenant-resource change set,
runs the selected official plans, preserves official PASS/FAIL values, and always
attempts Suite and resource cleanup. In a TTY, a missing API token is read
without echo and can be stored securely per Suite origin. `--token` is supported for
automation but is visible in argv and shell history. Progress is item-count based on
stderr; the final structured report is written to stdout without secrets.
Private credentials remain in controller-owned files or zeroizing memory; provider
receipts expose only signed resource identities and public mappings. Recovery replays
the exact prepared request and cleanup is digest-fenced against the observed run
resources."
        }
        cli::HelpTopic::Tls => {
            "Usage:
  nazoauthctl --deployment ID tls certificate plan --provider-config PATH \
    --tenant TENANT --hostname HOST --certificate PATH --private-key PATH
  nazoauthctl --deployment ID tls certificate apply --provider-config PATH \
    --tenant TENANT --hostname HOST --certificate PATH --private-key PATH --yes
  nazoauthctl --deployment ID tls certificate plan --provider-config PATH \
    --tenant TENANT --hostname HOST --from-acme-current
  nazoauthctl --deployment ID tls certificate apply --provider-config PATH \
    --tenant TENANT --hostname HOST --from-acme-current --yes
  nazoauthctl --deployment ID tls certificate check --provider-config PATH \
    --tenant TENANT --hostname HOST [--warning-window-seconds N]
  nazoauthctl --deployment ID tls certificate recover --tenant TENANT --hostname HOST --yes
  nazoauthctl --deployment ID tls certificate show --tenant TENANT --hostname HOST
  nazoauthctl --deployment ID tls acme plan --acme-config PATH --provider-config PATH \
    --tenant TENANT --hostname HOST
  nazoauthctl --deployment ID tls acme issue --acme-config PATH --provider-config PATH \
    --tenant TENANT --hostname HOST --agree-terms --yes
  nazoauthctl --deployment ID tls acme recover --tenant TENANT --hostname HOST --yes
  nazoauthctl --deployment ID tls acme show --tenant TENANT --hostname HOST

The external-generation-v1 provider uses an immutable generation directory and
one atomic `current` symlink. Its strict provider JSON declares material_root,
activation_link, trust_anchors, public_url, accepted_statuses, and separate
validate/reload commands. Validation runs against the candidate before activation;
reload is followed by a public TLS handshake, exact leaf-certificate digest check,
and bounded HTTP health request. Interrupted transactions are rolled back by the
explicit recover command. This provider controls only deployment-owned public TLS
material under the granted proxy_tls capability; it neither creates NazoAuth
protocol keys nor claims Direct TLS capability negotiation.

The acme command family creates or restores a deployment-owned ACME account,
serves one exact-host HTTP-01 challenge through a preconfigured webroot, persists
the server private key before finalization, validates the issued chain against
the provider trust policy, and commits an issuance receipt. Issuance does not
install or reload the certificate. `--from-acme-current` consumes the exact
current receipt only after revalidating its deployment/binding/revision,
provider/trust digests, account authority, and private artifacts; certificate
installation still uses the separate crash-safe provider transaction.

The certificate check command is read-only and intended for an external
monitoring scheduler. Success revalidates the active generation, source
authority, remaining lifetime, and real public TLS/HTTP endpoint before emitting
a bound readiness receipt. The process fails nonzero on drift, a pending or
uninstalled ACME issuance, public verification failure, or entry into the larger
of the provider minimum-validity and requested warning windows."
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

pub(crate) mod controller;

#[cfg(test)]
#[path = "../tests/unit/entrypoint.rs"]
mod tests;
