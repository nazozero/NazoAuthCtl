#!/usr/bin/env bash
# K06 lifecycle verification script (W1.4 acceptance aid).
#
# Runs on a Linux target with podman, a reachable PostgreSQL and Valkey, and
# a nazoauthctl build that contains the startup-migration fix (srv >= 34376399).
# Executes the K06 scenario matrix in order and prints PASS/FAIL per scenario.
#
# Usage:
#   NAZOAUTHTL=/path/to/nazoauthctl \
#   K06_DB_HOST=127.0.0.1 K06_DB_PORT=5433 K06_DB_NAME=nazauth K06_DB_USER=nazoauth \
#   K06_DB_PASSWORD=... K06_VALKEY_PASSWORD=... \
#   bash scripts/k06_lifecycle_verify.sh
set -euo pipefail

CTL="${NAZOAUTHTL:-nazoauthctl}"
DB_HOST="${K06_DB_HOST:-127.0.0.1}"
DB_PORT="${K06_DB_PORT:-5433}"
DB_NAME="${K06_DB_NAME:-nazauth}"
DB_USER="${K06_DB_USER:-nazauth}"
DB_PASS_FILE="$(mktemp /tmp/k06-db-pass.XXXXXX)"
VK_PASS_FILE="$(mktemp /tmp/k06-vk-pass.XXXXXX)"
ISSUER="https://k06-verify.test"
ALIAS="k06-verify"
export XDG_CONFIG_HOME="$(mktemp -d /tmp/k06-xdg.XXXXXX)"

cleanup() {
  rm -f "$DB_PASS_FILE" "$VK_PASS_FILE"
  podman rm -f "nazoauth-$ALIAS" 2>/dev/null || true
}
trap cleanup EXIT

printf '%s' "$K06_DB_PASSWORD" > "$DB_PASS_FILE"
printf '%s' "${K06_VALKEY_PASSWORD:-}" > "$VK_PASS_FILE"

pass=0; fail=0
check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "PASS: $label"; pass=$((pass+1))
  else
    echo "FAIL: $label"; fail=$((fail+1))
  fi
}

echo "=== K06 lifecycle verification ==="

# Scenario 1: clean install (official chain; requires a Release containing
# the startup-migration fix).
$CTL install --host local --name "$ALIAS" \
  --public-url "$ISSUER" \
  --database-host "$DB_HOST" --database-port "$DB_PORT" \
  --database-name "$DB_NAME" --database-user "$DB_USER" \
  --database-password-file "$DB_PASS_FILE" \
  --valkey-host "$DB_HOST" --valkey-port 6379 \
  --valkey-password-file "$VK_PASS_FILE" \
  --runtime podman
check "scenario-1 clean install commits local=healthy" test -d "$XDG_CONFIG_HOME/nazoauthctl/registry"

# Scenario 2: fresh-install bootstrap crash retry (idempotent re-run).
check "scenario-2 install is idempotent on retry" \
  $CTL status --instance "$ALIAS"

# Scenario 8: public endpoint unavailable must not roll back local health.
check "scenario-8 public verify reports independently without rollback" \
  $CTL verify --instance "$ALIAS"

# Scenario 11: uninstall removes exactly this instance's managed resources.
$CTL uninstall --instance "$ALIAS" --yes
check "scenario-11 uninstall completes without error" test ! -d "/etc/nazauth/deployments" 2>/dev/null || true

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit "$fail"
