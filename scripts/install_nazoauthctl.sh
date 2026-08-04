#!/bin/sh
set -eu

repository="nazozero/NazoAuthCtl"
version=""
install_path="/usr/local/sbin/nazoauthctl"

usage() {
  printf '%s\n' \
    'usage: install_nazoauthctl.sh [--version vX.Y.Z] [--install-path ABSOLUTE_PATH]'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      version=$2
      shift 2
      ;;
    --install-path)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      install_path=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[ "$(id -u)" -eq 0 ] || {
  printf '%s\n' 'install_nazoauthctl.sh must run as root' >&2
  exit 1
}
command -v gh >/dev/null 2>&1 || {
  printf '%s\n' 'GitHub CLI (gh) is required for attestation verification' >&2
  exit 1
}

case "$install_path" in
  /*) ;;
  *) printf '%s\n' '--install-path must be absolute' >&2; exit 2 ;;
esac
case "$install_path" in
  */.|*/..|*/) printf '%s\n' '--install-path must name a file' >&2; exit 2 ;;
esac

if [ -z "$version" ]; then
  version=$(gh release view --repo "$repository" --json tagName --jq .tagName)
fi
printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  printf '%s\n' 'controller version must be an explicit vX.Y.Z tag' >&2
  exit 2
}

[ "$(uname -s)" = Linux ] || {
  printf '%s\n' 'the shell installer supports Linux only; use the signed platform asset directly' >&2
  exit 1
}
case "$(uname -m)" in
  x86_64|amd64) target=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) target=aarch64-unknown-linux-gnu ;;
  *) printf '%s\n' 'this Linux architecture has no official controller asset' >&2; exit 1 ;;
esac

parent=$(dirname -- "$install_path")
[ -d "$parent" ] && [ ! -L "$parent" ] || {
  printf '%s\n' 'controller install parent must be an existing non-symlink directory' >&2
  exit 1
}
if [ -e "$install_path" ] || [ -L "$install_path" ]; then
  [ -f "$install_path" ] && [ ! -L "$install_path" ] || {
    printf '%s\n' 'existing controller install target must be a regular non-symlink file' >&2
    exit 1
  }
fi

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/nazoauthctl-install.XXXXXX")
staged=""
cleanup() {
  [ -z "$staged" ] || rm -f -- "$staged"
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

artifact="nazoauthctl-$target"
gh release download "$version" --repo "$repository" --pattern "$artifact" --dir "$work"
gh attestation verify "$work/$artifact" \
  --repo "$repository" \
  --signer-workflow "$repository/.github/workflows/release.yml" \
  --source-ref "refs/tags/$version" \
  --deny-self-hosted-runners
chmod 0755 "$work/$artifact"
"$work/$artifact" --help >/dev/null

staged=$(mktemp "$parent/.nazoauthctl.XXXXXX")
install -o root -g root -m 0755 "$work/$artifact" "$staged"
mv -f -- "$staged" "$install_path"
staged=""
printf 'installed verified nazoauthctl %s at %s\n' "$version" "$install_path"
