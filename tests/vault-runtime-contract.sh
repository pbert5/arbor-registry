#!/usr/bin/env bash
set -euo pipefail

test_root=$(mktemp -d "${TMPDIR:-/tmp}/arbor-vault-runtime.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

provider_dir="$test_root/provider"
credential_dir="$test_root/run/arbor-vaultd/credentials"
consumer_dir="$test_root/consumer"
mkdir -p "$provider_dir" "$credential_dir" "$consumer_dir"

provider_config="$provider_dir/config"
printf '%s\n' 'address=bao://local' 'path=kv/data/arbor/db' 'field=url' >"$provider_config"

secret_v1="db-url-v1-$$"
secret_v2="db-url-v2-$$"
printf '%s\n' "$secret_v1" >"$provider_dir/secret"

provider_fetch() {
  local next="$credential_dir/.api.next"
  cp "$provider_dir/secret" "$next"
  mv "$next" "$credential_dir/api"
  : >"$credential_dir/.ready"
}

vaultd_start() {
  test -f "$credential_dir/.ready" || return 1
  cp "$credential_dir/api" "$consumer_dir/db-url"
  : >"$consumer_dir/vaultd-active"
}

consumer_start() {
  test -f "$consumer_dir/vaultd-active" || return 1
  cp "$consumer_dir/db-url" "$consumer_dir/loaded"
}

fail() {
  printf 'vault-runtime contract failed: %s\n' "$1" >&2
  exit 1
}

if vaultd_start 2>/dev/null; then
  fail 'vaultd started before provider readiness'
fi

provider_fetch
test -s "$credential_dir/api" || fail 'provider did not publish a credential'
test -f "$credential_dir/.ready" || fail 'provider did not publish readiness'

vaultd_start
consumer_start
test "$(<"$consumer_dir/loaded")" = "$secret_v1" || fail 'initial credential was not delivered'

printf '%s\n' "$secret_v2" >"$provider_dir/secret"
provider_fetch
test "$(<"$consumer_dir/loaded")" = "$secret_v1" || fail 'rotation changed a running consumer credential'

rm "$consumer_dir/vaultd-active" "$consumer_dir/db-url" "$consumer_dir/loaded"
vaultd_start
consumer_start
test "$(<"$consumer_dir/loaded")" = "$secret_v2" || fail 'restart did not load the rotated credential'

case "$credential_dir" in
  /nix/store/*) fail 'credential fixture was placed in the Nix store' ;;
esac
if env | grep -F -- "$secret_v2" >/dev/null; then
  fail 'rotated credential leaked into the test environment'
fi
if grep -R -F -- "$secret_v2" "$provider_config" >/dev/null; then
  fail 'rotated credential leaked into provider configuration'
fi

printf 'vault-runtime mock contract: readiness, rotation/restart, and no-leak checks passed\n'
