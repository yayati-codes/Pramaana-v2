#!/usr/bin/env bash
# Installs/verifies the pinned pramaana toolchains. Idempotent.
set -euo pipefail

RUST_PIN="1.96.0"   # also pinned in rust-toolchain.toml
FOUNDRY_PIN="1.7.1" # forge/cast/anvil
CIRCOM_PIN="2.2.3"  # circom 2.x
NODE_MIN_MAJOR="20" # also .nvmrc (20.20.2)
PNPM_PIN="11.6.0"   # also package.json "packageManager"

ok()   { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

echo "rust:"
command -v rustup >/dev/null 2>&1 || fail "rustup not found (https://rustup.rs)"
rustup toolchain install "$RUST_PIN" --profile minimal --component rustfmt,clippy >/dev/null 2>&1
ok "rustc $RUST_PIN (auto-selected via rust-toolchain.toml)"

echo "foundry:"
FOUNDRY_BIN="$HOME/.foundry/bin"
[ -x "$FOUNDRY_BIN/foundryup" ] || fail "foundryup not found (https://getfoundry.sh)"
have_forge="$("$FOUNDRY_BIN/forge" --version 2>/dev/null | head -1 | awk '{print $3}' || true)"
if [ "$have_forge" != "$FOUNDRY_PIN" ]; then
  "$FOUNDRY_BIN/foundryup" --install "$FOUNDRY_PIN" >/dev/null
fi
ok "forge $("$FOUNDRY_BIN/forge" --version | head -1 | awk '{print $3}') (pin $FOUNDRY_PIN)"

echo "circom:"
command -v circom >/dev/null 2>&1 \
  || fail "circom not found (cargo install --git https://github.com/iden3/circom --tag v$CIRCOM_PIN)"
have_circom="$(circom --version | awk '{print $3}')"
if [ "$have_circom" = "$CIRCOM_PIN" ]; then
  ok "circom $have_circom"
else
  echo "  warn circom $have_circom installed, pin is $CIRCOM_PIN"
fi

echo "node/pnpm:"
command -v node >/dev/null 2>&1 || fail "node not found (nvm install \$(cat .nvmrc))"
node_major="$(node --version | sed 's/^v//' | cut -d. -f1)"
[ "$node_major" -ge "$NODE_MIN_MAJOR" ] || fail "node >= $NODE_MIN_MAJOR required, have $(node --version)"
corepack enable >/dev/null 2>&1 || true
corepack prepare "pnpm@$PNPM_PIN" --activate >/dev/null
ok "node $(node --version), pnpm $(pnpm --version) (pin $PNPM_PIN)"

echo "all toolchains ok"
