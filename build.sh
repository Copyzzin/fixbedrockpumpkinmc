#!/usr/bin/env bash
# Build bedrock-bridge and assemble a drop-in Pumpkin plugin folder.
#
#   ./build.sh                 build (+ tests if wasmtime is installed) and package
#   SKIP_TESTS=1 ./build.sh    build and package without running tests
#
# Output: dist/bedrock-bridge/            copy its contents into your Pumpkin server directory
#         dist/bedrock-bridge-<ver>.zip   same thing, zipped
set -euo pipefail

cd "$(dirname "$0")"

NAME="bedrock-bridge"
TARGET="wasm32-wasip2"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n1)"
OUT="dist/${NAME}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: '$1' not found. $2" >&2
    exit 1
  }
}

need cargo "Install Rust (1.88 or newer) from https://rustup.rs"
need rustup "Install Rust (1.88 or newer) from https://rustup.rs"

if ! rustup target list --installed | grep -qx "${TARGET}"; then
  echo "==> installing Rust target ${TARGET}"
  rustup target add "${TARGET}"
fi

if [[ "${SKIP_TESTS:-0}" != "1" ]] && command -v wasmtime >/dev/null 2>&1; then
  echo "==> running unit tests under wasmtime"
  CARGO_TARGET_WASM32_WASIP2_RUNNER="wasmtime" cargo test --target "${TARGET}"
else
  echo "==> skipping unit tests (install wasmtime to enable them, or SKIP_TESTS=1 to silence this)"
fi

echo "==> building release (${TARGET})"
cargo build --release --target "${TARGET}"

# Cargo turns the crate name's hyphens into underscores for the artifact name.
WASM="target/${TARGET}/release/${NAME//-/_}.wasm"
if [[ ! -f "${WASM}" ]]; then
  echo "error: expected build artifact ${WASM} was not produced" >&2
  exit 1
fi

# Optional sanity check: Pumpkin loads WASM *components*, not plain core modules.
if command -v wasm-tools >/dev/null 2>&1; then
  wasm-tools validate "${WASM}"
  if ! wasm-tools print "${WASM}" | head -n 3 | grep -q '(component'; then
    echo "error: ${WASM} is not a WASM component (was it built for ${TARGET}?)" >&2
    exit 1
  fi
  echo "==> wasm-tools: valid component"
fi

echo "==> assembling ${OUT}"
rm -rf "${OUT}"
mkdir -p "${OUT}/plugins/data/${NAME}"
cp "${WASM}" "${OUT}/plugins/${NAME}.wasm"
cp config.example.toml "${OUT}/plugins/data/${NAME}/config.toml"
cp dist-template/pumpkin-config.snippet.toml "${OUT}/"
cp dist-template/INSTALL.md "${OUT}/"
cp README.md "${OUT}/"

ZIP="dist/${NAME}-${VERSION}.zip"
rm -f "${ZIP}"
if command -v zip >/dev/null 2>&1; then
  (cd dist && zip -qr "$(basename "${ZIP}")" "${NAME}")
else
  python3 - "${ZIP}" "${OUT}" <<'EOF'
import os, sys, zipfile
zip_path, root = sys.argv[1], sys.argv[2]
base = os.path.dirname(root)
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, files in os.walk(root):
        for f in sorted(files):
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, base))
EOF
fi

echo
echo "Done:"
echo "  folder: ${OUT}/"
echo "  zip:    ${ZIP}"
echo
echo "Next: follow ${OUT}/INSTALL.md (the plugin will not start until config.toml is filled in)."
