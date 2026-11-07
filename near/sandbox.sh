#!/usr/bin/env bash
# Run the contract tests on near-sandbox (nearcore 2.14.0) in a Rust container.
# Run ./build.sh first.
# Usage: near/sandbox.sh [cargo test arguments]
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$root/.." && pwd)
cache=${CARGO_CACHE:-$HOME/.cache/dsmack-near-cargo}
mkdir -p "$cache"
exec podman run --rm \
  -v "$root:/work:Z" -v "$repo:/dsmack:ro,Z" -v "$cache:/cargo:Z" \
  -e HOME=/cargo/home -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/cargo/target-sandbox \
  -e DSMACK_DIR=/dsmack -e WASM_DIR=/work/out -w /work/tests \
  docker.io/library/rust:1-slim@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 bash -c '
    set -e
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq pkg-config libssl-dev ca-certificates clang >/dev/null 2>&1
    cargo test --release --locked -- --nocapture --test-threads=1 "$@"' _ "$@"
