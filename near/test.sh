#!/usr/bin/env bash
# Run the core tests in a Rust container.
# Usage: near/test.sh [cargo test arguments]
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$root/.." && pwd)
cache=${CARGO_CACHE:-$HOME/.cache/dsmack-near-cargo}
mkdir -p "$cache"
exec podman run --rm \
  -v "$root:/work:Z" -v "$repo:/dsmack:ro,Z" -v "$cache:/cargo:Z" \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/cargo/target -e DSMACK_DIR=/dsmack \
  -w /work docker.io/library/rust:1-slim@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 cargo test --locked -p dsmack-attest-core "$@"
