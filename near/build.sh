#!/usr/bin/env bash
# Build the contract WASM in a Rust container: out/dsmack_near.wasm for deployment
# and, for the sandbox tests, out/dsmack_near_fixture_clock.wasm, the example consumer
# out/dsmack_consumer.wasm and its test build out/dsmack_consumer_fixture_context.wasm.
# Usage: ./build.sh
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
cache=${CARGO_CACHE:-$HOME/.cache/dsmack-near-cargo}
mkdir -p "$cache" "$root/out"
exec podman run --rm -v "$root:/work:Z" -v "$cache:/cargo:Z" \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/cargo/target -e RUSTFLAGS="--cfg near" -w /work \
  docker.io/library/rust:1-slim@sha256:7eab7ce19273ce785e0ca7578bdf7bc1fcbae621775a8197379a04c9f6e03cd5 bash -c '
    set -euo pipefail
    rustup target add wasm32-unknown-unknown >/dev/null 2>&1
    wasm=/cargo/target/wasm32-unknown-unknown/release/dsmack_near.wasm
    cargo build -p dsmack-near --target wasm32-unknown-unknown --release --locked
    cp "$wasm" out/dsmack_near.wasm
    cargo build -p dsmack-near --target wasm32-unknown-unknown --release --locked --features fixture-clock
    cp "$wasm" out/dsmack_near_fixture_clock.wasm
    consumer=/cargo/target/wasm32-unknown-unknown/release/dsmack_consumer.wasm
    cargo build -p dsmack-consumer --target wasm32-unknown-unknown --release --locked
    cp "$consumer" out/dsmack_consumer.wasm
    cargo build -p dsmack-consumer --target wasm32-unknown-unknown --release --locked --features fixture-context
    cp "$consumer" out/dsmack_consumer_fixture_context.wasm
    if grep -q set_clock out/dsmack_near.wasm; then echo "the deployment build exports set_clock" >&2; exit 1; fi
    ls -l out
    sha256sum out/dsmack_near.wasm'
