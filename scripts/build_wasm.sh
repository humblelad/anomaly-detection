#!/usr/bin/env bash
# Builds the Rust WASM filter and exports just the 146 KB module to
# envoy/detection_filter.wasm. The Rust toolchain lives only inside the
# throwaway build stage — no ~1.5 GB builder image is left behind.
set -euo pipefail
cd "$(dirname "$0")/.."

docker buildx build \
  --target artifact \
  --output "type=local,dest=envoy" \
  wasm-filter

echo "wrote envoy/detection_filter.wasm ($(wc -c < envoy/detection_filter.wasm) bytes)"
