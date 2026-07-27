# Builds the Rust WASM filter and exports just the 146 KB module to
# envoy\detection_filter.wasm. The Rust toolchain lives only inside the
# throwaway build stage -- no ~1.5 GB builder image is left behind.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

docker buildx build `
  --target artifact `
  --output "type=local,dest=$root\envoy" `
  "$root\wasm-filter"

$size = (Get-Item "$root\envoy\detection_filter.wasm").Length
Write-Host "wrote envoy\detection_filter.wasm ($size bytes)"
