# Builds the 146 KB WASM module. The Rust toolchain lives only in this build
# stage; the `artifact` stage is `scratch` + one file, so it is exported to
# the host with `docker buildx build --output` (see scripts/build_wasm.*).
# Nothing from this Dockerfile ships as a runtime image.
FROM rust:1.97-slim AS build
RUN rustup target add wasm32-wasip1
WORKDIR /src
COPY Cargo.toml ./
COPY src/ ./src/
RUN cargo build --release --target wasm32-wasip1 \
    && cp target/wasm32-wasip1/release/detection_wasm_filter.wasm /detection_filter.wasm

FROM scratch AS artifact
COPY --from=build /detection_filter.wasm /detection_filter.wasm
