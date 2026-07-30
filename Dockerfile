# §15: alpine base, static binary at /usr/local/bin/rsfusa, OCI + io.x-fusa.* labels.
# Two-stage build: musl-linked static binary for minimal runtime image.

FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked \
    && strip target/release/rsfusa

# ── Runtime image ──────────────────────────────────────────────────────────

FROM alpine:3.21

ARG VERSION=0.3.16
ARG SPEC_VERSION=1.15.2

LABEL org.opencontainers.image.title="rust-FuSa" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/SoundMatt/rust-FuSa" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.x-fusa.tool="rust-FuSa" \
      io.x-fusa.language="rust" \
      io.x-fusa.binary="rsfusa" \
      io.x-fusa.spec-version="${SPEC_VERSION}"

COPY --from=builder /src/target/release/rsfusa /usr/local/bin/rsfusa

# Run as an unprivileged user, not root.
RUN adduser -D -u 10001 fusa
USER fusa

WORKDIR /project
ENTRYPOINT ["rsfusa"]
CMD ["help"]
