# The vault's enclave image. Build from the repository root:
#   docker build -f enclave/Dockerfile -t bunker-vault:d1 .

# A static musl binary: the final image needs no libc, and has no shell.
FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p nostr-remote-signer --bin bunkerd

FROM scratch
COPY --from=build /src/target/release/bunkerd /bunkerd
COPY enclave/conf/ /etc/bunker/
# The enclave's init ignores WORKDIR and starts in /: every path is absolute.
ENV BUNKER_IDENTITIES=/etc/bunker/identities.json \
    BUNKER_POLICY=/etc/bunker/policy.json \
    BUNKER_AGENTS=/etc/bunker/agents.json \
    BUNKER_AUDIT_LOG=/etc/bunker/audit.log
ENTRYPOINT ["/bunkerd"]
