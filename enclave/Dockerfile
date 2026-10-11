# The vault's enclave image. Build from the repository root:
#   docker build -f enclave/Dockerfile -t bunker-vault:d1 .

# Static musl binaries: the final image needs no libc, and has no shell.
FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p nostr-remote-signer --bin bunkerd --bin enclave-init

FROM scratch
COPY --from=build /src/target/release/bunkerd /src/target/release/enclave-init /
COPY enclave/conf/ /etc/bunker/
# The enclave's init ignores WORKDIR and starts in /: every path is absolute.
# The journal goes to the parent (journal-sink): the enclave has no disk.
# The agents come from the parent: enclave-init writes them at BUNKER_AGENTS, in RAM.
ENV BUNKER_IDENTITIES=/etc/bunker/identities.json \
    BUNKER_POLICY=/etc/bunker/policy.json \
    BUNKER_AGENTS=/etc/bunker/agents.json \
    BUNKER_AUDIT_LOG=vsock://3:7001
ENTRYPOINT ["/enclave-init", "/bunkerd"]
