# The vault's enclave image. Build from the repository root:
#   docker build -f enclave/Dockerfile -t bunker-vault:d1 .
# The root of trust and the KMS key are build arguments, so the measurement covers them:
#   docker build -f enclave/Dockerfile --build-arg ROOT_OF_TRUST=nitro \
#       --build-arg KMS_KEY_ID='arn:aws:kms:…' -t bunker-vault:d2 .
# Under QEMU, with the fake KMS on the parent (examples/fake_kms.rs), add:
#       --build-arg KMS_ENDPOINT=http://127.0.0.1:443

# Static musl binaries: the final image needs no libc, and has no shell.
FROM rust:1.90-alpine AS build
RUN apk add --no-cache musl-dev ca-certificates
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p nostr-remote-signer --features aws \
      --bin bunkerd --bin enclave-init

FROM scratch
COPY --from=build /src/target/release/bunkerd /src/target/release/enclave-init /
# TLS to KMS runs from inside the enclave.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY enclave/conf/ /etc/bunker/
ARG ROOT_OF_TRUST=passphrase
ARG KMS_KEY_ID=
ARG AWS_REGION=eu-west-3
ARG KMS_ENDPOINT=https://kms.${AWS_REGION}.amazonaws.com
# The enclave's init ignores WORKDIR and starts in /: every path is absolute.
# The journal goes to the parent (journal-sink): the enclave has no disk.
# The agents come from the parent: enclave-init writes them at BUNKER_AGENTS, in RAM.
ENV BUNKER_IDENTITIES=/etc/bunker/identities.json \
    BUNKER_POLICY=/etc/bunker/policy.json \
    BUNKER_AGENTS=/etc/bunker/agents.json \
    BUNKER_AUDIT_LOG=vsock://3:7001 \
    BUNKER_ROOT_OF_TRUST=$ROOT_OF_TRUST \
    BUNKER_KMS_KEY_ID=$KMS_KEY_ID \
    AWS_REGION=$AWS_REGION \
    AWS_ENDPOINT_URL_KMS=$KMS_ENDPOINT
ENTRYPOINT ["/enclave-init", "/bunkerd"]
