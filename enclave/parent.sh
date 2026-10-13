#!/usr/bin/env bash
# The parent's side of the enclave, the same under QEMU and on EC2: hand the vault its boot
# secrets once, serve the agents, and bridge the enclave's traffic to bunker-relay and KMS.
#
# Usage: BUNKER_AGENTS=agents.json enclave/parent.sh   (bunker-relay on 127.0.0.1:7777)
# The vault fetches the agents every second: edit the file to revoke, no signal needed.
# Boot secrets: BUNKER_PASSPHRASE and the AWS_* credentials of this environment; with none
# of them, the passphrase is asked for.
# KMS: the endpoint of AWS_REGION, or BUNKER_KMS_PROXY=host:port.
set -euo pipefail

# Must match enclave-init.
BOOT_ENV_PORT=7000
AGENTS_PORT=7002
RELAY_PORT=7777
KMS_PORT=8000
BOOT_ENV=(BUNKER_PASSPHRASE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN)

AGENTS=${BUNKER_AGENTS:-agents.json}
if [ ! -r "$AGENTS" ]; then
    echo "cannot read the agents at $AGENTS (set BUNKER_AGENTS)" >&2
    exit 1
fi

boot_env=
handed=
for name in "${BOOT_ENV[@]}"; do
    if [ -n "${!name:-}" ]; then
        boot_env+="$name=${!name}"$'\n'
        handed+=" $name"
    fi
done
if [ -z "$boot_env" ]; then
    printf 'enclave passphrase: '
    read -rs BUNKER_PASSPHRASE
    echo
    boot_env="BUNKER_PASSPHRASE=$BUNKER_PASSPHRASE"$'\n'
    handed=" BUNKER_PASSPHRASE"
fi
kms=${BUNKER_KMS_PROXY:-${AWS_REGION:+kms.$AWS_REGION.amazonaws.com:443}}

bridge=
feed=
proxy=
cleanup() { kill $bridge $feed $proxy 2>/dev/null || true; }
trap cleanup EXIT

socat "VSOCK-LISTEN:$RELAY_PORT,fork,reuseaddr" "TCP:127.0.0.1:$RELAY_PORT" &
bridge=$!
# Each connection opens the file anew: the vault always gets the current list.
socat -U "VSOCK-LISTEN:$AGENTS_PORT,fork,reuseaddr" "OPEN:$AGENTS,rdonly" &
feed=$!
if [ -n "$kms" ]; then
    # Plain TCP: TLS runs from the vault itself to KMS.
    socat "VSOCK-LISTEN:$KMS_PORT,fork,reuseaddr" "TCP:$kms" &
    proxy=$!
fi

echo "waiting for the enclave to fetch its boot secrets:$handed (vsock port $BOOT_ENV_PORT)"
# printf is a builtin: the secrets reach socat through a pipe, never through argv.
printf '%s' "$boot_env" | socat -u STDIN "VSOCK-LISTEN:$BOOT_ENV_PORT,reuseaddr"
echo "boot secrets delivered; serving $AGENTS, bridging relay${kms:+ and KMS ($kms)} - Ctrl-C to stop"
wait "$bridge"
