#!/usr/bin/env bash
# The parent's side of the enclave, the same under QEMU and on EC2: hand the passphrase
# over once, serve the agents, and bridge the enclave's relay traffic to bunker-relay.
#
# Usage: BUNKER_AGENTS=agents.json enclave/parent.sh   (bunker-relay on 127.0.0.1:7777)
# The vault fetches the agents every second: edit the file to revoke, no signal needed.
set -euo pipefail

# Must match enclave-init.
PASSPHRASE_PORT=7000
AGENTS_PORT=7002
RELAY_PORT=7777

AGENTS=${BUNKER_AGENTS:-agents.json}
if [ ! -r "$AGENTS" ]; then
    echo "cannot read the agents at $AGENTS (set BUNKER_AGENTS)" >&2
    exit 1
fi

if [ -z "${BUNKER_PASSPHRASE:-}" ]; then
    printf 'enclave passphrase: '
    read -rs BUNKER_PASSPHRASE
    echo
fi

bridge=
feed=
cleanup() { kill $bridge $feed 2>/dev/null || true; }
trap cleanup EXIT

socat "VSOCK-LISTEN:$RELAY_PORT,fork,reuseaddr" "TCP:127.0.0.1:$RELAY_PORT" &
bridge=$!
# Each connection opens the file anew: the vault always gets the current list.
socat -U "VSOCK-LISTEN:$AGENTS_PORT,fork,reuseaddr" "OPEN:$AGENTS,rdonly" &
feed=$!

echo "waiting for the enclave to fetch its passphrase (vsock port $PASSPHRASE_PORT)"
# printf is a builtin: the passphrase reaches socat through a pipe, never through argv.
printf '%s' "$BUNKER_PASSPHRASE" | socat -u STDIN "VSOCK-LISTEN:$PASSPHRASE_PORT,reuseaddr"
echo "passphrase delivered; serving $AGENTS, bridging relay traffic - Ctrl-C to stop"
wait "$bridge"
