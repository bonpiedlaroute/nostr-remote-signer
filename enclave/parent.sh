#!/usr/bin/env bash
# The parent's side of the enclave, the same under QEMU and on EC2: hand the passphrase
# over once, and bridge the enclave's relay traffic to bunker-relay.
#
# Usage: enclave/parent.sh        (bunker-relay listening on 127.0.0.1:7777)
set -euo pipefail

# Must match enclave-init.
PASSPHRASE_PORT=7000
RELAY_PORT=7777

if [ -z "${BUNKER_PASSPHRASE:-}" ]; then
    printf 'enclave passphrase: '
    read -rs BUNKER_PASSPHRASE
    echo
fi

bridge=
cleanup() { kill $bridge 2>/dev/null || true; }
trap cleanup EXIT

socat "VSOCK-LISTEN:$RELAY_PORT,fork,reuseaddr" "TCP:127.0.0.1:$RELAY_PORT" &
bridge=$!

echo "waiting for the enclave to fetch its passphrase (vsock port $PASSPHRASE_PORT)"
# printf is a builtin: the passphrase reaches socat through a pipe, never through argv.
printf '%s' "$BUNKER_PASSPHRASE" | socat -u STDIN "VSOCK-LISTEN:$PASSPHRASE_PORT,reuseaddr"
echo "passphrase delivered; bridging relay traffic - Ctrl-C to stop"
wait "$bridge"
