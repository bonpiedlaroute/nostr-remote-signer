#!/usr/bin/env bash
# Run an enclave image under QEMU, with what a Nitro parent instance provides:
# vsock to the host, and an answer to the boot heartbeat.
#
# Usage: enclave/qemu/run.sh <file.eif> [memory]      quit QEMU with Ctrl-A then X
set -euo pipefail

EIF=${1:?usage: run.sh <file.eif> [memory]}
MEM=${2:-1G}
SOCKET=/tmp/vhost4.socket
HERE=$(cd "$(dirname "$0")" && pwd)
: "${QEMU:?set QEMU to a qemu-system-x86_64 built with the nitro-enclave machine}"

# With -nographic, QEMU makes the terminal non-blocking: a helper writing to it while
# the enclave floods the console gets EAGAIN and dies. The helpers log to files instead.
LOGS=$(mktemp -d "${TMPDIR:-/tmp}/enclave-qemu.XXXXXX")

heartbeat=
vsock=
cleanup() {
    kill $heartbeat $vsock 2>/dev/null || true
    rm -f "$SOCKET"
    cat "$LOGS/heartbeat.log" >&2
    echo "logs: $LOGS" >&2
}
trap cleanup EXIT

python3 "$HERE/heartbeat.py" >"$LOGS/heartbeat.log" 2>&1 &
heartbeat=$!

rm -f "$SOCKET"
vhost-device-vsock --vm "guest-cid=4,forward-cid=1,forward-listen=9001,socket=$SOCKET" \
    >"$LOGS/vsock.log" 2>&1 &
vsock=$!

# QEMU connects to this socket: wait until vhost-device-vsock has created it.
for _ in $(seq 50); do
    [ -S "$SOCKET" ] && break
    sleep 0.1
done
[ -S "$SOCKET" ] || { echo "vhost-device-vsock did not start, see $LOGS/vsock.log" >&2; exit 1; }

# -no-reboot: the enclave's init reboots when its program exits; on Nitro that ends the
# enclave, so QEMU must stop too instead of booting it again.
"$QEMU" -M nitro-enclave,vsock=c,id=enclave -kernel "$EIF" \
    -nographic -no-reboot -m "$MEM" -accel kvm -cpu host \
    -chardev "socket,id=c,path=$SOCKET"
