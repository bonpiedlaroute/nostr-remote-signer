#!/usr/bin/env bash
# acceptance: can this host build enclave images and run them under QEMU?
# Usage: enclave/qemu/check-env.sh
# shellcheck disable=SC2016  # single quotes on purpose: the inner sh expands them

failed=0

check() {
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "✅ $label"
    else
        echo "❌ $label"
        failed=1
    fi
}

check "KVM: /dev/kvm usable without sudo" test -w /dev/kvm
check "docker: daemon reachable without sudo" docker info
check "QEMU: \$QEMU has the nitro-enclave machine" \
    sh -c '"$QEMU" -machine help | grep -q nitro-enclave'
check "vhost-device-vsock installed" sh -c 'command -v vhost-device-vsock'
check "vsock_loopback available" \
    sh -c 'lsmod | grep -q vsock_loopback || grep -q vsock_loopback "/lib/modules/$(uname -r)/modules.builtin"'
check "python3 with AF_VSOCK" python3 -c 'import socket; socket.AF_VSOCK'
check "nitro-cli installed" nitro-cli --version
check "nitro-cli blobs present" \
    sh -c 'test -d "${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs}"'

exit "$failed"
