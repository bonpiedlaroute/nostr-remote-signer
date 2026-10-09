#!/usr/bin/env python3
"""Answer the enclave's boot heartbeat, as nitro-cli does on a real parent instance.

QEMU only. At boot the enclave's init connects to the parent (CID 3) on port 9000, sends
one byte (0xB7) and waits for it back; vhost-device-vsock delivers that connection here.
"""
import socket

PORT = 9000

with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen()
    print(f"waiting for the enclave heartbeat on vsock port {PORT}", flush=True)
    while True:
        conn, (cid, _) = server.accept()
        with conn:
            beat = conn.recv(1)
            conn.sendall(beat)
        print(f"heartbeat 0x{beat.hex()} from cid {cid}: answered", flush=True)
