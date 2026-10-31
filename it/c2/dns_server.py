#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Minimal UDP/53 DNS responder for the external C2 host.

Answers any A query with C2's own address. Its only purpose is to give the
ews's beacon DNS queries a real server to talk to over eth0, so Zeek records
them in dns.log (Docker's embedded resolver lives on loopback and is not
captured by the sidecar). Pure stdlib; not a real resolver.
"""

import os
import socket
import struct

PORT = int(os.environ.get("DNS_PORT", "53"))
ANSWER_IP = os.environ.get("DNS_ANSWER_IP", "203.0.113.13")  # TEST-NET-3 placeholder


def build_response(query: bytes) -> bytes:
    # Transaction ID (echo) + flags 0x8180 (standard response, no error).
    tid = query[:2]
    header = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    # Question section starts after the 12-byte header; copy it verbatim.
    qend = 12
    while query[qend] != 0:
        qend += 1 + query[qend]
    qend += 1 + 4  # null label + QTYPE + QCLASS
    question = query[12:qend]
    # Answer: name pointer to offset 12, type A, class IN, TTL 60, RDLENGTH 4.
    answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" +
              struct.pack(">I", 60) + struct.pack(">H", 4) +
              socket.inet_aton(ANSWER_IP))
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    print(f"[c2] DNS responder on 0.0.0.0:{PORT} -> {ANSWER_IP}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 13:
                continue
            sock.sendto(build_response(data), addr)
        except Exception as e:  # never let one bad packet kill the responder
            print(f"[c2] dns error: {e}", flush=True)


if __name__ == "__main__":
    main()
