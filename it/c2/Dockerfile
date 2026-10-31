# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval external C2 endpoint.
# A box outside the plant network: terminates the ews's TLS beacon (HTTPS :443)
# and its DNS beacon (UDP :53), and carries an SSH client used to log into the
# ews.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass openssl curl ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY tls_server.py dns_server.py /opt/c2/

EXPOSE 443 53/udp
# Run the DNS responder in the background, then the TLS server in the foreground.
CMD ["sh", "-c", "python3 /opt/c2/dns_server.py & exec python3 /opt/c2/tls_server.py"]
