# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval engineering workstation (ews) — the IT/OT pivot box.
# Runs sshd (the SSH target an intruder logs into), carries client tooling
# (nmap, openssl, curl) and the OT clients (asyncua / python-snap7), and shares
# its network namespace with the Zeek sensor sidecar.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server openssh-client nmap openssl curl dnsutils iptables \
        ca-certificates iproute2 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*

# OT client libraries (pure Python, no native deps).
RUN pip install --no-cache-dir asyncua 'python-snap7==3.0.0'

# An "engineer" operator account the intruder authenticates as (demo creds).
RUN useradd -m -s /bin/bash engineer \
    && echo 'engineer:engineer' | chpasswd \
    && mkdir -p /run/sshd \
    && ssh-keygen -A \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY ot/ /opt/ot/

EXPOSE 22
# Foreground sshd keeps the container up and serves the SSH login.
CMD ["/usr/sbin/sshd", "-D", "-e"]
