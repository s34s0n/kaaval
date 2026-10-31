# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval sensor — Zeek + ICSNPP (OPC UA Binary + S7comm), JSON logging.
# Runs as a sidecar in the ews network namespace (see docker-compose.yml) and
# sniffs the ews eth0, so one capture point sees the whole IT->OT chain.
#
# zeek/zeek is multi-arch (native linux/arm64). zkg is preinstalled and
# autoconfigured; the base image lacks a compiler, so we add the build deps the
# ICSNPP C++ plugins need. The plugin compile is the slow part of this build.
FROM zeek/zeek:8.1.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ cmake make git libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Build + install both OT protocol parsers from the Zeek package source.
RUN zkg install --force --skiptests icsnpp-opcua-binary icsnpp-s7comm \
    && zeek -N | grep -i icsnpp

# Site policy: load the plugins, JSON logs, no rotation.
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek

# Zeek writes logs to its CWD; mount the host ./logs here.
WORKDIR /logs

# Interface eth0 comes from the shared ews network namespace.
ENTRYPOINT ["zeek"]
CMD ["-i", "eth0", "local"]
