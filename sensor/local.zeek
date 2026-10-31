# Kaaval sensor site policy.
# Loads the two ICSNPP OT analyzers on top of Zeek's default IT analyzers
# (conn/dns/ssl/ssh load automatically) and writes newline-delimited JSON to
# the working dir (/logs) with rotation off, so the backend can tail stable
# filenames.

@load icsnpp/opcua-binary
@load icsnpp/s7comm

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0secs;

# Docker virtual NICs offload TCP/UDP checksums, so captured packets carry
# "bad" checksums and Zeek would skip payload reassembly (conn.log fills but no
# ssh/ssl/opcua/s7comm logs). Ignore checksums so app-layer analyzers fire.
redef ignore_checksums = T;
