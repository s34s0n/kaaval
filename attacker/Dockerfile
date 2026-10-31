# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval attacker — red-team service with an HTTP API.
# Gains initial access by SSH into the ews, then drives each ATT&CK-tagged stage
# as a command on the ews (needs an SSH client + sshpass).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py attacks.py ./

EXPOSE 8090
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8090"]
