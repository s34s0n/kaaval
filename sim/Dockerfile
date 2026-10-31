# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval simulator image — runs either the PLC (plc.py) or the gateway
# (gateway.py); the command is chosen per service in docker-compose.yml.
# python-snap7 3.0 and asyncua are pure Python, so no build toolchain is needed.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tagspec.py tags.py process_model.py plc.py gateway.py ./
COPY processes/ ./processes/

# PLC serves S7comm on 102; gateway serves OPC UA on 4840.
EXPOSE 102 4840

# Default to the PLC; the gateway service overrides `command`.
CMD ["python", "plc.py"]
