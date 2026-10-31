#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval pre-flight doctor (macOS / Linux / WSL2). Clear pass/warn/fail with fixes.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; WARN=0; FAIL=0
ok()  { printf '  \033[32m[ok]\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
warn(){ printf '  \033[33m[warn]\033[0m %s\n' "$1"; WARN=$((WARN+1)); }
bad() { printf '  \033[31m[fail]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }

echo "Kaaval doctor"
echo "-------------"

# OS / arch
echo "System:"
ok "OS=$(uname -s)  arch=$(uname -m)"
case "$(uname -s)" in
  Linux)  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && ok "running under WSL2" ;;
  Darwin) ok "macOS host" ;;
  *)      warn "unrecognized OS — Windows must use Docker Desktop + WSL2" ;;
esac

# Docker + compose + buildx
echo "Docker:"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    ok "docker daemon reachable ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"
  else
    bad "docker installed but daemon not reachable — start Docker and retry"
  fi
  docker compose version >/dev/null 2>&1 && ok "docker compose v2 ($(docker compose version --short 2>/dev/null))" \
    || bad "'docker compose' v2 missing — update Docker (legacy docker-compose v1 unsupported)"
  docker buildx version >/dev/null 2>&1 && ok "buildx present" \
    || warn "docker buildx missing — needed for multi-arch builds; install the buildx plugin"
else
  bad "docker not found — install Docker Desktop (Mac/Win) or Docker Engine (Linux)"
fi

# Docker memory + disk
if docker info >/dev/null 2>&1; then
  MEM=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
  GB=$(( MEM / 1024 / 1024 / 1024 ))
  if [ "$GB" -ge 8 ]; then ok "Docker memory ${GB} GB"; else warn "Docker memory ${GB} GB (<8 GB) — raise it in Docker Desktop → Resources (more for a local 30B model)"; fi
fi
DISK=$(df -Pk . 2>/dev/null | awk 'NR==2{print int($4/1024/1024)}')
[ -n "${DISK:-}" ] && { [ "$DISK" -ge 15 ] && ok "free disk ${DISK} GB" || warn "free disk ${DISK} GB (<15 GB) — the images + Zeek build need headroom"; }

# Ports
echo "Ports (127.0.0.1):"
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; } || return 1; }
for p in 8080 8000 8090 4840 1102 2222; do
  if port_busy "$p"; then
    docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$p->" && ok "port $p (in use by Kaaval)" \
      || warn "port $p is in use by another process — free it or change the 127.0.0.1:$p mapping in docker-compose.yml"
  else ok "port $p free"; fi
done

# .env + key
echo "Config:"
if [ -f .env ]; then
  ok ".env present"
  prov=$(grep -E '^KAAVAL_LLM_PROVIDER=' .env | head -1 | cut -d= -f2- | tr -d '[:space:]'); prov=${prov:-openrouter}
  key=$(grep -E '^OPENROUTER_API_KEY=' .env | head -1 | cut -d= -f2- | tr -d '[:space:]')
  if [ "$prov" = "local" ]; then ok "LLM provider = local (no key needed)"
  elif [ -n "$key" ]; then ok "OPENROUTER_API_KEY set"
  else warn "OPENROUTER_API_KEY empty — add one (https://openrouter.ai/keys), or set KAAVAL_LLM_PROVIDER=local. Stack still runs; agents degrade without it."; fi
else
  warn ".env missing — run 'cp .env.example .env' and add your key (or 'make up' creates it)"
fi

# Line endings
if grep -lU $'\r' scripts/*.sh setup.sh *.sh 2>/dev/null | grep -q .; then
  bad "CRLF line endings in shell scripts — re-clone inside WSL or run: git config core.autocrlf input && git checkout -- ."
else ok "shell scripts are LF"; fi

# Docker socket
docker ps >/dev/null 2>&1 && ok "docker socket usable (lab executor needs it)" \
  || warn "cannot use the docker socket — on Linux add your user to the 'docker' group (sudo usermod -aG docker \$USER; re-login)"

echo "-------------"
printf 'Summary: \033[32m%d ok\033[0m, \033[33m%d warn\033[0m, \033[31m%d fail\033[0m\n' "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -eq 0 ] && { echo "Ready — run 'make up'."; exit 0; } || { echo "Fix the [fail] items above, then re-run 'make doctor'."; exit 1; }
