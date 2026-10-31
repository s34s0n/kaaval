# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval pre-flight doctor (Windows 11 + Docker Desktop + WSL2). Run: ./scripts/doctor.ps1
$pass = 0; $warn = 0; $fail = 0
function Ok($m)   { Write-Host "  [ok]   $m" -ForegroundColor Green;  $script:pass++ }
function Warn($m) { Write-Host "  [warn] $m" -ForegroundColor Yellow; $script:warn++ }
function Bad($m)  { Write-Host "  [fail] $m" -ForegroundColor Red;    $script:fail++ }

Set-Location (Join-Path $PSScriptRoot "..")
Write-Host "Kaaval doctor`n-------------"

Write-Host "System:"
Ok ("OS=Windows  arch=" + $env:PROCESSOR_ARCHITECTURE)
Warn "Windows must use the Docker Desktop WSL2 backend; clone this repo inside WSL (or keep LF line endings)."

Write-Host "Docker:"
try {
  $v = (docker version --format '{{.Server.Version}}') 2>$null
  if ([string]::IsNullOrWhiteSpace($v)) { throw }
  Ok "docker daemon reachable ($v)"
} catch { Bad "docker daemon not reachable — start Docker Desktop (WSL2 backend) and retry" }
try { docker compose version | Out-Null; Ok "docker compose v2 present" } catch { Bad "'docker compose' v2 missing — update Docker Desktop" }
try { docker buildx version | Out-Null; Ok "buildx present" } catch { Warn "docker buildx missing — needed for multi-arch builds" }

try {
  $mem = [int64](docker info --format '{{.MemTotal}}')
  $gb = [math]::Floor($mem / 1GB)
  if ($gb -ge 8) { Ok "Docker memory $gb GB" } else { Warn "Docker memory $gb GB (<8 GB) — raise it in Docker Desktop -> Resources" }
} catch {}

Write-Host "Ports (127.0.0.1):"
foreach ($p in 8080,8000,8090,4840,1102,2222) {
  $busy = Test-NetConnection -ComputerName 127.0.0.1 -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet
  if ($busy) { Warn "port $p in use — free it or change the 127.0.0.1:$p mapping in docker-compose.yml" } else { Ok "port $p free" }
}

Write-Host "Config:"
if (Test-Path ".env") {
  Ok ".env present"
  $txt = Get-Content ".env"
  $prov = ($txt | Select-String '^KAAVAL_LLM_PROVIDER=' | ForEach-Object { ($_ -split '=',2)[1].Trim() })
  if (-not $prov) { $prov = "openrouter" }
  $key  = ($txt | Select-String '^OPENROUTER_API_KEY=' | ForEach-Object { ($_ -split '=',2)[1].Trim() })
  if ($prov -eq "local") { Ok "LLM provider = local (no key needed)" }
  elseif ($key) { Ok "OPENROUTER_API_KEY set" }
  else { Warn "OPENROUTER_API_KEY empty — add one (https://openrouter.ai/keys) or set KAAVAL_LLM_PROVIDER=local" }
} else { Warn ".env missing — run: Copy-Item .env.example .env ; then add your key" }

Write-Host "-------------"
Write-Host ("Summary: {0} ok, {1} warn, {2} fail" -f $pass, $warn, $fail)
if ($fail -eq 0) { Write-Host "Ready — run 'docker compose up -d --build' (or 'make up' in WSL)."; exit 0 }
else { Write-Host "Fix the [fail] items above and re-run."; exit 1 }
