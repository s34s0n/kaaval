# Kaaval prerequisite check + .env bootstrap (Windows 11 + Docker Desktop + WSL2).
# Run from PowerShell in the repo root:  ./setup.ps1
$ErrorActionPreference = "Stop"
$fail = $false

function Ok($m)   { Write-Host "[OK] $m"   -ForegroundColor Green }
function Warn($m) { Write-Host "[..] $m"   -ForegroundColor Yellow }
function Err($m)  { Write-Host "[XX] $m"   -ForegroundColor Red }

# 1) Docker daemon
try {
  $ver = (docker version --format '{{.Server.Version}}') 2>$null
  if ([string]::IsNullOrWhiteSpace($ver)) { throw "no daemon" }
  Ok "Docker daemon $ver"
} catch {
  Err "Docker is not running. Install Docker Desktop with the WSL2 backend and start it."
  $fail = $true
}

# 2) Compose v2
try {
  docker compose version | Out-Null
  Ok "docker compose v2 available"
} catch {
  Err "'docker compose' (v2) not available. Update Docker Desktop."
  $fail = $true
}

# 3) .env
if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Warn "created .env from .env.example"
}

# 4) LLM key
$envText  = Get-Content ".env"
$provLine = ($envText | Select-String '^KAAVAL_LLM_PROVIDER=').ToString()
$provider = if ($provLine) { ($provLine -split '=',2)[1].Trim() } else { "openrouter" }
$keyLine  = ($envText | Select-String '^OPENROUTER_API_KEY=').ToString()
$key      = if ($keyLine) { ($keyLine -split '=',2)[1].Trim() } else { "" }
if ($provider -eq "openrouter" -and [string]::IsNullOrWhiteSpace($key)) {
  Warn "OPENROUTER_API_KEY is empty in .env — add one from https://openrouter.ai/keys"
  Warn "(The stack still runs and incidents still form & gate without it.)"
} else {
  Ok "LLM provider = $provider"
}

if ($fail) {
  Err "Prerequisites missing — fix the [XX] items above, then run: docker compose up -d --build"
  exit 1
}
Ok "Ready. Run:  docker compose up -d --build"
