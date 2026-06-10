$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$cloudflared = "C:\Program Files (x86)\cloudflared\cloudflared.exe"

Write-Host "Starting BrokenArrowStats server..."
Start-Process powershell -ArgumentList @(
  "-NoExit",
  "-Command",
  "Set-Location '$project\work'; python broken_arrow_server.py"
) -WindowStyle Minimized

Start-Sleep -Seconds 2

if (-not (Test-Path $cloudflared)) {
  throw "cloudflared not found. Run: winget install Cloudflare.cloudflared"
}

Write-Host "Opening public tunnel..."
Write-Host "Keep this window open. Closing it takes the site offline."
& $cloudflared tunnel --url http://127.0.0.1:8787