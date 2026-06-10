$ErrorActionPreference = "Stop"
$git = "C:\Program Files\Git\bin\git.exe"
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$project = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $project

if (-not (Test-Path $git)) {
  throw "Git is not installed. Run: winget install Git.Git"
}
if (-not (Test-Path $gh)) {
  throw "GitHub CLI is not installed. Run: winget install GitHub.cli"
}

& $gh auth status *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Log into GitHub first..."
  & $gh auth login --web --git-protocol https
}

$repoName = "brokenarrowstats"
$existing = & $gh repo view $repoName --json name 2>$null
if (-not $existing) {
  Write-Host "Creating GitHub repo $repoName..."
  & $gh repo create $repoName --public --source . --remote origin --push
} else {
  Write-Host "Pushing latest changes..."
  & $git push -u origin main
}

Write-Host ""
Write-Host "GitHub repo is ready."
Write-Host "Next: open https://dashboard.render.com/select-repo?type=blueprint"
Write-Host "Connect your GitHub account, select '$repoName', and click Apply."
Write-Host "Render will read render.yaml and deploy the free web service."
Write-Host ""
Write-Host "IMPORTANT - persistent logins:"
Write-Host "Render free tier wipes JSON account files whenever the app restarts."
Write-Host "Create a free Neon Postgres database so accounts survive restarts:"
Write-Host "  1. Neon project connection string (not Data API):"
Write-Host "     https://console.neon.tech/app/projects/aged-credit-58533760/branches/br-misty-water-apatr3zh"
Write-Host "  2. Render dashboard -> brokenarrowstats -> Environment"
Write-Host "  3. Add DATABASE_URL = your Neon connection string"
Write-Host "  4. Save and redeploy"
Write-Host "  5. Check https://brokenarrowstats.onrender.com/api/health shows storage=postgres"
Write-Host ""
Write-Host "After DATABASE_URL is set, create your account again on the site."
Write-Host ""
Write-Host "Custom domain (use your real domain name):"
Write-Host "  .\setup-custom-domain.ps1 -Domain stats.yourdomain.com"