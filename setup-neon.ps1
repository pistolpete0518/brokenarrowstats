param(
  [string]$DatabaseUrl = $env:DATABASE_URL
)

$ErrorActionPreference = "Stop"
$neonProject = "https://console.neon.tech/app/projects/aged-credit-58533760/branches/br-misty-water-apatr3zh"
$renderService = "https://dashboard.render.com"

Write-Host "BrokenArrowStats + Neon setup"
Write-Host ""
Write-Host "Important: use the Postgres CONNECTION STRING, not the Data API page."
Write-Host "In Neon, open Dashboard -> Connection details -> copy the connection string."
Write-Host ""

if ($DatabaseUrl) {
  $env:DATABASE_URL = $DatabaseUrl
  Write-Host "Testing DATABASE_URL..."
  python -c "import sys, json; sys.path.insert(0, 'work'); from db_store import test_database_connection; print(json.dumps(test_database_connection(), indent=2))"
  if ($LASTEXITCODE -ne 0) {
    throw "Database test failed."
  }
  Write-Host ""
  Write-Host "Connection works locally. Add the same DATABASE_URL to Render:"
} else {
  Write-Host "No DATABASE_URL provided yet."
  Write-Host "1. Open Neon connection details and copy the connection string."
  Write-Host "2. Run:"
  Write-Host '   .\setup-neon.ps1 -DatabaseUrl "postgresql://USER:PASSWORD@HOST/DB?sslmode=require"'
  Write-Host ""
}

Write-Host "Render steps:"
Write-Host "  1. Open Render dashboard -> brokenarrowstats -> Environment"
Write-Host "  2. Add DATABASE_URL = your Neon connection string"
Write-Host "  3. Save and redeploy"
Write-Host "  4. Check https://brokenarrowstats.onrender.com/api/health"
Write-Host "     It must show: `"storage`": `"postgres`" and `"ok`": true"
Write-Host "  5. Create your account again on the site"
Write-Host ""

Start-Process $neonProject
Start-Process $renderService