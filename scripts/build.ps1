Param(
  [switch]$Check
)

Write-Host "==> Building packages" -ForegroundColor Cyan
python -m build

if ($Check) {
  Write-Host "==> Checking artifacts with twine" -ForegroundColor Cyan
  python -m twine check dist/*
}

Write-Host "Done. Artifacts in ./dist" -ForegroundColor Green

