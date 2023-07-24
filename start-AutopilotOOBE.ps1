Write-Host -ForegroundColor Green "Starting AutopilotOOBE"
Start-Sleep -Seconds 5

Install-Module -Name AutopilotOOBE -RequiredVersion 21.8.31.1 -Force -Verbose
Import-Module AutopilotOOBE -Force
Start-AutopilotOOBE