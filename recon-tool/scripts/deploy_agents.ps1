<#
deploy_agents.ps1
Copy updated agent scripts to a Windows or Linux VM (via scp) and restart agents via ssh.
Usage (PowerShell):
  .\deploy_agents.ps1 -Target user@host -RemotePath C:\\tools -Files .\agents\inventory_agent.py, .\agents\attacker.py

Notes:
- Requires OpenSSH server on the target (Windows 10+ has optional OpenSSH server).
- This script will copy files using scp and run PowerShell commands remotely via ssh to restart inventory.
#>
param(
  [Parameter(Mandatory=$true)] [string] $Target,
  [Parameter(Mandatory=$true)] [string] $RemotePath,
  [Parameter(Mandatory=$true)] [string[]] $Files
)

foreach ($f in $Files) {
  if (-Not (Test-Path $f)) {
    Write-Warning "Local file not found: $f"
    continue
  }
  Write-Host "Copying $f -> $Target:$RemotePath"
  scp $f "$Target:$RemotePath/"
}

# Restart inventory on remote Windows host (run a PowerShell command over ssh)
$psCmd = "powershell -NoProfile -Command \"Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like '*inventory_agent.py*' } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }; Start-Process -FilePath 'python' -ArgumentList '$RemotePath\\inventory_agent.py' -WindowStyle Hidden\""

ssh $Target $psCmd
Write-Host "Deployment complete. If attacker should be started, run the attacker start command manually on the target."