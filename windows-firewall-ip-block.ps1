[CmdletBinding()]
param(
  [string]$Direction = 'Inbound',  # Can be Inbound or Outbound
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\BlockIP-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
 param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
 $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
 $line="[$ts][$Level] $Message"
 switch($Level){
  'ERROR' { Write-Host $line -ForegroundColor Red }
  'WARN'  { Write-Host $line -ForegroundColor Yellow }
  'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
  default { Write-Host $line }
 }
 Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
 if(Test-Path $LogPath -PathType Leaf){
  if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
   for($i=$LogKeep-1;$i -ge 0;$i--){
    $old="$LogPath.$i";$new="$LogPath."+($i+1)
    if(Test-Path $old){Rename-Item $old $new -Force}
   }
   Rename-Item $LogPath "$LogPath.1" -Force
  }
 }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Block IP ==="

try {

  $TargetIP = Read-Host "Enter IP address to block"

  if ($TargetIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
    throw "Invalid IPv4 address format: $TargetIP"
  }

  $RuleName = "Block_$($TargetIP.Replace('.','_'))"
  Write-Log "Target IP: $TargetIP"
  Write-Log "Direction: $Direction"
  Write-Log "Rule name: $RuleName"

  $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Log "Firewall rule '$RuleName' already exists" 'WARN'
    $status = "already_exists"
  }
  else {
    New-NetFirewallRule -DisplayName $RuleName `
                        -Direction $Direction `
                        -Action Block `
                        -RemoteAddress $TargetIP `
                        -Protocol Any `
                        -Enabled True `
                        -Profile Any | Out-Null
    Write-Log "Created firewall rule to block $TargetIP ($Direction)" 'INFO'
    $status = "blocked"
  }


  $logObj = [pscustomobject]@{
    timestamp    = (Get-Date).ToString('o')
    host         = $HostName
    action       = "block_ip"
    target_ip    = $TargetIP
    direction    = $Direction
    rule_name    = $RuleName
    status       = $status
  }

  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  Write-Log "JSON appended to $ARLog" 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $logObj = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host      = $HostName
    action    = "block_ip"
    status    = "error"
    error     = $_.Exception.Message
  }
  $logObj | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
