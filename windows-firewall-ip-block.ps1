[CmdletBinding()]
param(
  [string]$TargetIP,
  [string]$Direction = 'Inbound', 
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\BlockIP-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

if ($Arg1 -and -not $TargetIP) { $TargetIP = $Arg1 }
if ($Arg2 -and -not $Direction) { $Direction = $Arg2 }
if ($Arg3 -and -not $MaxWaitSeconds) { $MaxWaitSeconds = [int]$Arg3 }

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
  if (-not $TargetIP) { throw "TargetIP is required (no interactive input allowed)" }
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
  $json = $logObj | ConvertTo-Json -Compress -Depth 3
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $json -Encoding ascii -Force

  try {
    Remove-Item -Path $ARLog -Force -ErrorAction Stop
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Log file overwritten at $ARLog" 'INFO'
  }
  catch {
    Clear-Content -Path $ARLog -Force -ErrorAction SilentlyContinue
    Get-Content -Path $tempFile | Set-Content -Path $ARLog -Encoding ascii -Force
    Write-Log "Log file truncated and overwritten (lock fallback)" 'WARN'
  }
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
  $json = $logObj | ConvertTo-Json -Compress -Depth 3
  Set-Content -Path $ARLog -Value $json -Encoding ascii -Force
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
