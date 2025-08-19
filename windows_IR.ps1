param(
  [string]$CaseId = (Get-Date -Format 'yyyyMMdd_HHmmss'),
  [int]$Days = 7,
  [string]$OutputPath = $env:SystemDrive,
  [switch]$Help
)

$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding  = [Text.UTF8Encoding]::new($false)
chcp 65001 | Out-Null

if ($Help) {
  "Usage: .\IR-Windows.ps1 -CaseId ""<ID>"" -Days <N> -OutputPath ""<PATH>"""
  "-CaseId     Case identifier (used in folder name)"
  "-Days       Lookback days for event logs (default: 7)"
  "-OutputPath Output root path (default: system drive)"
  "-Help       Show this help"
  exit
}

$ErrorActionPreference = 'SilentlyContinue'

$Root = Join-Path $OutputPath ("IR_{0}_{1}" -f $env:COMPUTERNAME, $CaseId)
$dirs = @(
  "00_info","10_accounts","20_process","30_services","40_drivers",
  "50_schtasks","60_startup","70_network","80_software","90_logs","99_hash"
) | ForEach-Object { Join-Path $Root $_ }
$null = $dirs | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ }

Function Out-Utf8($path, $data) { $data | Out-File -FilePath $path -Encoding UTF8 -Force }

$stamp = Get-Date -Format 'yyyy-MM-ddTHH-mm-ssK'
Out-Utf8 (Join-Path $Root "00_info\_IR_META.txt") @"
Host: $env:COMPUTERNAME
User: $env:USERNAME
When: $stamp
PS:   $($PSVersionTable.PSVersion)
"@

Get-ComputerInfo | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "00_info\computerinfo.csv")
Get-CimInstance Win32_OperatingSystem | Select-Object CSName,LastBootUpTime,InstallDate,OSArchitecture,Version,BuildNumber |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "00_info\os_boot.csv")
tzutil /g | Out-File -Encoding UTF8 (Join-Path $Root "00_info\timezone.txt")
w32tm /tz | Out-File -Encoding UTF8 (Join-Path $Root "00_info\w32tm_tz.txt")

Get-LocalUser | Select-Object Name,Enabled,LastLogon | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "10_accounts\local_users.csv")
Get-LocalGroup | Select-Object Name,Description | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "10_accounts\local_groups.csv")
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
  Select-Object ObjectClass,Name,PrincipalSource | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "10_accounts\local_admins.csv")
quser 2>&1 | Out-Utf8 (Join-Path $Root "10_accounts\quser.txt")
qwinsta 2>&1 | Out-Utf8 (Join-Path $Root "10_accounts\qwinsta.txt")

Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine,CreationDate,ExecutablePath |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "20_process\processes.csv")

Get-CimInstance Win32_Service |
  Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "30_services\services.csv")

Get-CimInstance Win32_SystemDriver |
  Select-Object Name,State,StartMode,PathName,Description |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "40_drivers\drivers.csv")

$tasks = Get-ScheduledTask
$tasks | ForEach-Object {
  $info = $_ | Get-ScheduledTaskInfo
  [PSCustomObject]@{
    TaskName = $_.TaskName
    TaskPath = $_.TaskPath
    State    = $info.State
    LastRun  = $info.LastRunTime
    NextRun  = $info.NextRunTime
    Author   = $_.Author
    Action   = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
  }
} | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "50_schtasks\scheduled_tasks.csv")

$runKeys = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$startup = foreach ($k in $runKeys) {
  if (Test-Path $k) {
    Get-ItemProperty -Path $k | Select-Object PSPath,* -ExcludeProperty PS*
  }
}
$startup | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "60_startup\registry_run.csv")

$autoCandidates = @(
  "$env:ProgramFiles\Sysinternals\autorunsc64.exe",
  "$env:ProgramFiles\Sysinternals\autorunsc.exe",
  "$PSScriptRoot\autorunsc64.exe",
  "$PSScriptRoot\autorunsc.exe"
)
$autorun = $autoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($autorun) {
  & $autorun -accepteula -a * -c -h -s -t *> (Join-Path $Root "60_startup\autoruns.csv")
} else {
  Out-Utf8 (Join-Path $Root "60_startup\_note.txt") "autorunsc.exe not found (optional)."
}

ipconfig /all 2>&1 | Out-Utf8 (Join-Path $Root "70_network\ipconfig_all.txt")
Get-DnsClientCache 2>$null | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "70_network\dns_cache.csv")
arp -a 2>&1 | Out-Utf8 (Join-Path $Root "70_network\arp.txt")
route print 2>&1 | Out-Utf8 (Join-Path $Root "70_network\route.txt")
Get-NetTCPConnection -State Listen,Established,TimeWait,CloseWait -ErrorAction SilentlyContinue |
  Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "70_network\nettcp.csv")
netstat -ano 2>&1 | Out-Utf8 (Join-Path $Root "70_network\netstat_ano.txt")
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Select-Object DisplayName,DisplayGroup,Enabled,Direction,Action |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "70_network\firewall_rules.csv")

$uninst = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
$apps = foreach ($p in $uninst) {
  if (Test-Path $p) {
    Get-ChildItem $p | ForEach-Object {
      Get-ItemProperty $_.PsPath | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
    }
  }
}
$apps | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "80_software\installed_apps.csv")
Get-HotFix | Select-Object HotFixID,InstalledOn,Description | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "80_software\hotfix.csv")

$Start = (Get-Date).AddDays(-$Days)
$secIds = 4624,4625,4672,4688,4720,4722,4723,4724,4725,4726,4728,4732,1102
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Start; Id=$secIds} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "90_logs\Security_recent.csv")

$sysIds = 7045,7036
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Start; Id=$sysIds} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "90_logs\System_recent.csv")

$evDir = Join-Path $Root "90_logs\EVTX"
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$logs = wevtutil el
foreach ($log in $logs) {
  $safe = ($log -replace '[\\/:\*\?\"<>\|]','_')
  wevtutil epl "$log" (Join-Path $evDir "$safe.evtx") 2>$null
}

Get-ChildItem "C:\Windows\Prefetch" -ErrorAction SilentlyContinue |
  Select-Object Name,Length,LastWriteTime |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "00_info\prefetch_list.csv")
Get-Item "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
  Select-Object FullName,Length,LastWriteTime |
  Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root "00_info\hosts_meta.csv")

$hashDir = Join-Path $Root "99_hash"
$hashOut = Join-Path $hashDir "hashes_sha256.csv"
New-Item -ItemType Directory -Force -Path $hashDir | Out-Null

function Try-GetFileHash {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateSet('SHA256','SHA1','MD5')][string]$Algorithm = 'SHA256',
        [int]$MaxRetry = 5,
        [int]$DelayMs = 300
    )
    for ($i=1; $i -le $MaxRetry; $i++) {
        try {
            return Get-FileHash -Algorithm $Algorithm -Path $Path -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds $DelayMs
        }
    }
    [PSCustomObject]@{ Path = $Path; Hash = 'FAILED' }
}

$filesToHash = Get-ChildItem -Recurse $Root -File |
               Where-Object { $_.DirectoryName -ne $hashDir }

$hashRows = foreach ($f in $filesToHash) {
    $h = Try-GetFileHash -Path $f.FullName -Algorithm SHA256
    if ($h -is [Microsoft.Powershell.Commands.FileHashInfo]) {
        [PSCustomObject]@{ Path = $h.Path; Hash = $h.Hash }
    } else {
        $h
    }
}

$hashRows | Sort-Object Path |
    Export-Csv -NoTypeInformation -Encoding UTF8 $hashOut

Write-Host "[OK] Complete: $Root"
