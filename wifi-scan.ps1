param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath("Desktop")) "wifi-scan.json")
)

# Auto-elevate to Administrator if required by Windows Wi-Fi APIs
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] กำลังขอสิทธิ์ Administrator เพื่อเข้าถึง Wi-Fi Hardware API..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -OutputPath `"$OutputPath`"" -Verb RunAs
        exit
    }
}

$ErrorActionPreference = "Continue"

function Get-NetshValue {
    param([string[]]$Lines, [string]$Label)
    foreach ($line in $Lines) {
        if ($line -match "^\s*$([regex]::Escape($Label))\s*:\s*(.+?)\s*$") {
            return $Matches[1].Trim()
        }
    }
    return $null
}

function Get-SignalPercent {
    param([string]$Value)
    if ($Value -match "(\d{1,3})") {
        return [Math]::Max(0, [Math]::Min(100, [int]$Matches[1]))
    }
    return 0
}

Write-Host "[+] กำลังสแกนสัญญาณ Wi-Fi ในบริเวณใกล้เคียง..." -ForegroundColor Cyan

# 1. อ่านข้อมูลเครือข่ายที่กำลังเชื่อมต่ออยู่ (Connected Interface)
$connectedSsid = $null
$connectedAuth = "UNKNOWN"
$connectedCipher = "UNKNOWN"
$connectedSignal = 0
$interfaceLines = @(netsh wlan show interfaces 2>&1 | ForEach-Object { [string]$_ })
$blocks = @()
$currentBlock = @()
foreach ($line in $interfaceLines) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        if ($currentBlock.Count -gt 0) { $blocks += ,$currentBlock }
        $currentBlock = @()
    } else {
        $currentBlock += $line
    }
}
if ($currentBlock.Count -gt 0) { $blocks += ,$currentBlock }

foreach ($block in $blocks) {
    $blockState = Get-NetshValue -Lines $block -Label "State"
    if ($blockState -and $blockState.Trim() -ieq "connected") {
        $connectedSsid = Get-NetshValue -Lines $block -Label "SSID"
        $connectedAuth = Get-NetshValue -Lines $block -Label "Authentication"
        $connectedCipher = Get-NetshValue -Lines $block -Label "Cipher"
        $connectedSignal = Get-SignalPercent (Get-NetshValue -Lines $block -Label "Signal")
        break
    }
}

# 2. อ่านข้อมูลสัญญาณ Wi-Fi ทั้งหมดรอบข้าง (Available Networks)
$availableNetworks = @()
$networksOutput = @(netsh wlan show networks mode=bssid 2>&1 | ForEach-Object { [string]$_ })
if ($networksOutput -match "requires elevation") {
    $networksOutput = @(netsh wlan show networks 2>&1 | ForEach-Object { [string]$_ })
}

$currentSsid = $null
$currentAuth = "UNKNOWN"
$currentCipher = "UNKNOWN"
$currentSignal = 60

foreach ($line in $networksOutput) {
    if ($line -match "^SSID\s+\d+\s*:\s*(.+)$") {
        if ($currentSsid) {
            $hasPass = ($currentAuth.ToUpper() -notmatch "OPEN|NONE") -and ($currentCipher.ToUpper() -notmatch "NONE")
            $isConn = ($connectedSsid -and $currentSsid -eq $connectedSsid)
            $availableNetworks += [pscustomobject]@{
                ssid = $currentSsid
                authentication = $currentAuth
                cipher = $currentCipher
                signalQualityPercent = $currentSignal
                hasPassword = [bool]$hasPass
                isConnected = [bool]$isConn
            }
        }
        $currentSsid = $Matches[1].Trim()
        $currentAuth = "UNKNOWN"
        $currentCipher = "UNKNOWN"
        $currentSignal = 60
    }
    elseif ($line -match "^\s*Authentication\s*:\s*(.+)$") {
        $currentAuth = $Matches[1].Trim()
    }
    elseif ($line -match "^\s*Encryption\s*:\s*(.+)$") {
        $currentCipher = $Matches[1].Trim()
    }
    elseif ($line -match "^\s*Signal\s*:\s*(\d+)%") {
        $currentSignal = [int]$Matches[1]
    }
}

# บันทึก SSID ตัวสุดท้ายในลูป
if ($currentSsid) {
    $hasPass = ($currentAuth.ToUpper() -notmatch "OPEN|NONE") -and ($currentCipher.ToUpper() -notmatch "NONE")
    $isConn = ($connectedSsid -and $currentSsid -eq $connectedSsid)
    $availableNetworks += [pscustomobject]@{
        ssid = $currentSsid
        authentication = $currentAuth
        cipher = $currentCipher
        signalQualityPercent = $currentSignal
        hasPassword = [bool]$hasPass
        isConnected = [bool]$isConn
    }
}

# ถ้าไม่มีสัญญาณรอบข้างที่ parse ได้ ให้ใช้ connected network เป็น fallback
if ($availableNetworks.Count -eq 0 -and $connectedSsid) {
    $hasPass = ($connectedAuth.ToUpper() -notmatch "OPEN|NONE") -and ($connectedCipher.ToUpper() -notmatch "NONE")
    $availableNetworks += [pscustomobject]@{
        ssid = $connectedSsid
        authentication = $connectedAuth
        cipher = $connectedCipher
        signalQualityPercent = $connectedSignal
        hasPassword = [bool]$hasPass
        isConnected = $true
    }
}

$primarySsid = if ($connectedSsid) { $connectedSsid } elseif ($availableNetworks.Count -gt 0) { $availableNetworks[0].ssid } else { "Unknown" }
$primaryAuth = if ($connectedSsid) { $connectedAuth } elseif ($availableNetworks.Count -gt 0) { $availableNetworks[0].authentication } else { "UNKNOWN" }
$primaryCipher = if ($connectedSsid) { $connectedCipher } elseif ($availableNetworks.Count -gt 0) { $availableNetworks[0].cipher } else { "UNKNOWN" }
$primarySignal = if ($connectedSsid) { $connectedSignal } elseif ($availableNetworks.Count -gt 0) { $availableNetworks[0].signalQualityPercent } else { 70 }

$scan = [ordered]@{
    schemaVersion = 2
    capturedAtUtc = [DateTime]::UtcNow.ToString("o")
    interfaceName = "netsh wlan"
    ssid = $primarySsid
    signalQualityPercent = $primarySignal
    authentication = $primaryAuth
    cipher = $primaryCipher
    securityEnabled = ($primaryAuth.ToUpper() -notmatch "OPEN|NONE")
    availableNetworks = $availableNetworks
}

$json = ConvertTo-Json -InputObject ([pscustomobject]$scan) -Depth 5
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [System.IO.Directory]::Exists($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
[System.IO.File]::WriteAllText($resolvedOutputPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  สแกนสัญญาณ Wi-Fi สำเร็จ! ตรวจพบ $($availableNetworks.Count) เครือข่าย" -ForegroundColor Green
Write-Host "  บันทึกรายงานไว้ที่: $resolvedOutputPath" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
