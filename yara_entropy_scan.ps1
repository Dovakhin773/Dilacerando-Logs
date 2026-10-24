# ==============================================================================
# Wazuh Active Response - YARA Math & Entropy Scanner para Windows
# Destino: C:\Program Files (x86)\ossec-agent\active-response\bin\yara_entropy_scan.ps1
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Le o JSON passado pelo Wazuh Agent via stdin
$inputJson = [Console]::In.ReadToEnd()
if (-not $inputJson) { exit 0 }

try {
    $parsed = $inputJson | ConvertFrom-Json -ErrorAction Stop
    $targetFile = $parsed.parameters.alert.syscheck.path
    if (-not $targetFile) {
        $targetFile = $parsed.parameters.alert.data.file
    }
} catch {
    exit 0
}

if (-not $targetFile -or -not (Test-Path $targetFile)) {
    exit 0
}

# Pausa breve para garantir que a gravacao em disco foi concluida
Start-Sleep -Seconds 1

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$YaraRules = "C:\Program Files (x86)\ossec-agent\ruleset\yara\entropy_hunting.yar"

if (-not (Test-Path $YaraRules)) {
    exit 0
}

# Procura binario do YARA
$yaraExe = "C:\Program Files (x86)\ossec-agent\active-response\bin\yara64.exe"
if (-not (Test-Path $yaraExe)) {
    $yaraCmd = Get-Command "yara64.exe" -ErrorAction SilentlyContinue
    if (-not $yaraCmd) { $yaraCmd = Get-Command "yara.exe" -ErrorAction SilentlyContinue }
    if ($yaraCmd) { $yaraExe = $yaraCmd.Source }
}

if (-not (Test-Path $yaraExe)) {
    exit 0
}

# Executa o YARA contra o arquivo
$yaraOutput = & $yaraExe -m "$YaraRules" "$targetFile" 2>$null

if ($yaraOutput) {
    # Calculo nativo da Entropia de Shannon em .NET
    $bytes = [System.IO.File]::ReadAllBytes($targetFile)
    $n = $bytes.Length
    $entropy = 0.0
    if ($n -gt 0) {
        $freq = @{}
        foreach ($b in $bytes) { $freq[$b] = $freq[$b] + 1 }
        foreach ($count in $freq.Values) {
            $p = $count / $n
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }
    $fileEntropy = ("{0:N4}" -f $entropy).Replace(",", ".")

    $timestamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    foreach ($line in $yaraOutput) {
        $parts = $line -split '\s+'
        $ruleName = $parts[0]
        $metaInfo = ($parts[1..($parts.Length - 2)]) -join ' '
        $logLine = "$timestamp wazuh-yara-entropy: INFO - scan_result: matched | yara_rule: $ruleName | file_entropy: $fileEntropy | target_file: $targetFile | meta: $metaInfo"
        Add-Content -Path $LogFile -Value $logLine -Encoding utf8
    }
}

exit 0
