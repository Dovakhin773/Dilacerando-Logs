<#
==============================================================================
SIMULADOR AO VIVO (WINDOWS): "DILACERANDO LOGS, CUSPINDO ENTROPIA"
Como usar na aula:
    powershell -ExecutionPolicy Bypass -File .\simulador_aula_entropia.ps1
==============================================================================
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Live Demo: Dilacerando Logs, Cuspindo Entropia (YARA Math + Wazuh)"

$LabDir = "$env:TEMP\aula_entropia"
if (-not (Test-Path $LabDir)) {
    New-Item -ItemType Directory -Path $LabDir -Force | Out-Null
} else {
    Get-ChildItem -Path $LabDir -File | Remove-Item -Force
}

# Localizacao da regra YARA
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$YaraRuleFile = Join-Path $ScriptDir "..\yara\entropy_hunting.yar"
if (-not (Test-Path $YaraRuleFile)) {
    $YaraRuleFile = "C:\Program Files (x86)\ossec-agent\ruleset\yara\entropy_hunting.yar"
}
if (-not (Test-Path $YaraRuleFile)) {
    $YaraRuleFile = ".\yara\entropy_hunting.yar"
}
if (-not (Test-Path $YaraRuleFile)) {
    $YaraRuleFile = ".\entropy_hunting.yar"
}

# Funcao de calculo nativo de Entropia de Shannon em .NET puro (sem depender de Python!)
function Get-ShannonEntropy {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return "0.0000 bits/byte (Arquivo nao encontrado)" }
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $n = $bytes.Length
    if ($n -eq 0) { return "0.0000 bits/byte (Vazio)" }
    
    $freq = @{}
    foreach ($b in $bytes) {
        $freq[$b] = $freq[$b] + 1
    }
    
    $entropy = 0.0
    foreach ($count in $freq.Values) {
        $p = $count / $n
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return ("{0:N4} bits/byte (Tamanho: {1} bytes)" -f $entropy, $n)
}

# Funcao auxiliar para executar o YARA
function Invoke-YaraScan {
    param([string]$FilePath, [switch]$ShowStrings)
    
    $yaraCmd = Get-Command "yara64.exe" -ErrorAction SilentlyContinue
    if (-not $yaraCmd) { $yaraCmd = Get-Command "yara.exe" -ErrorAction SilentlyContinue }
    if (-not $yaraCmd) { 
        $commonPaths = @(
            "C:\ProgramData\chocolatey\bin\yara64.exe",
            "C:\Program Files\yara\yara64.exe",
            "C:\yara\yara64.exe",
            "C:\Program Files (x86)\ossec-agent\active-response\bin\yara.exe"
        )
        foreach ($p in $commonPaths) {
            if (Test-Path $p) { $yaraCmd = $p; break }
        }
    }

    if ($yaraCmd -and (Test-Path $YaraRuleFile)) {
        if ($ShowStrings) {
            & $yaraCmd -s "$YaraRuleFile" "$FilePath"
        } else {
            & $yaraCmd -m "$YaraRuleFile" "$FilePath"
        }
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [OK] Nenhuma regra disparou (Zero Falso Positivo!)" -ForegroundColor Green
        }
    } else {
        Write-Host "    [INFO] YARA nao encontrado no PATH para executar a regra automaticamente." -ForegroundColor DarkYellow
        Write-Host "    (Dica: Instale com 'choco install yara' ou baixe em github.com/VirusTotal/yara/releases)" -ForegroundColor DarkGray
    }
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   LIVE DEMO WINDOWS: DILACERANDO LOGS, CUSPINDO ENTROPIA (YARA MATH) " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Diretorio do Lab: $LabDir" -ForegroundColor DarkGray
Write-Host "Regra YARA:       $YaraRuleFile" -ForegroundColor DarkGray
Write-Host ""

# ------------------------------------------------------------------------------
# CENARIO 1: ARQUIVO E LOG LEGITIMO (BASELINE)
# ------------------------------------------------------------------------------
Write-Host "[CENARIO 1] Gerando Script Administrativo e Log DNS Legitimos (Baseline)..." -ForegroundColor Green

$file1Path = Join-Path $LabDir "1_backup_legitimo.ps1"
@"
# Script de Backup Administrativo do Active Directory
`$LogDir = "C:\inetpub\logs\LogFiles"
`$BackupDir = "D:\Backups\Logs"
Write-Output "Iniciando compactacao diaria dos logs..."
Compress-Archive -Path `$LogDir -DestinationPath "`$BackupDir\iis_logs.zip" -Force
Write-Output "Backup concluido com sucesso."
"@ | Out-File -FilePath $file1Path -Encoding utf8

$fileLogNormal = Join-Path $LabDir "1_dns_corporativo_normal.log"
@"
2026-10-23T17:10:01Z client 10.0.0.15 query: portal.empresa.com.br IN A
2026-10-23T17:10:02Z client 10.0.0.15 query: login.microsoftonline.com IN A
2026-10-23T17:10:04Z client 10.0.0.22 query: api.github.com IN A
2026-10-23T17:10:09Z client 10.0.0.40 query: windowsupdate.microsoft.com IN A
"@ | Out-File -FilePath $fileLogNormal -Encoding utf8

Write-Host " -> Entropia de 1_backup_legitimo.ps1:     $((Get-ShannonEntropy $file1Path))" -ForegroundColor Gray
Write-Host " -> Entropia de 1_dns_corporativo_normal: $((Get-ShannonEntropy $fileLogNormal))" -ForegroundColor Gray
Write-Host " -> Resultado do YARA nos arquivos legitimos:"
Invoke-YaraScan $file1Path

Write-Host ""
Read-Host "Pressione [ENTER] para lancar o CENARIO 2 (Binario PE Empacotado/Crypter)..."

# ------------------------------------------------------------------------------
# CENARIO 2: BINARIO PE EMPACOTADO / CRIPTOGRAFADO (ALTA ENTROPIA)
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[CENARIO 2] Simulando Dropper PE Empacotado (Header MZ + 32KB Cifrado com CSPRNG)..." -ForegroundColor Yellow

$file2Path = Join-Path $LabDir "2_svchost_packed.exe"
$mzBytes = [byte[]](0x4D, 0x5A)
$randomBytes = New-Object byte[] 32768
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($randomBytes)

$fileStream = [System.IO.File]::Create($file2Path)
$fileStream.Write($mzBytes, 0, $mzBytes.Length)
$fileStream.Write($randomBytes, 0, $randomBytes.Length)
$fileStream.Close()

Write-Host " -> Entropia de 2_svchost_packed.exe:     $((Get-ShannonEntropy $file2Path))" -ForegroundColor Gray
Write-Host " -> Resultado do YARA (Esperado: SUSP_Packed_Or_Encrypted_PE_Entropy):" -ForegroundColor Red
Invoke-YaraScan $file2Path

Write-Host ""
Read-Host "Pressione [ENTER] para lancar o CENARIO 3 (Script PowerShell Ofuscado em Base64)..."

# ------------------------------------------------------------------------------
# CENARIO 3: SCRIPT POWERSHELL OFUSCADO / BASE64 MASSIVO
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[CENARIO 3] Simulando Script PowerShell com Payload Ofuscado (Base64 de Alta Entropia)..." -ForegroundColor Yellow

$rawSecret = New-Object byte[] 4096
$rng.GetBytes($rawSecret)
$b64Payload = [Convert]::ToBase64String($rawSecret)

$file3Path = Join-Path $LabDir "3_stage2_loader.ps1"
@"
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $b64Payload
"@ | Out-File -FilePath $file3Path -Encoding ascii

Write-Host " -> Entropia de 3_stage2_loader.ps1:      $((Get-ShannonEntropy $file3Path))" -ForegroundColor Gray
Write-Host " -> Resultado do YARA (Esperado: SUSP_Obfuscated_Script_High_Entropy):" -ForegroundColor Red
Invoke-YaraScan $file3Path

Write-Host ""
Read-Host "Pressione [ENTER] para lancar o CENARIO 4 (Artefato Criptografado por Ransomware)..."

# ------------------------------------------------------------------------------
# CENARIO 4: ARTEFATO CIFRADO POR RANSOMWARE (SEM CABECALHO CONHECIDO)
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[CENARIO 4] Simulando Arquivo Criptografado por Ransomware (.locked com Alta Entropia)..." -ForegroundColor Yellow

$file4Path = Join-Path $LabDir "4_planilha_financeira.xlsx.locked"
$lockedBytes = New-Object byte[] 65536
$rng.GetBytes($lockedBytes)
[System.IO.File]::WriteAllBytes($file4Path, $lockedBytes)

Write-Host " -> Entropia de 4_planilha_financeira.xlsx.locked: $((Get-ShannonEntropy $file4Path))" -ForegroundColor Gray
Write-Host " -> Resultado do YARA (Esperado: SUSP_Encrypted_Drop_Or_Ransomware_Artifact):" -ForegroundColor Red
Invoke-YaraScan $file4Path

Write-Host ""
Read-Host "Pressione [ENTER] para lancar o CENARIO 5 (Dilacerando Logs de DNS com DGA e Exfiltracao)..."

# ------------------------------------------------------------------------------
# CENARIO 5: DILACERANDO LOGS DE DNS (DGA & DNS TUNNELING) E NOMES ALEATORIOS
# ------------------------------------------------------------------------------
Write-Host ""
Write-Host "[CENARIO 5] Injetando Logs com Dominios DGA / Tunneling e Dropper em C:\Users\Public\..." -ForegroundColor Yellow

$fileLogAttack = Join-Path $LabDir "5_dns_dga_tunneling_attack.log"
@"
2026-10-23T17:15:01Z client 10.0.0.15 query: intranet.corporativa.local IN A
2026-10-23T17:15:02Z client 10.0.0.99 query: x9k2m7q8z1v4b6n3p0w5r2t8y1u4i7o0.evilc2.top IN A
2026-10-23T17:15:03Z client 10.0.0.99 query: a8F3kL9zQ2mN7vB4xC1wP0rT6yU5jH8gD2s.c2-tunnel.xyz IN TXT
2026-10-23T17:15:05Z client 10.0.0.99 file_created: C:\Users\Public\9f86d081884c7d659a2feaa0c55ad015.exe
"@ | Out-File -FilePath $fileLogAttack -Encoding utf8

Write-Host " -> Entropia global do arquivo de log:    $((Get-ShannonEntropy $fileLogAttack))" -ForegroundColor Gray
Write-Host "    (Repare que o log inteiro tem entropia moderada, mas o YARA isola CADA trecho com @offset e !length!)" -ForegroundColor DarkCyan
Write-Host " -> Resultado do YARA (Esperado: DGA e Random Filename):" -ForegroundColor Red
Invoke-YaraScan $fileLogAttack -ShowStrings

Write-Host ""
Write-Host "[CONCLUIDO] Todos os 5 cenarios foram executados com sucesso!" -ForegroundColor Green
Write-Host "Artefatos gerados em $LabDir para teste do FIM + Active Response!" -ForegroundColor Green
