#!/bin/bash
# ==============================================================================
# SIMULADOR AO VIVO (LINUX): "DILACERANDO LOGS, CUSPINDO ENTROPIA"
# Como usar na aula:
#   chmod +x simulador_aula_entropia.sh
#   ./simulador_aula_entropia.sh
# ==============================================================================

LAB_DIR="/tmp/aula_entropia"
YARA_RULE_FILE="/var/ossec/ruleset/yara/entropy_hunting.yar"

# Fallback caso queira rodar o script fora do servidor do Wazuh (apenas com YARA local)
if [ ! -f "$YARA_RULE_FILE" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/../yara/entropy_hunting.yar" ]; then
        YARA_RULE_FILE="$SCRIPT_DIR/../yara/entropy_hunting.yar"
    elif [ -f "./yara/entropy_hunting.yar" ]; then
        YARA_RULE_FILE="./yara/entropy_hunting.yar"
    else
        YARA_RULE_FILE="./entropy_hunting.yar"
    fi
fi

mkdir -p "$LAB_DIR"
rm -f "$LAB_DIR"/*

# Funcao auxiliar para mostrar a entropia na tela durante a aula
calc_entropy() {
    python3 -c "
import math, sys
from collections import Counter
try:
    data = open(sys.argv[1], 'rb').read()
    n = len(data)
    e = -sum((c/n) * math.log2(c/n) for c in Counter(data).values()) if n else 0
    print(f'{e:.4f} bits/byte (Tamanho: {n} bytes)')
except Exception:
    print('N/A')
" "$1"
}

echo -e "\033[1;36m======================================================================\033[0m"
echo -e "\033[1;36m   LIVE DEMO: DILACERANDO LOGS, CUSPINDO ENTROPIA (YARA MATH + WAZUH) \033[0m"
echo -e "\033[1;36m======================================================================\033[0m"
echo "Diretório do Lab: $LAB_DIR"
echo "Regra YARA:       $YARA_RULE_FILE"
echo ""

# ------------------------------------------------------------------------------
# CENARIO 1: ARQUIVO E LOG LEGITIMO (BASELINE)
# ------------------------------------------------------------------------------
echo -e "\033[1;32m[CENARIO 1] Gerando Script Administrativo e Log DNS Legitimos (Baseline)...\033[0m"
cat << 'EOF' > "$LAB_DIR/1_backup_legitimo.sh"
#!/bin/bash
# Script de rotacao de logs corporativos
LOG_DIR="/var/log/nginx"
BACKUP_DIR="/mnt/backups/nginx"
echo "Iniciando backup diario dos logs de acesso..."
tar -czf "$BACKUP_DIR/access_logs.tar.gz" "$LOG_DIR/access.log"
echo "Backup finalizado com sucesso."
EOF

cat << 'EOF' > "$LAB_DIR/1_dns_corporativo_normal.log"
2026-10-23T17:10:01Z client 10.0.0.15 query: portal.empresa.com.br IN A
2026-10-23T17:10:02Z client 10.0.0.15 query: login.microsoftonline.com IN A
2026-10-23T17:10:04Z client 10.0.0.22 query: api.github.com IN A
2026-10-23T17:10:09Z client 10.0.0.40 query: updates.ubuntu.com IN A
EOF

echo " -> Entropia de 1_backup_legitimo.sh:       $(calc_entropy "$LAB_DIR/1_backup_legitimo.sh")"
echo " -> Entropia de 1_dns_corporativo_normal:   $(calc_entropy "$LAB_DIR/1_dns_corporativo_normal.log")"
echo " -> Resultado do YARA nos arquivos legitimos:"
yara "$YARA_RULE_FILE" "$LAB_DIR/1_backup_legitimo.sh" "$LAB_DIR/1_dns_corporativo_normal.log" || echo "    [OK] Nenhuma regra disparou (Zero Falso Positivo!)"
echo ""
read -p "Pressione [ENTER] para lancar o CENARIO 2 (Binario PE Empacotado/Crypter)..."

# ------------------------------------------------------------------------------
# CENARIO 2: BINARIO PE EMPACOTADO / CRIPTOGRAFADO (ALTA ENTROPIA)
# ------------------------------------------------------------------------------
echo ""
echo -e "\033[1;33m[CENARIO 2] Simulando Dropper PE Empacotado (Header MZ + 32KB de Payload Cifrado)...\033[0m"
printf "MZ" > "$LAB_DIR/2_svchost_packed.exe"
head -c 32768 /dev/urandom >> "$LAB_DIR/2_svchost_packed.exe"

echo " -> Entropia de 2_svchost_packed.exe:       $(calc_entropy "$LAB_DIR/2_svchost_packed.exe")"
echo -e " -> \033[1;31mResultado do YARA (Esperado: SUSP_Packed_Or_Encrypted_PE_Entropy):\033[0m"
yara -m "$YARA_RULE_FILE" "$LAB_DIR/2_svchost_packed.exe"
echo ""
read -p "Pressione [ENTER] para lancar o CENARIO 3 (Script PowerShell Ofuscado em Base64)..."

# ------------------------------------------------------------------------------
# CENARIO 3: SCRIPT POWERSHELL OFUSCADO / BASE64 MASSIVO
# ------------------------------------------------------------------------------
echo ""
echo -e "\033[1;33m[CENARIO 3] Simulando Script PowerShell com Payload Ofuscado (Base64 de Alta Entropia)...\033[0m"
B64_PAYLOAD=$(head -c 4096 /dev/urandom | base64 | tr -d '\n')
cat << EOF > "$LAB_DIR/3_stage2_loader.ps1"
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $B64_PAYLOAD
EOF

echo " -> Entropia de 3_stage2_loader.ps1:        $(calc_entropy "$LAB_DIR/3_stage2_loader.ps1")"
echo -e " -> \033[1;31mResultado do YARA (Esperado: SUSP_Obfuscated_Script_High_Entropy):\033[0m"
yara -m "$YARA_RULE_FILE" "$LAB_DIR/3_stage2_loader.ps1"
echo ""
read -p "Pressione [ENTER] para lancar o CENARIO 4 (Artefato Criptografado por Ransomware)..."

# ------------------------------------------------------------------------------
# CENARIO 4: ARTEFATO CIFRADO POR RANSOMWARE (SEM CABECALHO CONHECIDO)
# ------------------------------------------------------------------------------
echo ""
echo -e "\033[1;33m[CENARIO 4] Simulando Arquivo Criptografado por Ransomware (.locked com Alta Entropia)...\033[0m"
head -c 65536 /dev/urandom > "$LAB_DIR/4_planilha_financeira.xlsx.locked"

echo " -> Entropia de 4_planilha_financeira.xlsx.locked: $(calc_entropy "$LAB_DIR/4_planilha_financeira.xlsx.locked")"
echo -e " -> \033[1;31mResultado do YARA (Esperado: SUSP_Encrypted_Drop_Or_Ransomware_Artifact):\033[0m"
yara -m "$YARA_RULE_FILE" "$LAB_DIR/4_planilha_financeira.xlsx.locked"
echo ""
read -p "Pressione [ENTER] para lancar o CENARIO 5 (Dilacerando Logs de DNS com DGA e Exfiltracao)..."

# ------------------------------------------------------------------------------
# CENARIO 5: DILACERANDO LOGS DE DNS (DGA & DNS TUNNELING) E NOMES ALEATORIOS
# ------------------------------------------------------------------------------
echo ""
echo -e "\033[1;33m[CENARIO 5] Injetando Logs com Dominios DGA / Tunneling e Dropper com Nome Aleatorio...\033[0m"
cat << 'EOF' > "$LAB_DIR/5_dns_dga_tunneling_attack.log"
2026-10-23T17:15:01Z client 10.0.0.15 query: intranet.corporativa.local IN A
2026-10-23T17:15:02Z client 10.0.0.99 query: x9k2m7q8z1v4b6n3p0w5r2t8y1u4i7o0.evilc2.top IN A
2026-10-23T17:15:03Z client 10.0.0.99 query: a8F3kL9zQ2mN7vB4xC1wP0rT6yU5jH8gD2s.c2-tunnel.xyz IN TXT
2026-10-23T17:15:05Z client 10.0.0.99 file_created: /tmp/9f86d081884c7d659a2feaa0c55ad015.exe
EOF

echo " -> Entropia global do arquivo de log:      $(calc_entropy "$LAB_DIR/5_dns_dga_tunneling_attack.log")"
echo "    (Repare que o log inteiro tem entropia moderada, mas o YARA mede CADA trecho isoladamente!)"
echo -e " -> \033[1;31mResultado do YARA (Esperado: DGA e Random Filename):\033[0m"
yara -s "$YARA_RULE_FILE" "$LAB_DIR/5_dns_dga_tunneling_attack.log"
echo ""
echo -e "\033[1;32m[CONCLUIDO] Todos os 5 cenarios foram executados com sucesso!\033[0m"
echo -e "\033[1;32mVerifique agora o painel do Wazuh (Rules 100301 a 100306 no Dashboard)!\033[0m"
