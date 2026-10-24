#!/bin/bash
# ==============================================================================
# Wazuh Active Response - YARA Math & Entropy Scanner (Linux)
# Destino: /var/ossec/active-response/bin/yara_entropy_scan.sh
# Permissoes necessarias:
#   sudo chmod 750 /var/ossec/active-response/bin/yara_entropy_scan.sh
#   sudo chown root:wazuh /var/ossec/active-response/bin/yara_entropy_scan.sh
# ==============================================================================

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

read -r INPUT_JSON

if [ -z "$INPUT_JSON" ]; then
    exit 0
fi

# 1. Extrai o caminho do arquivo (Tenta jq primeiro; se nao tiver, usa Python3 nativo)
FILENAME=""
if command -v jq >/dev/null 2>&1; then
    FILENAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // .parameters.alert.data.file // empty')
else
    FILENAME=$(python3 -c "
import sys, json
try:
    d = json.loads(sys.argv[1])
    params = d.get('parameters', {}).get('alert', {})
    path = params.get('syscheck', {}).get('path') or params.get('data', {}).get('file', '')
    print(path)
except Exception:
    pass
" "$INPUT_JSON" 2>/dev/null)
fi

LOG_FILE="/var/ossec/logs/active-responses.log"
YARA_RULES="/var/ossec/ruleset/yara/entropy_hunting.yar"

# Se o arquivo de regras nao estiver no local padrao, procura no diretorio do lab
if [ ! -f "$YARA_RULES" ]; then
    if [ -f "/tmp/entropy_hunting.yar" ]; then
        YARA_RULES="/tmp/entropy_hunting.yar"
    fi
fi

# Verifica se o arquivo alvo e a regra existem
if [ -z "$FILENAME" ] || [ ! -f "$FILENAME" ] || [ ! -f "$YARA_RULES" ]; then
    exit 0
fi

# Localiza o binario do YARA
YARA_BIN=$(command -v yara 2>/dev/null)
if [ -z "$YARA_BIN" ]; then
    if [ -x "/usr/local/bin/yara" ]; then
        YARA_BIN="/usr/local/bin/yara"
    elif [ -x "/usr/bin/yara" ]; then
        YARA_BIN="/usr/bin/yara"
    fi
fi

if [ -z "$YARA_BIN" ]; then
    exit 0
fi

# Pausa breve de 1 segundo para garantir conclusao da gravacao do arquivo no disco
sleep 1

# 2. Executa o YARA contra o arquivo
YARA_OUTPUT=$("$YARA_BIN" -m "$YARA_RULES" "$FILENAME" 2>/dev/null)

if [ -n "$YARA_OUTPUT" ]; then
    # 3. Calcula a entropia real do arquivo via Python3 (bits/byte de 0.00 a 8.00)
    FILE_ENTROPY=$(python3 -c "
import math, sys
from collections import Counter
try:
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    if not data:
        print('0.0000')
    else:
        n = len(data)
        e = -sum((c/n) * math.log2(c/n) for c in Counter(data).values())
        print(f'{e:.4f}')
except Exception:
    print('0.0000')
" "$FILENAME" 2>/dev/null)

    # 4. Formata e grava cada regra correspondente no active-responses.log
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        RULE_NAME=$(echo "$line" | awk '{print $1}')
        # Usa virgula como delimitador do sed para evitar quebra com barras / do caminho
        META_INFO=$(echo "$line" | cut -d' ' -f2- | sed "s, $FILENAME\$,,")
        [ -z "$META_INFO" ] && META_INFO="none"
        TIMESTAMP=$(date '+%Y/%m/%d %H:%M:%S')
        echo "${TIMESTAMP} wazuh-yara-entropy: INFO - scan_result: matched | yara_rule: ${RULE_NAME} | file_entropy: ${FILE_ENTROPY} | target_file: ${FILENAME} | meta: ${META_INFO}" >> "$LOG_FILE"
    done <<< "$YARA_OUTPUT"
fi

exit 0
