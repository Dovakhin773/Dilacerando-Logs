import "math"

/*
   ==========================================================================
   ARQUIVO: entropy_hunting.yar
   TEMA: Dilacerando Logs, Cuspindo Entropia (YARA Math + Wazuh)
   DESTINO SUGERIDO: /var/ossec/ruleset/yara/entropy_hunting.yar
   ==========================================================================
*/

rule SUSP_Packed_Or_Encrypted_PE_Entropy {
    meta:
        description = "Detecta executavel Windows (PE) com altissima entropia indicando Packer, Crypter ou Payload Cifrado"
        author = "Aula Dilacerando Logs"
        mitre_att = "T1027.002"
        severity = "High"

    condition:
        // Verifica assinatura MZ no offset 0 (Executavel PE)
        uint16(0) == 0x5A4D and
        filesize > 4KB and filesize < 20MB and
        (
            // Entropia global do binario >= 7.20
            math.entropy(0, filesize) >= 7.20
            or
            // OU os ultimos 2KB do arquivo possuem entropia >= 7.60 (Overlay criptografado)
            (filesize > 8KB and math.entropy(filesize - 2048, 2048) >= 7.60)
        )
}

rule SUSP_Obfuscated_Script_High_Entropy {
    meta:
        description = "Detecta scripts (PS1, SH, VBS, JS) com entropia tipica de Base64 massivo ou ofuscacao pesada"
        author = "Aula Dilacerando Logs"
        mitre_att = "T1027.010"
        severity = "High"

    strings:
        $s_ps1 = /powershell|pwsh|-enc|-encodedcommand|FromBase64String|Invoke-Expression|IEX/i
        $s_sh  = /\#\!\/bin\/(ba)?sh|base64\s+-d|eval\s+/i
        $b64_chunk = /[A-Za-z0-9+\/]{120,}={0,2}/

    condition:
        // Nao e binario PE nem ELF
        uint16(0) != 0x5A4D and uint32(0) != 0x464C457F and
        filesize > 512 and filesize < 2MB and
        (any of ($s_*) or #b64_chunk >= 1) and
        // Scripts normais tem entropia entre 4.0 e 4.8. Acima de 5.30 indica ofuscacao/encoding pesado
        math.entropy(0, filesize) >= 5.30
}

rule SUSP_Encrypted_Drop_Or_Ransomware_Artifact {
    meta:
        description = "Detecta arquivo recem-criado com entropia proxima de 8.0 sem cabecalho de formato comprimido conhecido"
        author = "Aula Dilacerando Logs"
        mitre_att = "T1486"
        severity = "Critical"

    condition:
        filesize > 2KB and filesize < 50MB and
        // Exclui formatos comprimidos legitimos para evitar Falsos Positivos:
        uint32(0) != 0x04034B50 and // ZIP / DOCX / XLSX / JAR
        uint16(0) != 0x8B1F     and // GZIP (.gz / .tgz)
        uint32(0) != 0x474E5089 and // PNG
        uint16(0) != 0xD8FF     and // JPEG
        uint32(0) != 0x46445025 and // %PDF
        uint32(0) != 0xAFBC7A37 and // 7-Zip
        uint16(0) != 0x5A4D     and // PE (tratado na regra especifica)
        uint32(0) != 0x464C457F and // ELF
        // Entropia altissima (>= 7.50) e desvio medio dos bytes proximo de distribuicao uniforme (~64.0)
        math.entropy(0, filesize) >= 7.50 and
        math.deviation(0, filesize, 127.5) >= 60.0
}

rule SUSP_DGA_Or_DNS_Tunneling_In_Logs {
    meta:
        description = "Dilacera logs de DNS/Proxy procurando subdominios ou dominios com alta entropia (DGA / Exfiltracao DNS)"
        author = "Aula Dilacerando Logs"
        mitre_att = "T1568.002, T1071.004"
        severity = "High"

    strings:
        // Captura rotulos de dominios/subdominios longos (20+ caracteres alfanumericos antes do ponto)
        $dns_label = /[a-zA-Z0-9-]{20,63}\.[a-zA-Z0-9.-]{2,40}\.[a-zA-Z]{2,10}/

    condition:
        filesize < 10MB and
        // Para cada dominio capturado pela regex no log, mede a entropia APENAS daquele trecho (@offset, !length)
        for any i in (1..#dns_label) : (
            !dns_label[i] >= 26 and
            math.entropy(@dns_label[i], !dns_label[i]) >= 4.30
        )
}

rule SUSP_Random_Filename_In_Logs {
    meta:
        description = "Detecta nomes de arquivos gerados aleatoriamente (Dropper/Temp) dentro de logs de auditoria/FIM"
        author = "Aula Dilacerando Logs"
        mitre_att = "T1036"
        severity = "Medium"

    strings:
        // Captura caminhos em /tmp, /var/tmp, /dev/shm ou C:\Users\Public com nomes longos/hexadecimais
        $susp_path = /(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|[A-Za-z]:\\Users\\Public\\|[A-Za-z]:\\Windows\\Temp\\|\\Users\\Public\\|\\Windows\\Temp\\)[a-zA-Z0-9_]{16,45}\.(exe|dll|bin|sh|ps1|bat|dat|tmp)/i

    condition:
        filesize < 10MB and
        for any i in (1..#susp_path) : (
            // Limiar de 4.10 cobre hashes hexadecimais (MD5/SHA) e geradores alfanumericos
            math.entropy(@susp_path[i], !susp_path[i]) >= 4.10
        )
}
