# Kit Master da Aula: Dilacerando Logs, Cuspindo Entropia (YARA Math + Wazuh)

> **"Matemática de 1948 > Marketing de US$ 1 Milhão"**  
> Guia completo e definitivo para ministrar a aula prática de 1 hora sobre detecção comportamental de ameaças via cálculo de **Entropia de Shannon** usando o módulo `math` do YARA integrado ao **Active Response** e **FIM (Syscheck)** do Wazuh.

---

## 📁 Estrutura de Arquivos do Projeto

```text
aula-yara-entropia-wazuh/
├── README.md                                  # Este manual completo de instalação, uso e aula
├── apresentacao_slides.html                   # Apresentação interativa em 16 slides com Calculadora ao Vivo
│
├── yara/
│   └── entropy_hunting.yar                    # As 5 regras YARA com import "math" calibradas
│
├── wazuh-agent/
│   ├── yara_entropy_scan.sh                   # Script Active Response para Agentes Linux (Bash + Python3)
│   ├── yara_entropy_scan.cmd                  # Wrapper executável para Agentes Windows
│   └── yara_entropy_scan.ps1                  # Script Active Response nativo Windows (.NET puro)
│
├── wazuh-manager/
│   ├── local_decoder.xml                      # Decoder customizado para extrair entropia, regra e arquivo
│   ├── local_rules.xml                        # Regras Wazuh 100300 a 100306 mapeadas no MITRE ATT&CK
│   └── ossec_conf_snippet.xml                 # Trechos prontos para o ossec.conf (Manager e Agente)
│
└── simulacao-aula/
    ├── simulador_aula_entropia.sh             # Live Demo interativa em 5 atos para Linux
    └── simulador_aula_entropia.ps1            # Live Demo interativa em 5 atos para Windows
```

---

## 🧮 As 5 Regras YARA e Mapeamento MITRE ATT&CK

| Regra YARA | Limiar de Entropia | Técnica MITRE | Descrição da Ameaça |
| :--- | :---: | :---: | :--- |
| **`SUSP_Packed_Or_Encrypted_PE_Entropy`** | $\ge 7.20$ bits/byte | `T1027.002` | Executável Windows (Header `MZ`) empacotado (UPX, Themida) ou com *overlay* cifrado. |
| **`SUSP_Obfuscated_Script_High_Entropy`** | $\ge 5.30$ bits/byte | `T1027.010` | Scripts `.ps1`, `.sh`, `.vbs` com blocos maciços de Base64 ou ofuscação pesada. |
| **`SUSP_Encrypted_Drop_Or_Ransomware_Artifact`** | $\ge 7.50$ bits/byte | `T1486` | Arquivo recém-criado com distribuição uniforme sem cabeçalhos legítimos (Ransomware). |
| **`SUSP_DGA_Or_DNS_Tunneling_In_Logs`** | $\ge 4.30$ bits/byte | `T1568.002` `T1071.004` | Dilacera logs de DNS/Proxy medindo isoladamente cada domínio longo suspeito. |
| **`SUSP_Random_Filename_In_Logs`** | $\ge 4.10$ bits/byte | `T1036` | Nomes temporários aleatórios (MD5/hex/alfanumérico) em `/tmp` ou `C:\Users\Public`. |

---

## 🚀 Instalação e Configuração Passo a Passo

Em uma arquitetura Wazuh, as configurações se dividem entre o **Wazuh Manager** (cérebro) e os **Wazuh Agents** (endpoints vigiados).

---

### PASSO 1: Configuração no Wazuh Manager

Acesse o servidor do **Wazuh Manager** via SSH como `root`:

#### 1.1. Instalar o Decoder Customizado
Copie o conteúdo de `wazuh-manager/local_decoder.xml` para o final do arquivo `/var/ossec/etc/decoders/local_decoder.xml`:
```bash
sudo nano /var/ossec/etc/decoders/local_decoder.xml
```
Cole:
```xml
<decoder name="wazuh-yara-entropy">
  <prematch>wazuh-yara-entropy</prematch>
</decoder>

<decoder name="wazuh-yara-entropy-fields">
  <parent>wazuh-yara-entropy</parent>
  <regex>scan_result: (\S+) \| yara_rule: (\S+) \| file_entropy: (\S+) \| target_file: (.+) \| meta: (.*)</regex>
  <order>scan_result, yara_rule, file_entropy, target_file, yara_meta</order>
</decoder>
```

#### 1.2. Instalar as Regras Customizadas
Copie o conteúdo de `wazuh-manager/local_rules.xml` para o arquivo `/var/ossec/etc/rules/local_rules.xml`:
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
*(As regras 100300 a 100306 mapeiam os alertas para níveis 10 a 14 com MITRE ATT&CK).*

#### 1.3. Configurar o Active Response no Manager
Abra o arquivo principal do Manager:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Dentro do bloco `<ossec_config>`, adicione a definição do comando e o gatilho:
```xml
  <!-- Definicao do Comando Active Response -->
  <command>
    <name>yara-entropy-scan</name>
    <executable>yara_entropy_scan.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <!-- Gatilho: Dispara sempre que o FIM detectar arquivo criado (554) ou modificado (550) -->
  <active-response>
    <disabled>no</disabled>
    <command>yara-entropy-scan</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
```

#### 1.4. Reiniciar o Wazuh Manager para aplicar
```bash
sudo systemctl restart wazuh-manager
```

---

### PASSO 2: Configuração no Endpoint (Agente Linux)

Acesse o **Agente Linux** onde a simulação vai rodar (ou a própria VM All-in-One):

#### 2.1. Salvar as Regras YARA
```bash
sudo mkdir -p /var/ossec/ruleset/yara
sudo cp yara/entropy_hunting.yar /var/ossec/ruleset/yara/entropy_hunting.yar
sudo chmod 640 /var/ossec/ruleset/yara/entropy_hunting.yar
sudo chown root:wazuh /var/ossec/ruleset/yara/entropy_hunting.yar
```

#### 2.2. Instalar o Script Active Response
```bash
sudo cp wazuh-agent/yara_entropy_scan.sh /var/ossec/active-response/bin/yara_entropy_scan.sh
sudo chmod 750 /var/ossec/active-response/bin/yara_entropy_scan.sh
sudo chown root:wazuh /var/ossec/active-response/bin/yara_entropy_scan.sh
```

#### 2.3. Configurar o FIM (Syscheck) e Ingestão de Logs no Agente
Abra o `/var/ossec/etc/ossec.conf` do Agente:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Certifique-se de que a pasta temporária está sob monitoramento em tempo real dentro de `<syscheck>`:
```xml
<syscheck>
  <directories realtime="yes" check_all="yes" report_changes="no">/tmp/aula_entropia</directories>
</syscheck>
```
E que o arquivo de log do Active Response está sendo lido pelo logcollector:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/ossec/logs/active-responses.log</location>
</localfile>
```

Reinicie o agente:
```bash
sudo systemctl restart wazuh-agent
```

---

### PASSO 3: Configuração no Endpoint (Agente Windows - Opcional)

Se você preferir demonstrar em um Agente Windows, execute no **PowerShell como Administrador**:

```powershell
# 1. Copiar as regras YARA
New-Item -ItemType Directory -Path "C:\Program Files (x86)\ossec-agent\ruleset\yara" -Force
Copy-Item ".\yara\entropy_hunting.yar" -Destination "C:\Program Files (x86)\ossec-agent\ruleset\yara\entropy_hunting.yar" -Force

# 2. Copiar os scripts Active Response
Copy-Item ".\wazuh-agent\yara_entropy_scan.cmd" -Destination "C:\Program Files (x86)\ossec-agent\active-response\bin\" -Force
Copy-Item ".\wazuh-agent\yara_entropy_scan.ps1" -Destination "C:\Program Files (x86)\ossec-agent\active-response\bin\" -Force

# 3. Reiniciar servico do agente Windows
Restart-Service wazuh
```

---

## 🎬 Showtime: Executando a Simulação ao Vivo na Aula

Os simuladores geram os 5 atos de teste passo a passo, calculando a entropia de Shannon de cada artefato ao vivo no console antes de acionar o YARA:

### 🐧 No Linux (Bash):
```bash
chmod +x simulacao-aula/simulador_aula_entropia.sh
./simulacao-aula/simulador_aula_entropia.sh
```

### 🪟 No Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File .\simulacao-aula\simulador_aula_entropia.ps1
```

### O que acontece em cada ato da simulação:
1. **Ato 1 (Baseline Limpo):** Cria um script legítimo de backup (`1_backup_legitimo`) e um log de DNS corporativo.  
   *Entropia:* ~$4.3$ bits/byte.  
   *Resultado:* **Nenhuma regra dispara (Zero Falso Positivo!).**
2. **Ato 2 (Dropper PE Empacotado):** Cria `2_svchost_packed.exe` com assinatura `MZ` e 32KB criptografados.  
   *Entropia:* **~$7.99$ bits/byte.**  
   *Resultado:* Dispara **`SUSP_Packed_Or_Encrypted_PE_Entropy`** (Wazuh Rule `100302`, Nível 13).
3. **Ato 3 (Script PowerShell Ofuscado):** Cria `3_stage2_loader.ps1` com `-EncodedCommand` em Base64 randômico.  
   *Entropia:* **~$6.01$ bits/byte.**  
   *Resultado:* Dispara **`SUSP_Obfuscated_Script_High_Entropy`** (Wazuh Rule `100303`, Nível 12).
4. **Ato 4 (Drop de Ransomware):** Cria `4_planilha_financeira.xlsx.locked` com 64KB de dados cifrados sem cabeçalho PE/ZIP.  
   *Entropia:* **~$7.99$ bits/byte.**  
   *Resultado:* Dispara **`SUSP_Encrypted_Drop_Or_Ransomware_Artifact`** (Wazuh Rule `100304`, Nível 14 - Emergência).
5. **Ato 5 (Dilacerando Logs de DNS):** Injeta no log consultas DGA (`x9k2m...evilc2.top`), exfiltração DNS TXT e dropper temporário.  
   *Resultado:* O YARA isola cirurgicamente os offsets e dispara **`SUSP_DGA_Or_DNS_Tunneling_In_Logs`** (Rule `100305`) e **`SUSP_Random_Filename_In_Logs`** (Rule `100306`).

---

## 📊 Visualização no Dashboard do Wazuh

1. Acesse o **Wazuh Dashboard** no navegador (`https://IP-DO-DASHBOARD`).
2. Vá em **Security Events** (Eventos de Segurança).
3. Na barra de busca, filtre por:
   ```text
   rule.groups: "entropy_hunting"
   ```
   ou especificamente pelas regras da aula:
   ```text
   rule.id: (100301 or 100302 or 100303 or 100304 or 100305 or 100306)
   ```
4. Expanda qualquer evento para mostrar aos alunos os campos extraídos:
   * `data.yara_rule`: Nome da regra disparada.
   * `data.file_entropy`: Valor numérico exato da entropia em bits/byte (ex: `7.9946`).
   * `data.target_file`: Arquivo identificado em disco.
   * `rule.mitre.id`: Mapeamento das técnicas MITRE ATT&CK (`T1027`, `T1568.002`, `T1486`, `T1036`).

---

## 🖥️ Como Apresentar os Slides

O arquivo [`apresentacao_slides.html`](apresentacao_slides.html) foi construído para rodar localmente sem necessidade de servidor web:

1. Dê dois cliques em `apresentacao_slides.html` para abrir no Chrome, Edge ou Firefox.
2. Pressione **`F11`** para entrar em modo tela cheia de apresentação.
3. Use as teclas do teclado:
   * **`→` (Seta Direita):** Avança para o próximo slide.
   * **`←` (Seta Esquerda):** Volta para o slide anterior.
4. **Slide 5:** Contém a **Calculadora de Entropia de Shannon ao Vivo**. Peça a um aluno para ditar uma palavra ou comando e veja o cálculo em tempo real.
5. **Slide 11:** Contém o **Mapa Mental Interativo do Fluxo** conectando FIM, Active Response, YARA Math e o Dashboard.
6. Clique no botão **"Notas do Instrutor: ON"** no canto superior direito para ver o roteiro e stand-up de cada slide.

---

## 🛠️ Guia de Troubleshooting Rápido (Caso algo dê errado na aula)

| Sintoma | Causa Mais Comum | Como Resolver em 10 Segundos |
| :--- | :--- | :--- |
| O simulador diz que o YARA não foi encontrado | Pacote `yara` não está instalado no sistema | No Linux: `sudo apt install yara`<br/>No Windows: `choco install yara` |
| O arquivo é criado em `/tmp`, mas nada aparece no `active-responses.log` | Permissão do script Active Response ou caminho FIM | Rode no Agente:<br/>`sudo chmod 750 /var/ossec/active-response/bin/yara_entropy_scan.sh`<br/>`sudo chown root:wazuh /var/ossec/active-response/bin/yara_entropy_scan.sh` |
| A regra YARA bate, mas o Wazuh não gera alerta no painel | O decoder ou as regras locais não foram carregados no Manager | Valide no Manager com o comando:<br/>`/var/ossec/bin/wazuh-logtest`<br/>Cole a linha do log para confirmar se decodifica como `wazuh-yara-entropy`. |
| O Dashboard do Wazuh dá erro de autenticação ou tela vermelha | O serviço `wazuh-indexer` está parado | No nó do Indexer, rode:<br/>`systemctl status wazuh-indexer`<br/>`systemctl start wazuh-indexer` |
