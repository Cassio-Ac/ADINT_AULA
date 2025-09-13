# Documentação das Ferramentas do Pipeline de Análise de Superfície

Este documento descreve detalhadamente cada ferramenta integrada ao pipeline de análise de superfície de ataque, incluindo sua função, uso e configuração.

## Índice

1. [WHOIS](#whois)
2. [DNS](#dns)
3. [COLETOR](#coletor)
4. [SHODAN](#shodan)
5. [FEED](#feed)
6. [TELEGRAM](#telegram)

## WHOIS

### Descrição

A ferramenta WHOIS consulta informações de registro de domínios, fornecendo detalhes sobre proprietários, contatos, datas de criação/expiração e servidores de nomes.

### Script Principal

`WHOIS/whois_universal.py`

### Funcionalidades

- Consulta informações WHOIS para múltiplos domínios
- Suporte a diferentes TLDs (.com, .br, .org, etc.)
- Extração estruturada de informações
- Saída em formato JSON

### Parâmetros

```
-l, --list ARQUIVO    Arquivo com lista de domínios
-o, --output ARQUIVO  Arquivo de saída JSON
-d, --domain DOMÍNIO  Consultar um único domínio
-v, --verbose         Modo verboso
```

### Exemplo de Uso

```bash
python3 WHOIS/whois_universal.py -l dominios.txt -o resultados_whois.json
```

### Configuração

```yaml
tools:
  whois:
    enabled: true
    script: WHOIS/whois_universal.py
    index: whois
    description: "Consulta informações WHOIS para domínios"
```

### Índice Elasticsearch

`analise_superficie_[empresa]_whois`

### Exemplo de Saída

```json
{
  "domain_name": "adint.com.br",
  "registrant_name": "R F G DA SILVA - SEGURANCA DE DADOS LTDA",
  "registrant_id": "37.737.641/0001-33",
  "country": "BR",
  "owner_c": "ADINT19",
  "admin_c": null,
  "tech_c": "COTHA",
  "billing_c": null,
  "name_server": [
    "ns1.serverbrasil.com.br",
    "ns2.serverbrasil.com.br"
  ],
  "nsstat": [
    "20250815 AA",
    "20250815 AA"
  ],
  "nslastaa": [
    "20250815",
    "20250815"
  ],
  "saci": "yes",
  "creation_date": "20230320 #25916944",
  "updated_date": "20231118",
  "expiration_date": "20330320",
  "status": "published",
  "nic_hdl_br": [
    "ADINT19",
    "COTHA"
  ],
  "person": [
    "Adsumus Intelligence",
    "Contato Técnico - Hagile"
  ],
  "email": [
    "robsonnavyseals@gmail.com",
    "contato@hagile.com.br"
  ],
  "domain": "adint.com.br",
  "server": "whois.registro.br",
  "tld": "br",
  "_analise_metadata": {
    "company": "ADINT",
    "timestamp": "20250816_145551",
    "pipeline_run": "20250816_145551"
  }
}
```

## DNS

### Descrição

A ferramenta DNS analisa configurações DNS de domínios, atribuindo pontuações de segurança e fornecendo recomendações para melhorias.

### Script Principal

`DNS/dns-security-analyzer.py`

### Funcionalidades

- Análise de registros DNS (A, AAAA, MX, NS, TXT, SOA, CAA, etc.)
- Verificação de configurações de segurança (DNSSEC, SPF, DMARC, etc.)
- Atribuição de pontuação de segurança (0-100)
- Recomendações priorizadas para melhorias
- Saída em formato JSON

### Parâmetros

```
-f, --file ARQUIVO     Arquivo com lista de domínios
-d, --domain DOMÍNIO   Analisar um único domínio
-o, --output ARQUIVO   Arquivo de saída JSON
-v, --verbose          Modo verboso
```

### Exemplo de Uso

```bash
python3 DNS/dns-security-analyzer.py -f dominios.txt -d dns_analysis
```

### Configuração

```yaml
tools:
  dns:
    enabled: true
    script: DNS/dns-security-analyzer.py
    index: dns
    description: "Analisa configurações DNS e atribui pontuação de segurança"
```

### Índice Elasticsearch

`analise_superficie_[empresa]_dns`

### Exemplo de Saída

```json
{
  "adint.com.br": {
    "domain": "adint.com.br",
    "timestamp": "2025-08-16T14:55:53.572288",
    "dns_records": {
      "A": ["69.162.95.26"],
      "AAAA": [],
      "NS": [
        "ns2.serverbrasil.com.br.",
        "ns1.serverbrasil.com.br."
      ],
      "MX": ["0 adint.com.br."],
      "TXT": [
        "\"v=spf1 ip4:69.162.95.26 +a +mx +ip4:69.162.77.162 +ip4:69.162.77.166 +ip4:69.162.95.30 +ip4:216.245.220.186 +ip4:216.245.220.187 +ip4:216.245.220.188 -all\""
      ],
      "SOA": [
        "ns1.serverbrasil.com.br. allan\\.marques.hagile.com.br. 2025062301 3600 1800 1209600 86400"
      ],
      "CAA": [],
      "CNAME": []
    },
    "security_scores": [
      {
        "category": "DNSSEC",
        "description": "Validação DNSSEC",
        "max_points": 20,
        "earned_points": 0,
        "details": "❌ DNSSEC não habilitado",
        "severity": "critical"
      },
      {
        "category": "SPF",
        "description": "Registro SPF",
        "max_points": 15,
        "earned_points": 15,
        "details": "SPF configurado: ✅ Usa -all (fail)",
        "severity": "high"
      }
    ],
    "total_score": 42,
    "max_possible_score": 105,
    "grade": "D",
    "recommendations": [
      {
        "priority": "🔴 CRÍTICO",
        "category": "DNSSEC",
        "recommendation": "Habilitar DNSSEC para prevenir ataques de DNS spoofing e cache poisoning",
        "impact": "Proteção contra manipulação de respostas DNS"
      }
    ],
    "percentage": 40.0
  }
}
```

## COLETOR

### Descrição

O COLETOR é um conjunto de ferramentas para coleta de informações sobre domínios e infraestrutura, incluindo subfinder, httpx, naabu, tlsx e nuclei.

### Script Principal

`COLETOR/coletor.sh`

### Ferramentas Integradas

1. **subfinder**: Enumeração de subdomínios
2. **httpx**: Verificação de servidores HTTP/HTTPS
3. **naabu**: Scanner de portas TCP
4. **tlsx**: Extração de certificados SSL/TLS e Subject Alternative Names (SAN)
5. **nuclei**: Scanner de vulnerabilidades baseado em templates

### Parâmetros

```
Uso: ./coletor.sh ARQUIVO_DOMINIOS [OUT_DIR=out]

ARQUIVO_DOMINIOS  Arquivo com lista de domínios
OUT_DIR           Diretório de saída (padrão: out)
```

### Exemplo de Uso

```bash
./COLETOR/coletor.sh dominios.txt OUT_DIR=resultados_coletor
```

### Configuração

```yaml
tools:
  coletor:
    enabled: true
    script: COLETOR/coletor.sh
    index: coletor
    description: "Pipeline de coleta com subfinder, httpx, naabu, tlsx e nuclei"
    sub_indices:
      - httpx
      - naabu
      - certs
      - san
      - nuclei

tool_settings:
  coletor:
    threads: 20
    rate_limit: 50
```

### Índices Elasticsearch

- `analise_superficie_[empresa]_coletor_httpx`
- `analise_superficie_[empresa]_coletor_naabu`
- `analise_superficie_[empresa]_coletor_certs`
- `analise_superficie_[empresa]_coletor_san`
- `analise_superficie_[empresa]_coletor_nuclei`

### Exemplo de Saída (HTTPX)

```json
{
  "timestamp": "2025-08-16T15:12:34.567Z",
  "domain": "adint.com.br",
  "url": "https://adint.com.br",
  "status_code": 200,
  "title": "ADINT - Active Defense Intelligence",
  "content_length": 12845,
  "content_type": "text/html; charset=UTF-8",
  "server": "Apache/2.4.52 (Ubuntu)",
  "technologies": [
    "WordPress",
    "PHP/7.4.33",
    "jQuery",
    "Bootstrap"
  ],
  "headers": {
    "Server": "Apache/2.4.52 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.33",
    "Content-Type": "text/html; charset=UTF-8",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff"
  },
  "security_headers": {
    "has_hsts": false,
    "has_xss_protection": false,
    "has_csp": false,
    "has_x_content_type_options": true,
    "has_x_frame_options": true
  },
  "response_time": 0.345,
  "screenshot_path": "screenshots/adint.com.br.png",
  "_analise_metadata": {
    "company": "ADINT",
    "timestamp": "20250816_145551",
    "pipeline_run": "20250816_145551",
    "tool": "httpx"
  }
}
```

## SHODAN

### Descrição

A ferramenta SHODAN consulta informações no Shodan para domínios e IPs, fornecendo detalhes sobre serviços expostos, vulnerabilidades e configurações.

### Script Principal

`SHODAN/unified_shodan_scanner.py`

### Funcionalidades

- Consulta informações no Shodan para múltiplos domínios
- Resolução de IPs para domínios
- Extração de informações sobre serviços, portas, banners, etc.
- Identificação de vulnerabilidades (CVEs)
- Saída em formato JSON

### Parâmetros

```
Uso: python3 unified_shodan_scanner.py ARQUIVO_DOMINIOS DIRETORIO_SAIDA

ARQUIVO_DOMINIOS  Arquivo com lista de domínios
DIRETORIO_SAIDA   Diretório para armazenar resultados
```

### Exemplo de Uso

```bash
python3 SHODAN/unified_shodan_scanner.py dominios.txt resultados_shodan
```

### Configuração

```yaml
tools:
  shodan:
    enabled: true
    script: SHODAN/unified_shodan_scanner.py
    index: shodan
    description: "Consulta informações no Shodan para domínios e IPs"

tool_settings:
  shodan:
    max_results: 1000
```

### Índice Elasticsearch

`analise_superficie_[empresa]_shodan`

### Exemplo de Saída

```json
{
  "ip": "69.162.95.26",
  "hostnames": [
    "server.adint.com.br"
  ],
  "ports": [
    22,
    80,
    443,
    8080
  ],
  "vulns": [
    "CVE-2022-37434",
    "CVE-2023-25690"
  ],
  "os": "Linux 5.4",
  "isp": "ServerBrasil",
  "org": "R F G DA SILVA - SEGURANCA DE DADOS LTDA",
  "country_name": "Brazil",
  "country_code": "BR",
  "city": "São Paulo",
  "last_update": "2025-08-15T10:23:45",
  "services": [
    {
      "port": 22,
      "service": "SSH",
      "product": "OpenSSH",
      "version": "8.4p1",
      "banner": "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1"
    },
    {
      "port": 80,
      "service": "HTTP",
      "product": "Apache httpd",
      "version": "2.4.52",
      "banner": "Apache/2.4.52 (Ubuntu)"
    },
    {
      "port": 443,
      "service": "HTTPS",
      "product": "Apache httpd",
      "version": "2.4.52",
      "ssl": {
        "cert": {
          "issued": "2025-01-15T00:00:00",
          "expires": "2026-01-15T23:59:59",
          "issuer": "Let's Encrypt Authority X3",
          "subject": "CN=adint.com.br"
        }
      }
    }
  ],
  "_analise_metadata": {
    "company": "ADINT",
    "timestamp": "20250816_145551",
    "pipeline_run": "20250816_145551",
    "domain": "adint.com.br"
  }
}
```

## FEED

### Descrição

A ferramenta FEED coleta notícias e alertas de segurança de feeds RSS relevantes, permitindo acompanhar informações recentes sobre ameaças, vulnerabilidades e tendências de segurança.

### Script Principal

`FEED/rss_feed.py`

### Funcionalidades

- Coleta de feeds RSS de múltiplas fontes
- Categorização de notícias (AI, Cybersecurity, Threat Intel)
- Armazenamento de metadados (título, autor, data, resumo, etc.)
- Envio direto para o Elasticsearch
- Suporte a ILM (Index Lifecycle Management)

### Parâmetros

```
Uso: python3 rss_feed.py COMANDO [OPÇÕES]

Comandos:
  collect        Coleta feeds RSS e salva em arquivos JSON
  send           Envia feeds coletados para o Elasticsearch
  collect-send   Coleta e envia em uma única operação

Opções:
  --feeds-file ARQUIVO    Arquivo de configuração YAML com feeds (padrão: feeds.yaml)
  --output-dir DIR        Diretório para armazenar resultados (padrão: feeds)
  --days DIAS             Número de dias para coletar (padrão: 7)
  --es-host HOST          Host do Elasticsearch (padrão: localhost)
  --es-port PORTA         Porta do Elasticsearch (padrão: 9200)
  --index NOME            Nome do índice no Elasticsearch
```

### Exemplo de Uso

```bash
python3 FEED/rss_feed.py collect-send --feeds-file FEED/feeds.yaml --output-dir resultados_feed --days 7 --index analise_superficie_adint_feed
```

### Configuração

```yaml
tools:
  feed:
    enabled: true
    script: FEED/rss_feed.py
    index: feed
    description: "Coleta feeds RSS de segurança relevantes"

tool_settings:
  feed:
    days_to_collect: 7
```

### Configuração de Feeds (feeds.yaml)

```yaml
categories:
  - name: "Cybersecurity (News/Análises)"
    feeds:
      - name: "The Register » Security (Atom)"
        url: "https://www.theregister.com/security/headlines.atom"
      - name: "Schneier on Security"
        url: "https://www.schneier.com/feed/atom/"
      # ... outros feeds ...

  - name: "AI"
    feeds:
      - name: "NVIDIA Developer Blog"
        url: "https://developer.nvidia.com/blog/feed/"
      # ... outros feeds ...
```

### Índice Elasticsearch

`analise_superficie_[empresa]_feed`

### Exemplo de Saída

```json
{
  "@timestamp": "2025-08-14T16:00:00+00:00",
  "feed_name": "NVIDIA Developer Blog",
  "feed_title": "NVIDIA Technical Blog",
  "feed_description": "News and tutorials for developers, data scientists, and IT admins",
  "feed_link": "https://developer.nvidia.com/blog",
  "feed_updated": "2025-08-15T21:40:21Z",
  "entry_id": "",
  "title": "Upcoming Livestream: Building Cross-Framework Agent Ecosystems",
  "link": "https://www.addevent.com/event/Rz26291177",
  "published": "2025-08-14T16:00:00+00:00",
  "summary": "<img alt=\"\" class=\"webfeedsFeaturedVisual wp-post-image\" height=\"432\" src=\"https://developer-blogs.nvidia.com/wp-content/uploads/2025/08/genai-press-project-aiq-3503101-1920x1080-1-768x432-jpg.webp\" style=\"display: block; margin-bottom: 5px; clear: both;\" title=\"genai-press-project-aiq-3503101-1920x1080\" width=\"768\" />Join us on Aug. 21 to see how NVIDIA NeMo Agent toolkit boosts multi-agent workflows with deep MCP integration.",
  "author": "Nicola Sessions",
  "tags": [
    "Data Science",
    "Generative AI",
    "AI Agent",
    "NeMo"
  ],
  "content_hash": "e6d534878afd6c2b2064be85ca965302",
  "category": "AI",
  "source_type": "rss_feed"
}
```

## TELEGRAM

### Descrição

A ferramenta TELEGRAM coleta dados de vazamentos do Telegram, permitindo identificar informações sensíveis que possam ter sido expostas.

### Script Principal

`TELEGRAM/download_Combo.py`

### Funcionalidades

- Conexão com a API do Telegram
- Download de arquivos de canais específicos
- Filtragem por extensão, data e tamanho
- Processamento de arquivos de vazamento
- Envio para o Elasticsearch

### Parâmetros

```
Uso: python3 download_Combo.py [OPÇÕES]

Opções:
  --limit N           Limitar o número de arquivos a baixar
  --ext EXTENSÃO      Filtrar por extensão (ex: .txt)
  --output-dir DIR    Diretório para armazenar downloads
  --days DIAS         Baixar apenas arquivos dos últimos N dias
```

### Exemplo de Uso

```bash
python3 TELEGRAM/download_Combo.py --limit 10 --ext .txt --output-dir downloads
```

### Script de Importação

Para importar os dados baixados para o Elasticsearch, use o script `TELEGRAM/import_to_elk.py`:

```bash
python3 TELEGRAM/import_to_elk.py --input-dir downloads --es-host localhost --es-port 9200 --index analise_superficie_adint_telegram
```

### Configuração

```yaml
tools:
  telegram:
    enabled: false  # Desabilitado por padrão
    script: TELEGRAM/download_Combo.py
    index: telegram
    description: "Coleta dados de vazamentos do Telegram (opcional)"

tool_settings:
  telegram:
    max_files: 10
    file_types: [".txt"]
```

### Índice Elasticsearch

`analise_superficie_[empresa]_telegram`

### Exemplo de Saída

```json
{
  "timestamp": "2025-08-16T16:05:23.456Z",
  "source_type": "telegram",
  "channel_name": "Omega Cloud Combos",
  "channel_id": -1001917800796,
  "message_id": 12345,
  "message_date": "2025-08-15T14:32:18Z",
  "file_name": "Brazil combo mix.txt",
  "file_size": 3879499,
  "file_type": "text/plain",
  "file_hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "download_date": "2025-08-16T16:03:45Z",
  "leak_type": "credentials",
  "leak_count": 15234,
  "domains_affected": [
    "gmail.com",
    "hotmail.com",
    "yahoo.com.br",
    "uol.com.br"
  ],
  "sample_format": "email:password",
  "_analise_metadata": {
    "company": "ADINT",
    "timestamp": "20250816_145551",
    "pipeline_run": "20250816_145551",
    "tool": "telegram"
  }
}
```

### Configuração da API do Telegram

Para usar a ferramenta TELEGRAM, você precisa configurar a API do Telegram:

1. Obtenha uma `api_id` e `api_hash` em https://my.telegram.org/apps
2. Crie um arquivo `config.json` na pasta `TELEGRAM` com o seguinte conteúdo:

```json
{
  "api_id": 12345678,
  "api_hash": "abcdef1234567890abcdef1234567890",
  "phone": "+5511999999999",
  "channel_id": -1001917800796
}
```

3. Execute o script `TELEGRAM/download_Combo.py` uma vez para autenticar sua conta
