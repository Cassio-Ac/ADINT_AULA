# Esquema de Dados do Pipeline de Análise de Superfície

Este documento descreve o esquema de dados para cada índice criado pelo pipeline de análise de superfície de ataque no Elasticsearch.

## Índice de Conteúdos

1. [Metadados Comuns](#metadados-comuns)
2. [Índice de Metadados](#índice-de-metadados)
3. [Índice WHOIS](#índice-whois)
4. [Índice DNS](#índice-dns)
5. [Índices do COLETOR](#índices-do-coletor)
   - [HTTPX](#httpx)
   - [Naabu](#naabu)
   - [TLSX](#tlsx)
   - [Nuclei](#nuclei)
6. [Índice Shodan](#índice-shodan)
7. [Índice de Feeds](#índice-de-feeds)
8. [Índice Telegram](#índice-telegram)

## Metadados Comuns

Todos os documentos incluem um campo `_analise_metadata` com a seguinte estrutura:

```json
"_analise_metadata": {
  "company": "string",       // Nome da empresa analisada
  "timestamp": "string",     // Timestamp da execução (formato: YYYYMMDD_HHMMSS)
  "pipeline_run": "string"   // Identificador único da execução do pipeline
}
```

## Índice de Metadados

**Nome do índice**: `analise_superficie_[empresa]_metadata`

**Descrição**: Armazena metadados sobre a execução do pipeline.

**Esquema**:

```json
{
  "company": "string",       // Nome da empresa analisada
  "timestamp": "string",     // Timestamp da execução (formato: YYYYMMDD_HHMMSS)
  "notes": "string",         // Observações sobre a análise (opcional)
  "domains_file": "string",  // Nome do arquivo de domínios utilizado
  "_analise_metadata": {}    // Metadados comuns
}
```

## Índice WHOIS

**Nome do índice**: `analise_superficie_[empresa]_whois`

**Descrição**: Armazena informações de registro de domínios.

**Esquema**:

```json
{
  "domain_name": "string",           // Nome do domínio
  "registrant_name": "string",       // Nome do registrante
  "registrant_id": "string",         // ID do registrante (CNPJ/CPF)
  "country": "string",               // País de registro
  "owner_c": "string",               // Contato do proprietário
  "admin_c": "string",               // Contato administrativo
  "tech_c": "string",                // Contato técnico
  "billing_c": "string",             // Contato de cobrança
  "name_server": ["string"],         // Lista de nameservers
  "nsstat": ["string"],              // Status dos nameservers
  "nslastaa": ["string"],            // Última verificação dos nameservers
  "saci": "string",                  // Status SACI (domínios .br)
  "creation_date": "string",         // Data de criação
  "updated_date": "string",          // Data de atualização
  "expiration_date": "string",       // Data de expiração
  "status": "string",                // Status do domínio
  "nic_hdl_br": ["string"],          // Handles NIC.br (domínios .br)
  "person": ["string"],              // Nomes de pessoas associadas
  "email": ["string"],               // Emails associados
  "domain": "string",                // Nome do domínio (duplicado)
  "server": "string",                // Servidor WHOIS consultado
  "tld": "string",                   // TLD do domínio
  "_analise_metadata": {}            // Metadados comuns
}
```

## Índice DNS

**Nome do índice**: `analise_superficie_[empresa]_dns`

**Descrição**: Armazena análises de segurança DNS para domínios.

**Esquema**:

```json
{
  "[domain]": {                      // Objeto com o nome do domínio como chave
    "domain": "string",              // Nome do domínio
    "timestamp": "string",           // Timestamp da análise
    "dns_records": {                 // Registros DNS
      "A": ["string"],               // Registros A (IPv4)
      "AAAA": ["string"],            // Registros AAAA (IPv6)
      "NS": ["string"],              // Registros NS (Nameservers)
      "MX": ["string"],              // Registros MX (Mail Exchange)
      "TXT": ["string"],             // Registros TXT
      "SOA": ["string"],             // Registro SOA
      "CAA": ["string"],             // Registros CAA (Certificate Authority Authorization)
      "CNAME": ["string"]            // Registros CNAME
    },
    "security_scores": [             // Pontuações de segurança
      {
        "category": "string",        // Categoria (ex: DNSSEC, SPF, DMARC)
        "description": "string",     // Descrição da categoria
        "max_points": "number",      // Pontuação máxima possível
        "earned_points": "number",   // Pontuação obtida
        "details": "string",         // Detalhes da análise
        "severity": "string"         // Severidade (critical, high, medium, low)
      }
    ],
    "total_score": "number",         // Pontuação total
    "max_possible_score": "number",  // Pontuação máxima possível
    "grade": "string",               // Nota (A, B, C, D, F)
    "recommendations": [             // Recomendações
      {
        "priority": "string",        // Prioridade (🔴 CRÍTICO, 🟠 ALTO, etc)
        "category": "string",        // Categoria
        "recommendation": "string",  // Recomendação
        "impact": "string"           // Impacto da implementação
      }
    ],
    "percentage": "number"           // Porcentagem da pontuação (0-100)
  },
  "_analise_metadata": {}            // Metadados comuns
}
```

## Índices do COLETOR

### HTTPX

**Nome do índice**: `analise_superficie_[empresa]_coletor_httpx`

**Descrição**: Armazena informações sobre serviços web.

**Esquema**:

```json
{
  "timestamp": "string",             // Timestamp da análise
  "domain": "string",                // Nome do domínio
  "url": "string",                   // URL completa
  "status_code": "number",           // Código de status HTTP
  "title": "string",                 // Título da página
  "content_length": "number",        // Tamanho do conteúdo
  "content_type": "string",          // Tipo de conteúdo
  "server": "string",                // Servidor web
  "technologies": ["string"],        // Tecnologias detectadas
  "headers": {                       // Cabeçalhos HTTP
    "[header_name]": "string"
  },
  "security_headers": {              // Cabeçalhos de segurança
    "has_hsts": "boolean",
    "has_xss_protection": "boolean",
    "has_csp": "boolean",
    "has_x_content_type_options": "boolean",
    "has_x_frame_options": "boolean"
  },
  "response_time": "number",         // Tempo de resposta
  "screenshot_path": "string",       // Caminho para screenshot
  "_analise_metadata": {}            // Metadados comuns
}
```

### Naabu

**Nome do índice**: `analise_superficie_[empresa]_coletor_naabu`

**Descrição**: Armazena informações sobre portas abertas.

**Esquema**:

```json
{
  "timestamp": "string",             // Timestamp da análise
  "host": "string",                  // Nome do host
  "ip": "string",                    // Endereço IP
  "port": "number",                  // Número da porta
  "protocol": "string",              // Protocolo (tcp/udp)
  "service": "string",               // Serviço detectado
  "state": "string",                 // Estado (open/closed/filtered)
  "reason": "string",                // Razão do estado
  "latency": "number",               // Latência da resposta
  "_analise_metadata": {}            // Metadados comuns
}
```

### TLSX

**Nome do índice**: `analise_superficie_[empresa]_coletor_tlsx`

**Descrição**: Armazena informações sobre certificados SSL/TLS.

**Esquema**:

```json
{
  "timestamp": "string",             // Timestamp da análise
  "host": "string",                  // Nome do host
  "ip": "string",                    // Endereço IP
  "port": "number",                  // Número da porta
  "tls_version": "string",           // Versão TLS
  "cipher_suite": "string",          // Suíte de cifra
  "issuer": "string",                // Emissor do certificado
  "subject": "string",               // Assunto do certificado
  "not_before": "string",            // Data de início da validade
  "not_after": "string",             // Data de fim da validade
  "sans": ["string"],                // Subject Alternative Names
  "ja3_fingerprint": "string",       // Fingerprint JA3 (cliente)
  "ja3s_fingerprint": "string",      // Fingerprint JA3S (servidor)
  "security_issues": [               // Problemas de segurança
    {
      "issue": "string",             // Descrição do problema
      "severity": "string",          // Severidade
      "details": "string"            // Detalhes
    }
  ],
  "_analise_metadata": {}            // Metadados comuns
}
```

### Nuclei

**Nome do índice**: `analise_superficie_[empresa]_coletor_nuclei`

**Descrição**: Armazena informações sobre vulnerabilidades detectadas.

**Esquema**:

```json
{
  "timestamp": "string",             // Timestamp da análise
  "template-id": "string",           // ID do template Nuclei
  "template-path": "string",         // Caminho do template
  "info": {                          // Informações sobre a vulnerabilidade
    "name": "string",                // Nome
    "author": "string",              // Autor
    "severity": "string",            // Severidade
    "description": "string",         // Descrição
    "reference": "string",           // Referência
    "tags": ["string"]               // Tags
  },
  "host": "string",                  // Host afetado
  "matched-at": "string",            // URL onde foi encontrado
  "extracted-results": ["string"],   // Resultados extraídos
  "ip": "string",                    // Endereço IP
  "curl-command": "string",          // Comando curl para reprodução
  "matcher-status": "boolean",       // Status do matcher
  "matched-line": "string",          // Linha que deu match
  "type": "string",                  // Tipo (http, dns, etc)
  "_analise_metadata": {}            // Metadados comuns
}
```

## Índice Shodan

**Nome do índice**: `analise_superficie_[empresa]_shodan`

**Descrição**: Armazena informações do Shodan sobre hosts.

**Esquema**:

```json
{
  "ip": "string",                    // Endereço IP
  "hostnames": ["string"],           // Hostnames associados
  "ports": ["number"],               // Portas abertas
  "vulns": ["string"],               // Vulnerabilidades (CVEs)
  "os": "string",                    // Sistema operacional
  "isp": "string",                   // Provedor de internet
  "org": "string",                   // Organização
  "country_name": "string",          // Nome do país
  "country_code": "string",          // Código do país
  "city": "string",                  // Cidade
  "last_update": "string",           // Última atualização
  "services": [                      // Serviços detectados
    {
      "port": "number",              // Porta
      "service": "string",           // Nome do serviço
      "product": "string",           // Produto
      "version": "string",           // Versão
      "banner": "string",            // Banner
      "ssl": {                       // Informações SSL (se aplicável)
        "cert": {
          "issued": "string",        // Data de emissão
          "expires": "string",       // Data de expiração
          "issuer": "string",        // Emissor
          "subject": "string"        // Assunto
        }
      }
    }
  ],
  "_analise_metadata": {}            // Metadados comuns
}
```

## Índice de Feeds

**Nome do índice**: `analise_superficie_[empresa]_feed`

**Descrição**: Armazena notícias e alertas de segurança de feeds RSS.

**Esquema**:

```json
{
  "@timestamp": "string",            // Timestamp da entrada
  "feed_name": "string",             // Nome do feed
  "feed_title": "string",            // Título do feed
  "feed_description": "string",      // Descrição do feed
  "feed_link": "string",             // Link do feed
  "feed_updated": "string",          // Data de atualização do feed
  "entry_id": "string",              // ID da entrada
  "title": "string",                 // Título da entrada
  "link": "string",                  // Link da entrada
  "published": "string",             // Data de publicação
  "summary": "string",               // Resumo
  "author": "string",                // Autor
  "tags": ["string"],                // Tags
  "content_hash": "string",          // Hash do conteúdo
  "category": "string",              // Categoria
  "source_type": "string"            // Tipo de fonte
}
```

## Índice Telegram

**Nome do índice**: `analise_superficie_[empresa]_telegram`

**Descrição**: Armazena informações sobre vazamentos de dados coletados do Telegram.

**Esquema**:

```json
{
  "timestamp": "string",             // Timestamp da coleta
  "source_type": "string",           // Tipo de fonte (telegram)
  "channel_name": "string",          // Nome do canal
  "channel_id": "number",            // ID do canal
  "message_id": "number",            // ID da mensagem
  "message_date": "string",          // Data da mensagem
  "file_name": "string",             // Nome do arquivo
  "file_size": "number",             // Tamanho do arquivo
  "file_type": "string",             // Tipo do arquivo
  "file_hash": "string",             // Hash do arquivo
  "download_date": "string",         // Data do download
  "leak_type": "string",             // Tipo de vazamento
  "leak_count": "number",            // Contagem de registros vazados
  "domains_affected": ["string"],    // Domínios afetados
  "sample_format": "string",         // Formato da amostra
  "_analise_metadata": {}            // Metadados comuns
}
```
