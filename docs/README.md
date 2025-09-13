# Documentação do Pipeline de Análise de Superfície de Ataque

Esta documentação fornece detalhes sobre o pipeline de análise de superfície de ataque, incluindo sua arquitetura, componentes, estrutura de dados e guias de uso.

## 📑 Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura](#arquitetura)
3. [Componentes](#componentes)
4. [Estrutura de Dados](#estrutura-de-dados)
5. [Guias de Uso](#guias-de-uso)
6. [Exemplos](#exemplos)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

## 📋 Visão Geral

O pipeline de análise de superfície de ataque é uma solução integrada para coletar, processar e analisar informações de segurança sobre domínios e infraestrutura de uma organização. Ele combina várias ferramentas especializadas em um fluxo de trabalho unificado, enviando os resultados para o Elasticsearch para análise posterior.

### Objetivos

- Automatizar a coleta de informações sobre domínios e infraestrutura
- Identificar vulnerabilidades e problemas de configuração
- Centralizar os resultados em um único sistema (Elasticsearch)
- Facilitar a análise e visualização dos dados coletados

### Ferramentas Integradas

- **WHOIS**: Consulta informações de registro de domínios
- **DNS**: Analisa configurações DNS e atribui pontuação de segurança
- **COLETOR**: Executa subfinder, httpx, naabu, tlsx e nuclei
- **SHODAN**: Consulta informações no Shodan para domínios e IPs
- **FEED**: Coleta feeds RSS de segurança relevantes
- **TELEGRAM**: Coleta dados de vazamentos do Telegram (opcional, requer configuração)

## 🏗️ Arquitetura

O pipeline segue uma arquitetura modular, onde cada componente é responsável por uma etapa específica do processo de análise. O script principal (`adint_pipeline.py`) orquestra a execução das ferramentas e o envio dos resultados para o Elasticsearch.

### Fluxo de Execução

1. **Inicialização**: O pipeline recebe o nome da empresa e lista de domínios
2. **Preparação**: Cria estrutura de diretórios e índices no Elasticsearch
3. **Execução**: Executa cada ferramenta na sequência configurada
4. **Processamento**: Processa os resultados e envia para o Elasticsearch
5. **Finalização**: Gera relatório final com links para os índices

### Diagrama de Componentes

```
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
|  Entrada       |     |  Pipeline      |     |  Ferramentas   |
|  - Empresa     | --> |  Principal     | --> |  - WHOIS       |
|  - Domínios    |     |  (Python)      |     |  - DNS         |
|  - Notas       |     |                |     |  - COLETOR     |
|                |     |                |     |  - SHODAN      |
+----------------+     +----------------+     +----------------+
                             |
                             v
                      +----------------+     +----------------+
                      |                |     |                |
                      |  Processamento | --> |  Elasticsearch |
                      |  de Resultados |     |  (Índices)     |
                      |                |     |                |
                      +----------------+     +----------------+
                                              |
                                              v
                                       +----------------+
                                       |                |
                                       |  Visualização  |
                                       |  (Kibana)      |
                                       |                |
                                       +----------------+
```

## 🧩 Componentes

### Script Principal

O script `adint_pipeline.py` é o componente central do pipeline, responsável por:

- Processar argumentos de linha de comando
- Configurar o ambiente de execução
- Orquestrar a execução das ferramentas
- Processar e enviar resultados para o Elasticsearch

### Ferramentas

#### WHOIS

- **Script**: `WHOIS/whois_universal.py`
- **Função**: Consulta informações de registro de domínios
- **Saída**: Informações detalhadas sobre registros de domínios

#### DNS

- **Script**: `DNS/dns-security-analyzer.py`
- **Função**: Analisa configurações DNS e atribui pontuação de segurança
- **Saída**: Análise detalhada de segurança DNS, incluindo pontuação e recomendações

#### COLETOR

- **Script**: `COLETOR/coletor.sh`
- **Função**: Executa ferramentas de coleta (subfinder, httpx, naabu, tlsx, nuclei)
- **Saída**: Informações sobre subdomínios, serviços web, portas abertas, certificados SSL e vulnerabilidades

#### SHODAN

- **Script**: `SHODAN/unified_shodan_scanner.py`
- **Função**: Consulta informações no Shodan para domínios e IPs
- **Saída**: Informações detalhadas sobre serviços, vulnerabilidades e exposição na internet

#### FEED

- **Script**: `FEED/rss_feed.py`
- **Função**: Coleta feeds RSS de segurança relevantes
- **Saída**: Notícias e alertas de segurança recentes

#### TELEGRAM

- **Script**: `TELEGRAM/download_Combo.py`
- **Função**: Coleta dados de vazamentos do Telegram (opcional)
- **Saída**: Informações sobre vazamentos de dados

### Configuração

O arquivo `pipeline_config.yaml` contém a configuração do pipeline, incluindo:

- Ferramentas habilitadas/desabilitadas
- Caminhos para scripts
- Configurações específicas por ferramenta
- Configurações do Elasticsearch

## 📊 Estrutura de Dados

O pipeline armazena os resultados em índices do Elasticsearch, com um prefixo específico (`analise_superficie_*`).

### Índices

- `analise_superficie_[empresa]_metadata`: Metadados da execução do pipeline
- `analise_superficie_[empresa]_whois`: Resultados das consultas WHOIS
- `analise_superficie_[empresa]_dns`: Resultados das análises DNS
- `analise_superficie_[empresa]_coletor_*`: Resultados do COLETOR (httpx, naabu, tlsx, nuclei)
- `analise_superficie_[empresa]_shodan`: Resultados das consultas Shodan
- `analise_superficie_[empresa]_feed`: Feeds RSS relevantes
- `analise_superficie_[empresa]_telegram`: Dados de vazamentos (opcional)

### Metadados

Todos os documentos incluem um campo `_analise_metadata` com informações sobre a execução:

```
"_analise_metadata": {
  "company": "NOME_DA_EMPRESA",
  "timestamp": "YYYYMMDD_HHMMSS",
  "pipeline_run": "YYYYMMDD_HHMMSS"
}
```

### Exemplos de Documentos

Consulte a pasta `samples/` para exemplos de documentos armazenados em cada índice.

## 📘 Guias de Uso

### Instalação

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/seu-usuario/pipeline-analise-superficie.git
   cd adint-pipeline
   ```

2. **Execute o script de configuração**:
   ```bash
   ./setup.sh
   ```

### Execução Básica

```bash
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt
```

### Opções Avançadas

```bash
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt -n "Observações" -h elasticsearch.local -p 9200 -o resultados
```

### Configuração Personalizada

Edite o arquivo `pipeline_config.yaml` para personalizar o comportamento do pipeline:

```yaml
tools:
  whois:
    enabled: true
    script: WHOIS/whois_universal.py
    index: whois
  
  # ... outras ferramentas ...

elasticsearch:
  index_settings:
    number_of_shards: 1
    number_of_replicas: 0
```

### Visualização no Kibana

1. Acesse o Kibana
2. Vá para "Stack Management" > "Index Patterns"
3. Crie um padrão de índice `analise_superficie_[empresa]_*`
4. Explore os dados usando o Discover ou crie dashboards

## 🔍 Exemplos

### Exemplo: Análise de Domínios Corporativos

```bash
./run_pipeline.sh -c "Acme Corp" -d dominios.txt -n "Análise trimestral de segurança"
```

### Exemplo: Análise Focada em DNS

Edite `pipeline_config.yaml` para habilitar apenas a ferramenta DNS:

```yaml
tools:
  whois:
    enabled: false
  dns:
    enabled: true
  coletor:
    enabled: false
  # ...
```

```bash
./run_pipeline.sh -c "Acme Corp" -d dominios.txt
```

## 🔧 Troubleshooting

### Problemas Comuns

#### Erro de Conexão com Elasticsearch

**Sintoma**: Mensagem de erro indicando falha na conexão com o Elasticsearch.

**Solução**:
1. Verifique se o Elasticsearch está em execução: `curl http://localhost:9200`
2. Verifique as configurações de host e porta no comando ou no arquivo de configuração

#### Falha em uma Ferramenta Específica

**Sintoma**: O pipeline executa, mas uma ferramenta específica falha.

**Solução**:
1. Verifique se a ferramenta está instalada e configurada corretamente
2. Verifique os logs específicos da ferramenta
3. Execute a ferramenta manualmente para identificar o problema

### Logs

Os logs do pipeline são armazenados no arquivo `adint_pipeline.log`. Consulte este arquivo para informações detalhadas sobre a execução.

## ❓ FAQ

### Como adicionar uma nova ferramenta ao pipeline?

1. Adicione o script da ferramenta em um diretório apropriado
2. Atualize o arquivo `pipeline_config.yaml` para incluir a nova ferramenta
3. Modifique o script `adint_pipeline.py` para suportar a nova ferramenta

### Como personalizar os índices do Elasticsearch?

Edite a seção `elasticsearch` no arquivo `pipeline_config.yaml` para personalizar as configurações dos índices.

### O pipeline funciona com Elasticsearch em cluster?

Sim, basta especificar o host e porta corretos ao executar o pipeline.

### Como desabilitar uma ferramenta específica?

Edite o arquivo `pipeline_config.yaml` e defina `enabled: false` para a ferramenta que deseja desabilitar.

### Como atualizar os feeds RSS?

Edite o arquivo `FEED/feeds.yaml` para adicionar, remover ou modificar feeds RSS.

### Como configurar a API do Telegram?

Consulte o arquivo `TELEGRAM/README.md` para instruções detalhadas sobre como configurar a API do Telegram.
