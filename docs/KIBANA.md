# Guia de Visualização no Kibana

Este guia fornece instruções para configurar visualizações e dashboards no Kibana para analisar os dados coletados pelo pipeline de análise de superfície de ataque.

## Índice

1. [Configuração Inicial](#configuração-inicial)
2. [Padrões de Índice](#padrões-de-índice)
3. [Dashboards Recomendados](#dashboards-recomendados)
4. [Visualizações Úteis](#visualizações-úteis)
5. [Exemplos de Consultas](#exemplos-de-consultas)
6. [Exportação e Importação](#exportação-e-importação)

## Configuração Inicial

### Acesso ao Kibana

1. Abra o navegador e acesse `http://localhost:5601`
2. Faça login (se necessário)

### Configuração de Tempo Padrão

1. Vá para "Stack Management" > "Advanced Settings"
2. Defina "Default time field" como `@timestamp`
3. Defina "Time filter defaults" para um período adequado (ex: últimos 30 dias)

## Padrões de Índice

### Criação de Padrões de Índice

Para cada empresa analisada, crie os seguintes padrões de índice:

1. **Todos os índices da empresa**:
   - Vá para "Stack Management" > "Index Patterns"
   - Clique em "Create index pattern"
   - Digite `analise_superficie_[empresa]_*`
   - Selecione `@timestamp` como campo de tempo (se disponível)

2. **Índices específicos** (opcional):
   - `analise_superficie_[empresa]_dns`
   - `analise_superficie_[empresa]_whois`
   - `analise_superficie_[empresa]_coletor_*`
   - `analise_superficie_[empresa]_shodan`
   - `analise_superficie_[empresa]_feed`

## Dashboards Recomendados

### 1. Dashboard de Visão Geral

**Nome**: Visão Geral - [Empresa]

**Descrição**: Fornece uma visão geral de todos os resultados da análise.

**Visualizações**:
- Contagem total de domínios analisados
- Distribuição de pontuações DNS
- Top 10 vulnerabilidades encontradas
- Portas mais comuns
- Distribuição de serviços
- Notícias recentes relevantes

### 2. Dashboard de Análise DNS

**Nome**: Análise DNS - [Empresa]

**Descrição**: Foca na segurança DNS dos domínios analisados.

**Visualizações**:
- Distribuição de pontuações DNS
- Pontuações por categoria (DNSSEC, SPF, DMARC, etc.)
- Problemas críticos encontrados
- Distribuição de notas (A, B, C, D, F)
- Recomendações prioritárias

### 3. Dashboard de Exposição Web

**Nome**: Exposição Web - [Empresa]

**Descrição**: Analisa serviços web expostos e suas configurações.

**Visualizações**:
- Distribuição de códigos de status HTTP
- Tecnologias detectadas
- Cabeçalhos de segurança ausentes
- Portas abertas por host
- Serviços mais comuns

### 4. Dashboard de Certificados SSL

**Nome**: Certificados SSL - [Empresa]

**Descrição**: Analisa certificados SSL/TLS e suas configurações.

**Visualizações**:
- Distribuição de versões TLS
- Autoridades certificadoras mais comuns
- Certificados expirando em breve
- Problemas de segurança em certificados
- Subject Alternative Names (SANs) encontrados

### 5. Dashboard de Vulnerabilidades

**Nome**: Vulnerabilidades - [Empresa]

**Descrição**: Foca nas vulnerabilidades detectadas pelo Nuclei.

**Visualizações**:
- Vulnerabilidades por severidade
- Top 10 vulnerabilidades
- Hosts mais vulneráveis
- Vulnerabilidades por categoria
- Timeline de detecção

### 6. Dashboard de Shodan

**Nome**: Análise Shodan - [Empresa]

**Descrição**: Analisa informações coletadas do Shodan.

**Visualizações**:
- Distribuição geográfica de IPs
- Sistemas operacionais detectados
- CVEs encontradas
- Serviços expostos
- Organizações e ISPs

### 7. Dashboard de Feeds

**Nome**: Feeds de Segurança - [Empresa]

**Descrição**: Mostra notícias e alertas de segurança relevantes.

**Visualizações**:
- Notícias recentes por categoria
- Fontes mais ativas
- Timeline de publicações
- Tag cloud de tópicos
- Autores mais frequentes

## Visualizações Úteis

### Para Análise DNS

#### Pontuação DNS por Domínio

**Tipo**: Horizontal Bar Chart

**Configuração**:
- Métrica Y: `adint.com.br.total_score` (e outros domínios)
- Eixo X: Domínio

#### Problemas Críticos de DNS

**Tipo**: Data Table

**Configuração**:
- Split Rows: `adint.com.br.security_scores.category`
- Métrica: Count
- Filtro: `adint.com.br.security_scores.severity: "critical"`

### Para Vulnerabilidades

#### Vulnerabilidades por Severidade

**Tipo**: Pie Chart

**Configuração**:
- Split Slices: `info.severity.keyword`
- Métrica: Count

#### Top 10 Vulnerabilidades

**Tipo**: Data Table

**Configuração**:
- Split Rows: `template-id.keyword`
- Métrica: Count
- Ordenar por: Count (descendente)
- Tamanho: 10

### Para Shodan

#### Mapa de IPs

**Tipo**: Maps

**Configuração**:
- Geo Coordinates: `location.lat` e `location.lon`
- Métrica: Count

#### Serviços por Porta

**Tipo**: Horizontal Bar Chart

**Configuração**:
- Eixo Y: `services.port`
- Métrica X: Count

## Exemplos de Consultas

### Encontrar Domínios com Problemas Críticos de DNS

```
_index:analise_superficie_[empresa]_dns AND adint.com.br.security_scores.severity:critical
```

### Encontrar Vulnerabilidades de Alta Severidade

```
_index:analise_superficie_[empresa]_coletor_nuclei AND info.severity:high
```

### Encontrar Hosts com Portas Sensíveis Abertas

```
_index:analise_superficie_[empresa]_coletor_naabu AND port:(22 OR 3389 OR 1433 OR 3306)
```

### Encontrar Certificados Expirando em Breve

```
_index:analise_superficie_[empresa]_coletor_tlsx AND not_after:[now TO now+30d]
```

### Encontrar Notícias Sobre Vulnerabilidades Específicas

```
_index:analise_superficie_[empresa]_feed AND (title:CVE* OR summary:CVE*)
```

## Exportação e Importação

### Exportar Dashboards

1. Vá para "Stack Management" > "Saved Objects"
2. Selecione os dashboards que deseja exportar
3. Clique em "Export"
4. Salve o arquivo JSON

### Importar Dashboards

1. Vá para "Stack Management" > "Saved Objects"
2. Clique em "Import"
3. Selecione o arquivo JSON
4. Resolva conflitos se necessário

### Compartilhar Dashboards

1. Abra o dashboard que deseja compartilhar
2. Clique em "Share"
3. Escolha uma das opções:
   - "Snapshot" para compartilhar uma imagem
   - "Saved Object" para compartilhar o objeto salvo
   - "Embed Code" para incorporar em outra página
   - "Short URL" para gerar uma URL curta

## Dicas Avançadas

### Uso de Runtime Fields

Para criar campos calculados em tempo real:

1. Vá para "Stack Management" > "Index Patterns"
2. Selecione o padrão de índice
3. Clique em "Runtime fields" > "Add runtime field"
4. Configure o campo conforme necessário

### Uso de Transforms

Para agregar dados e criar novos índices:

1. Vá para "Stack Management" > "Transforms"
2. Clique em "Create transform"
3. Configure a transformação conforme necessário

### Alertas

Para configurar alertas baseados em condições:

1. Vá para "Stack Management" > "Rules and Connectors"
2. Clique em "Create rule"
3. Configure a regra conforme necessário
