# Guia de Instalação do Pipeline de Análise de Superfície

Este guia fornece instruções detalhadas para instalar e configurar o pipeline de análise de superfície de ataque.

## Requisitos do Sistema

### Hardware Recomendado

- CPU: 4 cores ou mais
- RAM: 8GB ou mais
- Armazenamento: 20GB de espaço livre

### Software Necessário

- Sistema Operacional: Linux (recomendado), macOS ou Windows com WSL
- Python 3.6+
- Docker (para Elasticsearch/Kibana, opcional)
- Ferramentas de linha de comando: curl, dig, jq

## Instalação Passo a Passo

### 1. Preparação do Ambiente

#### Instalação de Dependências no Ubuntu/Debian

```bash
# Atualizar repositórios
sudo apt update

# Instalar Python e ferramentas essenciais
sudo apt install -y python3 python3-pip python3-venv curl dig jq git

# Instalar ferramentas de segurança
sudo apt install -y whois nmap
```

#### Instalação de Dependências no macOS

```bash
# Instalar Homebrew (se necessário)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar Python e ferramentas essenciais
brew install python3 curl bind jq git

# Instalar ferramentas de segurança
brew install whois nmap
```

### 2. Clone do Repositório

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/adint-pipeline.git
cd adint-pipeline
```

### 3. Configuração do Ambiente Python

```bash
# Criar e ativar ambiente virtual (opcional, mas recomendado)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# ou
venv\Scripts\activate     # Windows

# Instalar dependências Python
pip install -r requirements.txt
```

### 4. Instalação do Elasticsearch e Kibana

#### Usando Docker (recomendado)

```bash
# Criar rede Docker
docker network create elastic

# Iniciar Elasticsearch
docker run -d --name elasticsearch --net elastic -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:7.17.0

# Iniciar Kibana
docker run -d --name kibana --net elastic -p 5601:5601 docker.elastic.co/kibana/kibana:7.17.0
```

#### Instalação Nativa

Consulte a [documentação oficial do Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html) e [Kibana](https://www.elastic.co/guide/en/kibana/current/install.html) para instruções detalhadas.

### 5. Instalação das Ferramentas de Coleta

#### Subfinder

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
```

#### HTTPX

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
```

#### Naabu

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu
```

#### TLSX

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/tlsx/cmd/tlsx
```

#### Nuclei

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

### 6. Configuração da API do Shodan

```bash
# Instalar CLI do Shodan
pip install shodan

# Configurar API Key
shodan init YOUR_API_KEY
```

### 7. Configuração do Telegram (Opcional)

```bash
# Criar ambiente virtual específico para o Telegram
python3 -m venv telegram_venv
source telegram_venv/bin/activate  # Linux/macOS
# ou
telegram_venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r TELEGRAM/requirements.txt

# Configurar API do Telegram
# Siga as instruções em TELEGRAM/README.md
```

### 8. Verificação da Instalação

Execute o script de configuração para verificar se todas as dependências estão instaladas corretamente:

```bash
./setup.sh
```

## Configuração

### Configuração do Pipeline

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

### Configuração do Elasticsearch

Por padrão, o pipeline se conecta ao Elasticsearch em `localhost:9200`. Para alterar isso:

```bash
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt -h elasticsearch.local -p 9200
```

### Configuração de Feeds RSS

Edite o arquivo `FEED/feeds.yaml` para adicionar, remover ou modificar feeds RSS:

```yaml
categories:
  - name: "Cybersecurity (News/Análises)"
    feeds:
      - name: "The Register » Security (Atom)"
        url: "https://www.theregister.com/security/headlines.atom"
      # ... outros feeds ...
```

## Troubleshooting

### Problemas Comuns

#### Erro de Conexão com Elasticsearch

**Sintoma**: Mensagem de erro indicando falha na conexão com o Elasticsearch.

**Solução**:
1. Verifique se o Elasticsearch está em execução: `curl http://localhost:9200`
2. Verifique as configurações de firewall
3. Verifique as configurações de host e porta no comando ou no arquivo de configuração

#### Erro ao Instalar Ferramentas Go

**Sintoma**: Erros ao instalar as ferramentas como subfinder, httpx, etc.

**Solução**:
1. Verifique se o Go está instalado e configurado corretamente: `go version`
2. Verifique se `$GOPATH/bin` está no seu PATH
3. Tente instalar manualmente cada ferramenta

#### Erro com API do Telegram

**Sintoma**: Erros ao tentar usar a ferramenta Telegram.

**Solução**:
1. Verifique se você criou e configurou corretamente a API do Telegram
2. Verifique se o ambiente virtual do Telegram está ativado
3. Consulte o arquivo `TELEGRAM/README.md` para instruções detalhadas

## Próximos Passos

Após a instalação e configuração, você pode:

1. [Executar o pipeline](./README.md#guias-de-uso)
2. [Configurar dashboards no Kibana](./KIBANA.md)
3. [Personalizar o pipeline](./CUSTOMIZATION.md)
