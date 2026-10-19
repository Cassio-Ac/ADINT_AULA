# Guia de Instalação do Pipeline de Análise de Superfície

Este guia mostra, passo a passo, como instalar e configurar o pipeline ADINT de análise de
superfície de ataque. O objetivo é que, ao final, você consiga rodar o pipeline e ver os dados
chegando no Elasticsearch/Kibana.

Se você ainda não leu o [README do projeto](../README.md), leia primeiro: ele explica o fluxo
(**coletar → tratar → armazenar → utilizar**) e traz o aviso de autorização. Resumindo o aviso:
WHOIS, DNS e Shodan são passivos, mas `httpx`, `naabu` e `nuclei` **mandam pacote para o alvo**.
Só escaneie o que é seu ou o que você tem autorização escrita para testar. Para treinar sem
risco, use `vulnweb.com` ou suba o OWASP Juice Shop do `docker-compose.yml`
(`docker compose --profile targets up -d juiceshop`).

> **Convenção deste guia.** Todo bloco de comando está marcado com onde ele roda:
> **Linux/WSL (bash)** ou **Windows (PowerShell)**. Nenhum caminho absoluto de máquina
> aparece aqui: `~/` é o seu HOME e `<pasta-do-projeto>` é a pasta onde você clonou o
> repositório. Os comandos assumem que você está **na raiz do projeto**.

## O ambiente tem duas metades

- **Pipeline + ferramentas de coleta** (Python + ferramentas em Go + `bash`): rodam em
  **Linux, macOS ou Windows com WSL2**. O `COLETOR/coletor.sh` é `bash` e usa utilitários
  Unix (`dig`, `jq`, `awk`, `column`, `bc`, `tee`), então na prática a coleta precisa de um
  shell Linux/WSL.
- **Elasticsearch + Kibana**: o jeito **recomendado** é via **Docker**, com o
  `docker-compose.yml` que já vem na raiz do projeto. A alternativa é uma instalação nativa
  (ver Opção B no passo 5).

Os dois lados conversam por HTTP na porta 9200. Se você usar WSL para a coleta e o
Elasticsearch em outro host, aponte o pipeline para o host certo com `--es-host`.

## 1. Requisitos do sistema

### Hardware recomendado

- CPU: 4 cores ou mais
- RAM: 8 GB ou mais (o container do Elasticsearch já sobe com `-Xms1g -Xmx1g`, e o Kibana
  come mais um tanto)
- Armazenamento: 20 GB livres

### Software necessário

| O quê | Versão | Para quê |
|---|---|---|
| Linux ou **WSL2** (Ubuntu 22.04/24.04) / macOS | — | as ferramentas de coleta são Unix |
| **Python 3.10+** | testado no 3.12 | scripts do pipeline |
| **Docker** | — | sobe Elasticsearch + Kibana |
| **Elasticsearch 8.x** | testado no 8.15.3 | armazenamento |
| Utilitários de linha de comando | — | `curl`, `dig`, `jq`, `awk`, `column`, `bc`, `tee` |
| **Go** | opcional | só se você quiser compilar as ferramentas em vez de usar o `pdtm` |

> **O Elasticsearch é 8.x, não 9.x.** O cliente Python está fixado em `elasticsearch>=8,<9`
> no `requirements.txt` (a 9.x removeu o parâmetro `timeout=` do construtor). Suba um
> servidor **8.x** — o `docker-compose.yml` e o `.env.example` já apontam para o 8.15.3.

### Visão geral das dependências

| Componente | Para que serve | Como instalar |
| --- | --- | --- |
| Python + `requirements.txt` | pipeline, WHOIS, DNS, Shodan, FEED, MCP | `pip install -r requirements.txt` |
| `dnsutils` (dá o `dig`) | coletor e analisador DNS | `apt install dnsutils` |
| `jq`, `bc`, `gawk`, `bsdmainutils` (dá o `column`) | `COLETOR/coletor.sh` | `apt install ...` |
| `libpcap-dev` | requisito de sistema do `naabu` | `apt install libpcap-dev` |
| `pdtm` | gerenciador oficial das ferramentas ProjectDiscovery | binário pré-compilado (releases) |
| subfinder, httpx, naabu, tlsx, nuclei | coleta de superfície (`coletor.sh`) | `pdtm -i ... -ip` |
| CLI `shodan` | varredura Shodan | já vem no `requirements.txt` |
| `telethon` | coleta do Telegram (opcional) | ver passo 8 |
| Docker | Elasticsearch + Kibana | `docker compose up -d` |

## 2. Dependências do sistema

### Ubuntu/Debian (ou WSL) — Linux/WSL (bash)

```bash
sudo apt update

# Python e básicos
sudo apt install -y python3 python3-pip python3-venv git curl

# Utilitários usados pelo coletor:
#  - dnsutils fornece o comando "dig" (NÃO existe pacote chamado "dig")
#  - bsdmainutils fornece o comando "column"
#  - bc e jq são usados no coletor.sh (jq em toda parte, bc na barra de progresso)
sudo apt install -y dnsutils jq bc gawk bsdmainutils

# WHOIS de linha de comando (útil para testes manuais)
sudo apt install -y whois

# libpcap-dev é requisito de sistema do naabu
sudo apt install -y libpcap-dev

# Opcionais, usados nas aulas de DNS:
sudo apt install -y dnsmap dnsrecon
```

> **Go é opcional.** As ferramentas do Project Discovery são instaladas pelo `pdtm`, que é um
> binário pré-compilado (passo 6). Só instale o `golang-go` se quiser compilar as ferramentas
> na mão: `sudo apt install -y golang-go`.

### macOS (Homebrew) — bash/zsh

```bash
# Instalar o Homebrew (se necessário)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python, utilitários e libpcap
#  - "bind" fornece o dig no macOS
brew install python3 git curl jq bc gawk bind libpcap whois
```

## 3. Obter o projeto

### Linux/WSL (bash)

```bash
git clone https://github.com/Cassio-Ac/ADINT_AULA.git
cd ADINT_AULA
```

Você deve ver na raiz: `adint_pipeline.py`, `pipeline_config.yaml`, `requirements.txt`,
`run_pipeline.sh`, `setup.sh`, `docker-compose.yml`, `.env.example` e as pastas `WHOIS/`,
`DNS/`, `COLETOR/`, `SHODAN/`, `FEED/`, `TELEGRAM/`, `ELK/`, `docs/`.

**Daqui para frente, todos os comandos assumem que você está nessa pasta.** Isso não é
preciosismo — veja a armadilha nº 4 no passo 11.

## 4. Ambiente Python

### Linux/WSL (bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell) — só se você for rodar algo fora do WSL

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **O ambiente virtual não é "opcional, recomendado" neste projeto: é o jeito de funcionar.**
> O orquestrador repassa o *mesmo* interpretador que o chamou para cada etapa — se você
> chamar com o Python do sistema, todas as etapas herdam um ambiente sem `elasticsearch`,
> `whois` e `shodan`. É a armadilha nº 3, detalhada no passo 11.

O `requirements.txt` instala, entre outros:

- `elasticsearch>=8,<9` — cliente do Elasticsearch. **Fixado de propósito**: a 9.x removeu o
  parâmetro `timeout=` do construtor e o pipeline usa `request_timeout=`.
- `mcp<2` — servidor MCP. **Fixado de propósito**: a 2.x renomeou `FastMCP` → `MCPServer`, e
  o `mcp_exposure_poc.py` usa a API v1 (`FastMCP`).
- `setuptools<80` — **fixado de propósito**: a CLI do Shodan importa `pkg_resources`, que o
  setuptools ≥81 removeu e que o venv do Python 3.12 não traz.
- `dnspython`, `python-whois` — analisador DNS.
- `pyyaml` — leitura do `pipeline_config.yaml` e do `FEED/feeds.yaml`.
- `requests`, `feedparser`, `shodan` — Shodan, feeds RSS e servidor MCP.
- `python-dotenv` — carrega o `.env` (chaves do Shodan/Telegram, host do Elasticsearch).
- `tqdm`, `python-dateutil` — importador do Telegram e PoC MCP.

> Esses três pins têm motivo escrito no próprio `requirements.txt`. Não "atualize" sem ler o
> comentário: quebra na hora.

## 5. Elasticsearch e Kibana

Você precisa de um Elasticsearch **8.x** (e, de preferência, Kibana) no ar.

### Opção A — Docker (recomendado)

Precisa do **Docker** (Docker Desktop no Windows com a integração WSL habilitada, ou Docker
dentro do Linux/WSL). O `docker-compose.yml` da raiz sobe Elasticsearch + Kibana em **modo
aula** (nó único, **sem segurança**) e já traz a liberação do `action.auto_create_index` — ou
seja, os subíndices do coletor são criados sem configuração extra.

#### Linux/WSL (bash)

```bash
# O Elasticsearch exige este limite de memória virtual:
sudo sysctl -w vm.max_map_count=262144

# Na raiz do projeto:
docker compose up -d

# No primeiro boot, aguarde ~1 min e teste:
curl -s http://localhost:9200 | jq -r .version.number     # deve responder 8.x
```

Kibana em <http://localhost:5601>.

- A versão do stack vem do `.env` (`STACK_VERSION`, por padrão **8.15.3**).
- `docker compose up -d` sobe **só** `es` e `kibana`. Os serviços `pipeline` e `juiceshop`
  estão atrás de *profiles* e não sobem sozinhos.
- Parar mantendo os dados: `docker compose down`. Resetar tudo (apaga): `docker compose down -v`.
  Os dados ficam no volume `es-data`.

> Com Docker Desktop no Windows + integração WSL, `localhost:9200` normalmente funciona dos
> dois lados. Se não funcionar, descubra o IP e passe `--es-host <IP>` ao pipeline.

### Opção B — Elasticsearch/Kibana nativo no Windows

Caminho alternativo, sem Docker. Instale o **Elasticsearch 8.x e o Kibana 8.x** (a mesma
família do cliente Python) e use os scripts da pasta `ELK\`.

**B.1 — aplicar a configuração da aula.** Copie `ELK\elastisearch.yml` do repositório,
sobrescrevendo o `elasticsearch.yml` da sua instalação (`<ES_HOME>` = a pasta onde você
instalou o Elasticsearch):

#### Windows (PowerShell)

```powershell
Copy-Item ".\ELK\elastisearch.yml" "<ES_HOME>\config\elasticsearch.yml" -Force
```

> O nome no repositório é `elastisearch.yml` (sem o segundo "c"); o destino é sempre
> `config\elasticsearch.yml`. Essa config roda em nó único, **desabilita a segurança**,
> escuta em `0.0.0.0:9200` e **libera a auto-criação** dos índices via
> `action.auto_create_index` — sem isso, os subíndices do coletor
> (`_coletor_httpx/_naabu/_certs/_san/_nuclei`) **não são criados**.

**B.2 — iniciar.** Use `ELK\start-elasticsearch-aula.bat`. Ele traz um `ES_HOME` fixo na
primeira linha útil (`set ES_HOME=...`): **edite essa linha para o caminho da sua
instalação** antes de rodar. O script ajusta o `ES_HOME`, chama `bin\elasticsearch.bat` e
deixa a janela aberta (`Ctrl+C` para parar). Se uma tentativa anterior deixou keystore/certs
conflitantes, rode antes `ELK\elastic_aula.bat` para limpar.

#### Windows (PowerShell)

```powershell
.\ELK\start-elasticsearch-aula.bat
```

**B.3 — Kibana.** Instale e rode o Kibana 8.x; ele sobe em `http://localhost:5601`.

### Testar (qualquer uma das opções)

#### Linux/WSL (bash)

```bash
curl -s http://localhost:9200 | jq -r .version.number
```

Se a coleta estiver no WSL e o Elasticsearch em outra máquina, teste com o IP correto
(`curl http://<IP>:9200`).

### Kibana: criar o Data View

No Kibana, o antigo **Index Patterns** passou a se chamar **Data Views** (desde o 8.0) — é lá
que você cadastra os índices do pipeline. O caminho, pela interface:

1. <http://localhost:5601> → menu → **Stack Management** → **Data Views** → **Create data view**.
2. **Index pattern**: `analise_superficie_*` (um único Data View cobre WHOIS, DNS, Shodan e
   todos os subíndices do coletor). Para os feeds RSS, crie um segundo com `rss-feeds*`.
3. **Timestamp field**: aqui mora uma sutileza. Os índices que o pipeline cria explicitamente
   (`_metadata`, `_whois`, `_dns`, `_shodan`, `_coletor`) mapeiam `timestamp` como `date`,
   com o formato `yyyyMMdd_HHmmss` declarado no mapeamento. Já os **subíndices do coletor**
   (`_coletor_httpx`, `_naabu`, `_certs`, `_san`, `_nuclei`) nascem por auto-criação do
   Elasticsearch, com mapeamento dinâmico — lá o mesmo campo cai como texto. Num Data View
   que cubra os dois grupos, `timestamp` pode aparecer marcado como *conflict* e não servir
   como campo de tempo. Nesse caso escolha **"I don't want to use the time filter"** e
   filtre pelos campos (abaixo). Só o índice `rss-feeds` usa `@timestamp` de verdade.
4. Em **Discover**, para ver uma empresa só, filtre por
   `company_slug.keyword : "minhaempresa"` — os índices são compartilhados por todas as
   empresas (veja "Índices e campos" no passo 11).

## 6. Ferramentas de coleta (pdtm)

O `COLETOR/coletor.sh` orquestra as cinco ferramentas do Project Discovery nesta ordem:
**subfinder → httpx → naabu → tlsx → nuclei**. Elas são instaladas pelo **pdtm**, o
gerenciador oficial deles.

Instale o `pdtm` a partir do binário pré-compilado (veja
<https://github.com/projectdiscovery/pdtm/releases>) e depois, **com o seu usuário comum**:

#### Linux/WSL (bash)

```bash
pdtm -i subfinder,httpx,naabu,nuclei,tlsx -ip
source ~/.bashrc
```

- `-i` instala as ferramentas listadas.
- `-ip` faz o **próprio pdtm** acrescentar o caminho dos binários ao seu `~/.bashrc` — você
  não precisa editar PATH na mão. O `source ~/.bashrc` é só para valer já nesta sessão.
- Os binários vão para `~/.pdtm/go/bin`.

Confira sempre **onde** eles foram parar:

```bash
pdtm -sp -silent     # imprime o diretório dos binários, uma linha, sem cor
```

O `coletor.sh` procura os binários nesta ordem: `$PD_BIN_DIR` → `pdtm -sp -silent` →
`~/.pdtm/go/bin` → `PATH`. Se precisar apontar na mão:

```bash
export PD_BIN_DIR="$(pdtm -sp -silent)"
```

> [!WARNING]
> ### Armadilha nº 1 — nunca instale o pdtm com `sudo`
>
> O pdtm instala no HOME de **quem rodou o comando**. Com `sudo`, as ferramentas vão para
> `/root/.pdtm/go/bin` — e `/root` é `drwx------`, então o seu usuário comum **não consegue
> nem entrar lá**.
>
> O sintoma é cruel: o coletor aborta com
>
> ```
> ✗ binário não encontrado: subfinder
> ```
>
> **com o subfinder instalado e funcionando.** A mensagem diz *"não encontrado"* quando o
> problema é *"não visível"*. É **permissão, não ausência**.
>
> A correção é reinstalar com o seu próprio usuário (sem `sudo`) e conferir com
> `pdtm -sp -silent`: o caminho impresso tem que estar dentro do **seu** HOME, não em
> `/root`.

> [!CAUTION]
> ### Armadilha nº 2 — existem dois programas chamados `httpx`
>
> O `httpx` do Project Discovery é um **scanner** escrito em Go. O `httpx` do PyPI é uma
> **biblioteca HTTP** do Python, com um binário de mesmo nome. Se a biblioteca estiver no
> PATH antes do scanner, o coletor chama a errada e a saída não faz sentido nenhum.
>
> ```bash
> command -v httpx     # deve apontar para o httpx do pdtm (~/.pdtm/go/bin/httpx)
> httpx -version       # o scanner se identifica: v1.x.x, projectdiscovery.io
> ```
>
> Se `httpx -version` não falar em `projectdiscovery.io`, é a biblioteca do Python. Resolva o
> PATH (ou `export PD_BIN_DIR="$(pdtm -sp -silent)"`) antes de seguir.

### naabu roda sem `sudo`

O `coletor.sh` chama o naabu **sem privilégio** (`-top-ports 1000 -json -silent`). Sem root o
naabu faz **CONNECT scan** e avisa:

```
[INF] Running CONNECT scan with non root privileges
```

Isso é **o modo de operação, não um erro** — não saia "consertando" com `sudo`. O requisito de
sistema do naabu é a `libpcap` (pacote `libpcap-dev`, instalado no passo 2).

### Alternativa: compilar na mão com `go install`

Só se você não quiser usar o `pdtm`. Use `go install ...@latest` (o antigo `go get` para
instalar binários foi descontinuado) e repare no `/v3` do nuclei:

#### Linux/WSL (bash)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

export PATH="$PATH:$(go env GOPATH)/bin"
```

Nesse caminho também vale a armadilha nº 1: rode como seu usuário, não com `sudo`.

### Utilitários exigidos pelo coletor

Além das cinco ferramentas, o `coletor.sh` exige `dig` (pacote `dnsutils`), `jq`, `awk`,
`column` (pacote `bsdmainutils`), `tee` e `bc`. Todos saíram do passo 2.

## 7. Chaves de API

### 7.1 O arquivo `.env`

#### Linux/WSL (bash)

```bash
cp .env.example .env
# edite o .env e preencha só o que você tiver
```

O `.env` guarda `STACK_VERSION`, `ES_HOST`/`ES_PORT`, `SHODAN_API_KEY`, as credenciais do
Telegram e a chave do Robtex. Ele está no `.gitignore` — **nunca comite suas chaves** e nunca
projete o arquivo preenchido numa tela compartilhada.

Contas gratuitas que valem a pena: **Shodan**, **VirusTotal**, **SecurityTrails** e um
**token do GitHub**.

### 7.2 Shodan

A CLI do Shodan já veio no `requirements.txt`. Há dois jeitos de dar a chave a ela, e o
scanner (`SHODAN/unified_shodan_scanner.py`) aceita os dois:

#### Linux/WSL (bash)

```bash
# Jeito 1 (preferido): põe a chave no .env
#   SHODAN_API_KEY=sua_chave_aqui
# O scanner detecta que a CLI não está inicializada e roda o "shodan init" sozinho.

# Jeito 2: inicializar a CLI na mão, uma vez
shodan init SUA_API_KEY
shodan info          # confirma que a chave vale e mostra seus créditos
```

Sem chave em nenhum dos dois lugares, a etapa do Shodan falha com uma mensagem pedindo
exatamente isso. Note que o scanner chama o executável `shodan` — ele precisa estar no PATH,
o que acontece quando o venv está ativo (outro motivo para o passo 4).

### 7.3 Chaves do subfinder (atenção: não é o `.env`)

**As chaves do subfinder NÃO vão no `.env`.** Ele é escrito em Go e lê um arquivo próprio:

#### Linux/WSL (bash)

```bash
mkdir -p ~/.config/subfinder
nano ~/.config/subfinder/provider-config.yaml
chmod 600 ~/.config/subfinder/provider-config.yaml
```

```yaml
virustotal:
  - SUA_CHAVE
securitytrails:
  - SUA_CHAVE
shodan:
  - SUA_CHAVE
github:
  - ghp_SEU_TOKEN
```

Cada fonte aceita **várias** chaves (o subfinder faz rodízio quando uma estoura o limite) —
por isso o formato é uma lista. O `.env.example` mantém `GITHUB_TOKEN` e
`SECURITYTRAILS_API_KEY` apenas como lembrete do que você tem; o subfinder não lê de lá.

## 8. Telegram (opcional)

A coleta de vazamentos via Telegram é **opcional** e **não** é executada pelo pipeline
automático. Ela usa a biblioteca `telethon`.

> **Não instale `TELEGRAM/requirements.txt` dentro do `.venv` do pipeline.** Esse arquivo
> fixa `elasticsearch==7.17.0` e **derrubaria** o cliente 8.x que o pipeline exige
> (`elasticsearch>=8,<9`). Você tem duas saídas:

#### Linux/WSL (bash)

```bash
# Saída 1 (mais simples): instale só o telethon no venv do pipeline,
# preservando o cliente elasticsearch 8.x que já está lá.
source .venv/bin/activate
pip install telethon

# Saída 2: venv dedicado, isolado do pipeline.
python3 -m venv telegram_venv
source telegram_venv/bin/activate
pip install -r TELEGRAM/requirements.txt
deactivate
```

> Se existir um `telegram_venv/` na raiz, o orquestrador o ativa para rodar a etapa
> `telegram` — etapa que, de todo modo, **não** faz parte do pipeline automático. O
> `import_to_elk.py` rodando dentro do `telegram_venv` fala com o Elasticsearch pelo cliente
> 7.17; se der problema de compatibilidade com o servidor 8.x, rode o importador pelo
> `.venv` do pipeline (saída 1).

As credenciais vêm do **`.env`** (lido com `python-dotenv`), não do código:

```
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_PHONE=
TELEGRAM_CHANNEL_ID=-100XXXXXXXXXX
TELEGRAM_INDEX=vazamentos_dados
```

Pegue `api_id`/`api_hash` em <https://my.telegram.org/apps>. Para descobrir o ID numérico de
um canal (formato `-100XXXXXXXXXX`), use `TELEGRAM/nome_grupos.py`.

> O `TELEGRAM/download_Combo.py` traz um ID de canal como *valor padrão* no código, usado
> quando `TELEGRAM_CHANNEL_ID` está vazio. **Defina sempre o seu** no `.env` em vez de
> depender desse padrão.

Scripts da pasta:

- `criar_sessao.py` — cria a sessão do Telethon (pede o código de login na primeira vez).
- `nome_grupos.py` — lista seus diálogos e os IDs numéricos.
- `download_Combo.py` — baixa arquivos do canal. Flags reais: `--limit`, `--ext`,
  `--since AAAA-MM-DD`, `--dry-run`. O diretório de saída é fixo
  (`TELEGRAM/downloads_omega_cloud`).
- `coletor_cve_leak.py` — coleta canais de CVE/vazamento.
- `import_to_elk.py` — importa o que foi baixado. Roda **sem argumentos** e grava no índice
  `vazamentos_dados` (ou no que estiver em `TELEGRAM_INDEX`).

## 9. Verificação da instalação

O `setup.sh` instala as dependências Python com `pip3 install -r requirements.txt` e confere
se `dig`, `jq` e `curl` existem; ele também oferece criar um venv separado para o Telegram.

> **Ative o `.venv` antes de rodar o `setup.sh`**, senão o `pip3` dele instala no Python do
> sistema. A oferta de criar o `telegram_venv` é o que o passo 8 chama de "saída 2": ela cria
> um venv **separado** com `elasticsearch==7.17.0` dentro, sem tocar no `.venv` do pipeline.
> Se você não vai usar o Telegram, responda "n".

#### Linux/WSL (bash)

```bash
source .venv/bin/activate
./setup.sh
```

Conferência manual, que é a que importa:

```bash
# 1) Python do venv enxerga tudo?
./.venv/bin/python3 -c "import elasticsearch, yaml, dns.resolver, whois, feedparser, shodan, dotenv; print('Python OK')"

# 2) As ferramentas de rede estão visíveis PARA O SEU USUÁRIO?
pdtm -sp -silent
subfinder -version && httpx -version && naabu -version && tlsx -version && nuclei -version

# 3) É o httpx certo? (tem que dizer projectdiscovery.io)
command -v httpx && httpx -version

# 4) Utilitários do coletor
dig -v; jq --version; column -V; echo "1+1" | bc

# 5) Elasticsearch no ar e na versão certa
curl -s http://localhost:9200 | jq -r .version.number
```

## 10. Configuração

### `pipeline_config.yaml`

O pipeline lê desse arquivo **apenas**:

- `tools.<nome>.enabled`, `tools.<nome>.script`, `tools.<nome>.index`
- `elasticsearch.index_settings`

```yaml
tools:
  whois:
    enabled: true
    script: WHOIS/whois_universal.py
    index: whois
  # ... demais ferramentas ...

elasticsearch:
  index_settings:
    number_of_shards: 1
    number_of_replicas: 0
    refresh_interval: "5s"
```

> As outras seções que existem no arquivo (`template`, `tool_settings`, `sub_indices`,
> `description`) **não são lidas** pelo código — alterá-las não muda nada. Elas estão ali
> como documentação.
>
> `run_pipeline()` executa apenas `whois`, `dns`, `coletor` e `shodan`, nessa ordem.
> `feed` e `telegram`, mesmo presentes no YAML, **não** são executados pelo pipeline.

**É aqui que se personaliza o pipeline.** O que dá para mudar sem tocar no código:

- **Desligar uma etapa**: `tools.<nome>.enabled: false`.
- **Trocar o script de uma etapa**: `tools.<nome>.script`, sempre com caminho **relativo à
  raiz do projeto** (ex.: `WHOIS/whois_universal.py`).
- **Trocar o índice de destino**: `tools.<nome>.index`. O nome final recebe o prefixo
  `analise_superficie_` (ex.: `index: whois` → `analise_superficie_whois`).
- **Shards/replicas/refresh** dos índices novos: `elasticsearch.index_settings`.

Para mudar threads, rate-limit ou timeouts **de verdade**, edite as flags das ferramentas
dentro do `COLETOR/coletor.sh` — não existe essa configuração no YAML. Há também um
`pipeline_config.shodan.yaml` na raiz, que você pode passar com `--config` para rodar só a
etapa do Shodan.

### Feeds RSS (`FEED/feeds.yaml`)

O formato é **`Categoria: { Nome: URL }`** — um mapa de categorias, cada uma com um mapa de
`Nome: URL`:

```yaml
Cybersecurity (News/Análises):
  The Hacker News: https://feeds.feedburner.com/TheHackersNews
  Krebs on Security: https://krebsonsecurity.com/feed/

Threat Intel / CVEs / IOCs:
  CISA Cybersecurity Advisories (All): https://www.cisa.gov/cybersecurity-advisories/all.xml
```

O coletor de feeds é o `FEED/rss_feed.py`, com os subcomandos `collect`, `send`,
`collect-send` e `setup`. O `--feeds-file` é **obrigatório**; o índice/alias padrão de escrita
é `rss-feeds`. A coleta de feeds não faz parte do pipeline automático.

## 11. Executando o pipeline

Prepare a lista de domínios:

#### Linux/WSL (bash)

```bash
cp dominios.txt.example dominios.txt
# edite: um domínio por linha, só o que você pode escanear
```

### Jeito recomendado — o Python do venv, de dentro da pasta do projeto

```bash
cd <pasta-do-projeto>
./.venv/bin/python3 adint_pipeline.py \
  --company "Minha Empresa" \
  --company-slug minhaempresa \
  --domains dominios.txt \
  --es-host localhost --es-port 9200 \
  --output-dir pipeline_results \
  --config pipeline_config.yaml
```

> [!IMPORTANT]
> ### Armadilha nº 3 — o interpretador se propaga
>
> O orquestrador dispara cada etapa com `sys.executable`, ou seja, **o mesmo interpretador
> que o chamou**. Se você invocar com o Python do sistema, todas as etapas herdam um ambiente
> sem `elasticsearch`, `whois` e `shodan`, e você vê:
>
> ```
> ModuleNotFoundError: No module named 'whois'
> ```
>
> ...em etapas que você nem sabia que importavam isso. Chame com `./.venv/bin/python3` (ou
> ative o venv antes). Não é preferência de estilo: é o que faz as etapas funcionarem.

> [!IMPORTANT]
> ### Armadilha nº 4 — rode de dentro da pasta do projeto
>
> Duas coisas dependem do diretório atual:
>
> 1. o `load_dotenv()` lê o `.env` **do diretório atual** — fora da pasta, suas chaves
>    simplesmente não existem;
> 2. o `pipeline_config.yaml` referencia os scripts por **caminho relativo**
>    (`WHOIS/whois_universal.py`) — fora da pasta, o pipeline não acha nenhum script.
>
> O `cd <pasta-do-projeto>` é obrigatório, não decorativo.

### Jeito alternativo — `run_pipeline.sh`

O wrapper existe e é mais curto de digitar. Opções, conforme `./run_pipeline.sh --help`:

| Opção | Descrição | Padrão |
| --- | --- | --- |
| `-c, --company` | nome da empresa alvo (**obrigatório**) | — |
| `-s, --company-slug` | slug/apelido da empresa | gerado do nome |
| `-d, --domains` | arquivo com a lista de domínios (**obrigatório**) | — |
| `-n, --notes` | observações sobre a análise | vazio |
| `-h, --host` | host do Elasticsearch | `localhost` |
| `-p, --port` | porta do Elasticsearch | `9200` |
| `-o, --output` | diretório de resultados | `pipeline_results` |
| `--help` | mostra a ajuda | — |

#### Linux/WSL (bash)

```bash
source .venv/bin/activate        # OBRIGATÓRIO: o wrapper chama "python3", não o do venv
./run_pipeline.sh -c "Minha Empresa" -s minhaempresa -d dominios.txt

# apontando para um Elasticsearch em outro host:
./run_pipeline.sh -c "Minha Empresa" -d dominios.txt -h 192.168.0.10 -p 9200
```

> O `run_pipeline.sh` invoca `python3 adint_pipeline.py`. Sem o venv ativo, esse `python3` é
> o do sistema e você cai direto na armadilha nº 3. O wrapper também **não** tem a opção
> `--config`: ele sempre usa o `pipeline_config.yaml` padrão.
>
> Não existe a opção `--verbose`/`-v` em nenhum script deste projeto.

Conferir o que entrou:

```bash
curl -s "http://localhost:9200/_cat/indices/analise_superficie_*?v"
```

### Rodando uma etapa por vez

Cada script roda sozinho, sem o orquestrador — é assim que se aprende o que cada um faz.
Repare que as interfaces **não são iguais**:

#### Linux/WSL (bash)

```bash
# WHOIS: -d/--dominio, -l/--lista, -o/--output, --list-tlds
./.venv/bin/python3 WHOIS/whois_universal.py -d exemplo.com.br

# DNS: domínio posicional ou -f/--file; -d/--dir é um DIRETÓRIO, não um domínio
./.venv/bin/python3 DNS/dns-security-analyzer.py -f dominios.txt -d saida_dns/

# COLETOR: diretório de saída pela variável de ambiente OUT_DIR
OUT_DIR=saida_coletor bash COLETOR/coletor.sh dominios.txt

# SHODAN: argumentos posicionais, sem flags
./.venv/bin/python3 SHODAN/unified_shodan_scanner.py dominios.txt saida_shodan/
```

### Índices e campos

Os índices são **gerais, por tipo de dado**, todos com o prefixo `analise_superficie_`:

- `analise_superficie_metadata`, `_whois`, `_dns`, `_shodan`, `_feed`
- `analise_superficie_coletor_httpx`, `_coletor_naabu`, `_coletor_certs`, `_coletor_san`,
  `_coletor_nuclei`
- `vazamentos_dados` (Telegram) e `rss-feeds` (feeds RSS)

**Não existe um índice por empresa** (nada de `analise_superficie_<empresa>_*`). Os dados de
todas as empresas convivem nos mesmos índices; o que separa é o **campo `company_slug`**.

Campos que o pipeline acrescenta a **todo** documento que indexa:

| Campo | Tipo | Conteúdo |
| --- | --- | --- |
| `company` | `text` + `.keyword` | o nome passado em `--company` |
| `company_slug` | `text` + `.keyword` | o `--company-slug`, ou um slug gerado do nome |
| `timestamp` | `date` (formato `yyyyMMdd_HHmmss`) | momento da execução |
| `pipeline_run` | `keyword` | identificador da execução (mesmo valor do `timestamp`) |

Detalhes que mordem na hora de consultar:

- Para filtrar por empresa em agregações e termos exatos, use **`company_slug.keyword`**
  (o campo base é `text`, analisado).
- **Não existe `@timestamp`** nos índices do pipeline. Só o índice `rss-feeds` usa
  `@timestamp`.
- Nos índices que o pipeline cria explicitamente, strings caem num *dynamic template* que as
  mapeia como `text` com subcampo `.keyword` (`ignore_above: 256`).
- `_id`: quando o documento tem um campo `id`, o `_id` gerado é `"<company_slug>_<id>"` —
  reexecutar sobrescreve o mesmo registro em vez de duplicar. Documentos **sem** `id` recebem
  `_id` automático, e aí cada execução cria documentos novos.

## 12. Quando algo quebra

A tabela de sintomas mais comuns está no [README](../README.md), e os casos detalhados em
[`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md). Os quatro primeiros lugares para olhar:

| Sintoma | Causa provável | Onde |
| --- | --- | --- |
| `✗ binário não encontrado: subfinder` (instalado) | pdtm instalado com `sudo` → foi para `/root` | armadilha nº 1, passo 6 |
| `httpx` imprime ajuda de biblioteca Python | PATH entregando o `httpx` do PyPI | armadilha nº 2, passo 6 |
| `ModuleNotFoundError` em várias etapas | rodou com o Python do sistema | armadilha nº 3, passo 11 |
| `.env` ignorado / "script não encontrado" | rodou de fora da pasta do projeto | armadilha nº 4, passo 11 |
| subíndices do coletor não aparecem | `action.auto_create_index` restritivo | passo 5 |
| `nuclei` devolve 0 achados | pode ser WAF **ou o alvo ter caído** | ver abaixo |

> [!TIP]
> **"Zero achados" e "zero verificado" são a mesma saída e coisas opostas.** Um scanner que
> não alcançou o alvo encerra com sucesso e relatório vazio. Antes de concluir que algo está
> limpo, confirme que o alvo responde e que a ferramenta de fato chegou lá.

## 13. Próximos passos

1. Rode o pipeline completo seguindo o passo 11 (a seção "Primeira execução" do
   [README](../README.md) tem a versão curta).
2. Cadastre o Data View no Kibana (passo 5) e explore os índices `analise_superficie_*`
   filtrando por `company_slug.keyword`.
3. Personalize as etapas no `pipeline_config.yaml` e os feeds no `FEED/feeds.yaml`
   (passo 10).
4. Suba o servidor MCP (`mcp_exposure_poc.py`) para consultar os índices a partir de uma LLM.
