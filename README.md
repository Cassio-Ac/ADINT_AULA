# Pipeline de Análise de Superfície de Ataque

Ferramentas do curso **ADINT**. O pipeline coleta informações públicas sobre os domínios de uma
organização, normaliza tudo em JSON, guarda no Elasticsearch e expõe esses dados a uma LLM
através de um servidor MCP.

O fluxo é sempre o mesmo, e é ele que organiza o repositório:

```
COLETAR          →    TRATAR      →    ARMAZENAR     →    UTILIZAR
WHOIS, DNS,           tudo vira        Elasticsearch      servidor MCP
Project Discovery,    JSON                                (a IA consulta
Shodan, RSS,                                               os índices)
Telegram
```

> [!IMPORTANT]
> **Só escaneie o que é seu ou o que você tem autorização escrita para testar.**
> As etapas de WHOIS, DNS e Shodan são passivas (consultam terceiros que já coletaram).
> As etapas de `httpx`, `naabu` e `nuclei` **mandam pacote para o alvo** — isso é atividade
> ativa e tem consequência legal. Para treinar sem risco, use `vulnweb.com`, mantido pela
> Acunetix exatamente para isso, ou suba um alvo seu (há um OWASP Juice Shop no
> `docker-compose.yml`, perfil `targets`).

---

## 1. Pré-requisitos

| O quê | Versão | Para quê |
|---|---|---|
| Linux ou **WSL2** (Ubuntu 22.04/24.04) | — | as ferramentas de coleta são Linux |
| **Python 3.10+** (testado no 3.12) | — | scripts do pipeline |
| **Docker** | — | sobe o Elasticsearch e o Kibana |
| **Elasticsearch 8.x** | testado no 8.15.3 | armazenamento (o cliente está fixado em `>=8,<9`) |

Pacotes de sistema:

```bash
sudo apt update
sudo apt install -y git curl jq dnsutils whois libpcap-dev bc
# dnsutils = dig/nslookup/delv · libpcap-dev = requisito do naabu
# bc = o coletor usa para calcular o percentual de progresso do tlsx
# dnsmap e dnsrecon são opcionais, usados nas aulas de DNS:
sudo apt install -y dnsmap dnsrecon
```

Contas gratuitas (opcionais, mas melhoram muito a coleta): **Shodan**, **VirusTotal**,
**SecurityTrails** e um **token do GitHub**.

---

## 2. Instalação

### 2.1 Clonar e criar o ambiente Python

```bash
git clone https://github.com/Cassio-Ac/ADINT_AULA.git
cd ADINT_AULA

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> [!NOTE]
> Três dependências estão **fixadas de propósito** e o motivo está no `requirements.txt`:
> `elasticsearch>=8,<9` (a 9.x removeu `timeout=` do construtor), `mcp<2` (a 2.x renomeou
> `FastMCP` → `MCPServer`) e `setuptools<80` (a CLI do Shodan importa `pkg_resources`, que o
> setuptools ≥81 removeu e o venv do Python 3.12 não traz). Não "atualize" esses três sem ler
> o comentário.

### 2.2 Instalar as ferramentas de rede (pdtm)

As cinco ferramentas do Project Discovery — `subfinder`, `httpx`, `naabu`, `tlsx`, `nuclei` —
são instaladas pelo **pdtm**, o gerenciador oficial deles:

```bash
# instale o pdtm (binário pré-compilado; veja github.com/projectdiscovery/pdtm/releases)
# e depois, com o SEU usuário:
pdtm -i subfinder,httpx,naabu,nuclei,tlsx -ip
source ~/.bashrc
```

`-i` instala · `-ip` faz o próprio pdtm acrescentar o caminho ao seu `~/.bashrc`.

> [!WARNING]
> **Nunca instale com `sudo`.** O pdtm instala em `~/.pdtm/go/bin` **do usuário que rodou o
> comando**. Se você usar `sudo`, as ferramentas vão para `/root/.pdtm/go/bin` — e `/root` é
> `drwx------`, então o seu usuário comum **não consegue nem entrar lá**.
>
> O sintoma é cruel: o coletor aborta com `✗ binário não encontrado: subfinder` **com o
> subfinder instalado e funcionando**. A mensagem diz *"não encontrado"* quando o problema é
> *"não visível"*. É permissão, não ausência.
>
> Confira sempre onde eles foram parar:
> ```bash
> pdtm -sp -silent     # deve imprimir /home/<você>/.pdtm/go/bin
> ```

> [!CAUTION]
> **Existem dois programas chamados `httpx`.** O do Project Discovery é um *scanner* escrito
> em Go; `httpx` do PyPI é uma *biblioteca HTTP* do Python. Se você instalar a biblioteca no
> mesmo ambiente, o PATH pode entregar a errada e a saída não vai fazer sentido nenhum.
> ```bash
> command -v httpx     # deve apontar para ~/.pdtm/go/bin/httpx
> httpx -version       # o scanner se identifica: v1.x.x, projectdiscovery.io
> ```

### 2.3 Subir o Elasticsearch e o Kibana

```bash
docker compose up -d
curl -s http://localhost:9200 | jq -r .version.number     # deve responder 8.x
```

Kibana em <http://localhost:5601>.

### 2.4 Configurar as chaves

```bash
cp .env.example .env
# edite o .env e preencha o que você tiver
```

> [!IMPORTANT]
> **As chaves do subfinder NÃO vão no `.env`.** Ele é escrito em Go e lê um arquivo próprio:
> ```bash
> mkdir -p ~/.config/subfinder
> nano ~/.config/subfinder/provider-config.yaml
> chmod 600 ~/.config/subfinder/provider-config.yaml
> ```
> ```yaml
> virustotal:
>   - SUA_CHAVE
> securitytrails:
>   - SUA_CHAVE
> shodan:
>   - SUA_CHAVE
> github:
>   - ghp_SEU_TOKEN
> ```
> Uma fonte aceita **várias** chaves (o subfinder faz rodízio quando estoura o limite). Nunca
> projete esse arquivo preenchido numa tela compartilhada.

---

## 3. Primeira execução

```bash
cp dominios.txt.example dominios.txt
# edite: um domínio por linha, só o que você pode escanear

cd /caminho/para/ADINT_AULA        # o cd é obrigatório — veja a nota abaixo
./.venv/bin/python3 adint_pipeline.py \
  --company "Minha Empresa" \
  --company-slug minhaempresa \
  --domains dominios.txt \
  --es-host localhost --es-port 9200 \
  --output-dir pipeline_results \
  --config pipeline_config.yaml
```

> [!NOTE]
> **Rode de dentro da pasta do projeto.** Não é superstição — são dois motivos concretos:
> 1. **O `.env`.** O orquestrador não lê o `.env`; quem lê são os scripts filhos (Shodan,
>    Telegram), e cada um chama `load_dotenv()`, que procura o arquivo **a partir do diretório
>    de trabalho herdado**. Lançando de outro lugar, eles não acham as chaves.
> 2. **Os caminhos que você passa.** `--domains`, `--output-dir` e o arquivo de log são
>    relativos ao diretório atual.
>
> (Os scripts das etapas, esses sim, são resolvidos contra a pasta do projeto — então
> `WHOIS/whois_universal.py` no `pipeline_config.yaml` funciona de qualquer lugar.)
>
> **Use o Python do venv** (`./.venv/bin/python3`, ou ative o venv antes). O pipeline repassa
> o *mesmo* interpretador para cada etapa, então se você chamar com o Python do sistema todas
> as etapas herdam um ambiente sem `elasticsearch`, `whois` e `shodan`.

Conferir o que entrou:

```bash
curl -s "http://localhost:9200/_cat/indices/analise_superficie_*?v"
```

Os dados de todas as empresas convivem nos mesmos índices; o que separa é o campo
**`company_slug`**. Para filtrar uma empresa, use `company_slug.keyword`.

---

## 4. O que tem aqui

| Pasta / arquivo | O que faz |
|---|---|
| `adint_pipeline.py` | orquestrador: roda cada etapa na ordem e indexa no Elasticsearch |
| `pipeline_config.yaml` | liga/desliga etapas e diz qual script e qual índice cada uma usa |
| `WHOIS/` | consulta WHOIS por TLD (socket na porta 43) e normaliza em JSON |
| `DNS/` | registros DNS + nota de segurança (SPF, DMARC, DNSSEC, CAA...) |
| `COLETOR/` | `coletor.sh`: subfinder → httpx → naabu → tlsx → nuclei |
| `SHODAN/` | consulta a API do Shodan por domínio e por IP |
| `FEED/` | coleta feeds RSS de segurança (`feeds.yaml`) |
| `TELEGRAM/` | criação de sessão e coleta de canais de CVE/vazamento |
| `ELK/` | configuração do Elasticsearch para o laboratório |
| `mcp_exposure_poc.py` | servidor MCP que expõe os índices a uma LLM |
| `docs/INSTALLATION.md` | instalação detalhada |
| `docs/TROUBLESHOOTING.md` | o que fazer quando quebra |

### Uma etapa por vez

Cada script roda sozinho, sem o orquestrador — é assim que se aprende o que cada um faz.
Todos têm um cabeçalho explicando uso e saída:

```bash
./.venv/bin/python3 WHOIS/whois_universal.py -d exemplo.com.br
./.venv/bin/python3 DNS/dns-security-analyzer.py -f dominios.txt -d saida/
bash COLETOR/coletor.sh dominios.txt
./.venv/bin/python3 SHODAN/unified_shodan_scanner.py dominios.txt saida/
```

---

## 5. Quando der errado

| Sintoma | Causa | Solução |
|---|---|---|
| `✗ binário não encontrado: subfinder` (instalado) | instalou o pdtm com `sudo` → foi para `/root` | reinstale com o seu usuário e confira com `pdtm -sp -silent` |
| `httpx` imprime ajuda de biblioteca Python | PATH entregando o `httpx` do PyPI | `command -v httpx` deve apontar para `~/.pdtm/go/bin/httpx` |
| `ModuleNotFoundError: No module named 'whois'` | rodou com o Python do sistema | use o Python do venv |
| `ModuleNotFoundError: pkg_resources` no Shodan | `setuptools` ≥81 | `pip install 'setuptools<80'` |
| `No module named 'mcp.server.fastmcp'` | instalou `mcp` 2.x | `pip install 'mcp<2'` |
| índices do coletor não aparecem | `action.auto_create_index` restritivo | veja `docker-compose.yml` / `ELK/` |
| `nuclei` devolve 0 achados | pode ser WAF **ou o alvo ter caído** | confirme que o alvo responde antes de concluir "limpo" |
| etapa `feed` está `enabled: true` mas não roda | a ordem das etapas é uma lista fixa em `run_pipeline()` | rode `FEED/rss_feed.py` direto, ou inclua o nome na lista `tools_order` |

Mais casos em [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

> [!TIP]
> **"Zero achados" e "zero verificado" são a mesma saída e coisas opostas.** Um scanner que
> não alcançou o alvo encerra com sucesso e relatório vazio. Antes de dizer que algo está
> limpo, confirme que a ferramenta de fato chegou lá.
