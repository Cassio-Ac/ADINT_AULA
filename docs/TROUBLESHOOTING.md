# Guia de Troubleshooting do Pipeline de Análise de Superfície

Este guia reúne soluções para os problemas que de fato acontecem ao rodar o pipeline ADINT de
análise de superfície de ataque. A instalação está em [`INSTALLATION.md`](./INSTALLATION.md);
a visão geral do projeto, no [README](../README.md).

> **Convenção deste guia.** Todo bloco de comando está marcado com onde ele roda:
> **Linux/WSL (bash)** ou **Windows (PowerShell)**. `~/` é o seu HOME e
> `<pasta-do-projeto>` é a pasta onde você clonou o repositório. Os comandos assumem que você
> está **na raiz do projeto**.

> **Importante — como o projeto realmente funciona**
>
> - O Elasticsearch é **8.x** (testado no 8.15.3) e o cliente Python está fixado em
>   `elasticsearch>=8,<9`.
> - Os índices são **gerais por tipo de dado**, com o prefixo `analise_superficie_`. **Não
>   existe índice por empresa** (nada de `analise_superficie_<empresa>_*`). Para analisar uma
>   empresa específica, **filtre pelo campo `company_slug`** (em termos exatos e agregações,
>   `company_slug.keyword`).
> - O pipeline (`adint_pipeline.py`) adiciona a cada documento os campos `company`,
>   `company_slug`, `timestamp` (formato `yyyyMMdd_HHmmss`) e `pipeline_run`. **Não existe**
>   `@timestamp` nos índices do pipeline (apenas o índice de feeds `rss-feeds` usa
>   `@timestamp`).
> - `run_pipeline()` executa, nesta ordem, apenas: **whois, dns, coletor, shodan**. As
>   ferramentas **feed** e **telegram** estão no `pipeline_config.yaml`, mas **não** são
>   executadas automaticamente — são rodadas à parte, pelos seus próprios scripts.
> - Do `pipeline_config.yaml` o código lê **somente** `tools.<nome>.{enabled,script,index}` e
>   `elasticsearch.index_settings`. As seções `template`, `tool_settings` e `sub_indices`
>   **não são lidas pelo código** (servem como documentação no YAML).

## Índice

1. [Os quatro erros que mais acontecem](#os-quatro-erros-que-mais-acontecem)
2. [Problemas de Conexão](#problemas-de-conexão)
3. [Problemas com Ferramentas](#problemas-com-ferramentas)
4. [Problemas com Elasticsearch](#problemas-com-elasticsearch)
5. [Problemas com Dados](#problemas-com-dados)
6. [Problemas com o Telegram](#problemas-com-o-telegram)
7. [Bugs Conhecidos Já Corrigidos](#bugs-conhecidos-já-corrigidos)
8. [Logs e Diagnóstico](#logs-e-diagnóstico)

## Os quatro erros que mais acontecem

Antes de investigar qualquer coisa, descarte estes quatro. Juntos, eles respondem pela maior
parte dos problemas de laboratório.

### 1. `✗ binário não encontrado: subfinder` — com o subfinder instalado

**Causa**: o `pdtm` foi instalado com `sudo`. Ele instala no HOME de **quem rodou o
comando**: com `sudo`, as ferramentas foram para `/root/.pdtm/go/bin`. E `/root` é
`drwx------` — o seu usuário comum **não consegue nem entrar lá**.

A mensagem diz *"não encontrado"* quando o problema é *"não visível"*. É **permissão, não
ausência**. O binário existe, funciona, e está num diretório que você não pode ler.

**Solução** — reinstalar com o seu próprio usuário, sem `sudo`:

#### Linux/WSL (bash)

```bash
pdtm -i subfinder,httpx,naabu,nuclei,tlsx -ip
source ~/.bashrc

# A fonte de verdade: o caminho impresso tem que estar DENTRO do seu HOME.
pdtm -sp -silent          # se imprimir algo em /root, foi o sudo
```

`-i` instala as ferramentas; `-ip` faz o próprio pdtm acrescentar o caminho ao seu
`~/.bashrc`. Se precisar apontar na mão para o coletor:

```bash
export PD_BIN_DIR="$(pdtm -sp -silent)"
```

### 2. O `httpx` errado

Existem **dois programas chamados `httpx`**: o *scanner* do Project Discovery (Go) e a
*biblioteca HTTP* do Python (PyPI), que também instala um binário com esse nome. Se a
biblioteca estiver no PATH antes do scanner, o coletor chama a errada e **a saída não faz
sentido nenhum** — sem erro claro, só resultado estranho.

#### Linux/WSL (bash)

```bash
command -v httpx     # deve apontar para o httpx do pdtm (~/.pdtm/go/bin/httpx)
httpx -version       # o scanner se identifica: v1.x.x, projectdiscovery.io
```

Se `httpx -version` não mencionar `projectdiscovery.io`, é a biblioteca do Python. Corrija o
PATH (ou exporte `PD_BIN_DIR`) antes de rodar o coletor.

### 3. `ModuleNotFoundError` em etapas aleatórias

**Causa**: o orquestrador dispara cada etapa com `sys.executable` — **o mesmo interpretador
que o chamou**. Rodar com o Python do sistema faz todas as etapas herdarem um ambiente sem
`elasticsearch`, `whois` e `shodan`:

```
ModuleNotFoundError: No module named 'whois'
```

**Solução** — use o Python do venv:

#### Linux/WSL (bash)

```bash
# Em qual Python você está?
python3 -c "import sys; print(sys.executable)"

# Chame explicitamente o do venv...
./.venv/bin/python3 adint_pipeline.py --company "Minha Empresa" --domains dominios.txt

# ...ou ative o venv antes (obrigatório se for usar o run_pipeline.sh,
# que chama "python3" e cai no PATH).
source .venv/bin/activate
```

### 4. O `.env` ignorado / "script não encontrado"

**Causa**: o pipeline foi iniciado **de fora da pasta do projeto**. Duas coisas dependem do
diretório atual:

1. o `load_dotenv()` lê o `.env` **do diretório atual** — fora da pasta, suas chaves
   simplesmente não existem (a etapa do Shodan reclama de chave, a do Telegram de
   credencial);
2. o `pipeline_config.yaml` referencia os scripts por **caminho relativo**
   (`WHOIS/whois_universal.py`) — fora da pasta, nenhum script é encontrado.

**Solução**:

#### Linux/WSL (bash)

```bash
cd <pasta-do-projeto>
./.venv/bin/python3 adint_pipeline.py --company "Minha Empresa" --domains dominios.txt
```

O `adint_pipeline.log` e o diretório de resultados também são criados no diretório atual.

## Problemas de Conexão

### Erro de Conexão com Elasticsearch

**Sintoma**: Mensagem de erro indicando falha na conexão com o Elasticsearch.

```
ConnectionError: Cannot connect to host localhost:9200
```

O `run_pipeline.sh` também avisa antes de iniciar:

```
Aviso: Não foi possível conectar ao Elasticsearch em localhost:9200
Deseja continuar mesmo assim? (s/n)
```

**Possíveis Causas**:
1. Elasticsearch não está em execução
2. Host ou porta incorretos
3. Firewall bloqueando a conexão

**Soluções**:

1. **Verificar se o Elasticsearch está em execução e na versão certa**:

   #### Linux/WSL (bash)

   ```bash
   curl -s http://localhost:9200 | jq -r .version.number     # deve responder 8.x
   ```

   Com **Docker** (caminho recomendado), na raiz do projeto:

   ```bash
   docker compose ps
   docker compose logs -f es
   docker compose up -d                                  # sobe es + kibana
   sudo sysctl -w vm.max_map_count=262144                # se o es morrer no boot
   ```

   Na **instalação nativa no Windows**, use o script do repositório. Ele traz um `ES_HOME`
   fixo no topo (`set ES_HOME=...`) — edite essa linha para o caminho da sua instalação:

   #### Windows (PowerShell)

   ```powershell
   .\ELK\start-elasticsearch-aula.bat
   ```

   Antes do primeiro uso, copie a config da aula (`<ES_HOME>` = onde você instalou o
   Elasticsearch):

   ```powershell
   Copy-Item ".\ELK\elastisearch.yml" "<ES_HOME>\config\elasticsearch.yml" -Force
   ```

   Detalhes em [`INSTALLATION.md`](./INSTALLATION.md).

2. **Verificar host e porta**: passe os valores corretos ao pipeline.

   #### Linux/WSL (bash)

   ```bash
   ./.venv/bin/python3 adint_pipeline.py \
     --company "Minha Empresa" --domains dominios.txt \
     --es-host 192.168.0.10 --es-port 9200

   # ou, pelo wrapper (com o venv ativo):
   ./run_pipeline.sh -c "Minha Empresa" -d dominios.txt -h 192.168.0.10 -p 9200
   ```

3. **Verificar firewall** (caso o Elasticsearch esteja em outra máquina):

   #### Linux/WSL (bash)

   ```bash
   sudo ufw status
   sudo ufw allow 9200/tcp
   ```

   Com WSL para a coleta e Elasticsearch no Windows, teste pelo IP do host Windows e
   verifique o firewall do Windows.

> **Autenticação**: tanto o `docker-compose.yml` quanto o `ELK/elastisearch.yml` usam
> `xpack.security.enabled: false`, ou seja, **sem usuário/senha** (é modo laboratório —
> jamais exponha isso na rede). O `adint_pipeline.py` **não lê nenhuma chave de autenticação**
> do `pipeline_config.yaml` (ele só lê `elasticsearch.index_settings`), portanto não adianta
> criar seções como `elasticsearch.auth` no YAML — elas são ignoradas. Se você habilitar
> segurança no Elasticsearch, será necessário ajustar o próprio código do pipeline.

### Erro de Conexão com API Externa (Shodan)

**Sintoma**: Mensagem de erro indicando falha na conexão com a API do Shodan.

**Possíveis Causas**:
1. Problemas de rede
2. API key inválida, ausente ou expirada
3. Limite de requisições (créditos) excedido

**Soluções**:

1. **Verificar conectividade**:

   #### Linux/WSL (bash)

   ```bash
   ping api.shodan.io
   ```

2. **Verificar / configurar a API key**. O scanner
   (`SHODAN/unified_shodan_scanner.py`) aceita dois caminhos:

   - **`SHODAN_API_KEY` no `.env`** (preferido): se a CLI não estiver inicializada, o próprio
     scanner roda o `shodan init` com essa chave.
   - **CLI inicializada na mão**, uma vez.

   #### Linux/WSL (bash)

   ```bash
   shodan info                 # confirma a chave e mostra seus créditos
   shodan init SUA_API_KEY     # se precisar configurar
   ```

   Dois detalhes que mordem:
   - o scanner chama o **executável** `shodan`, então ele precisa estar no PATH — o que
     acontece com o venv ativo;
   - a CLI do Shodan importa `pkg_resources`. Por isso o `requirements.txt` fixa
     `setuptools<80`: no setuptools ≥81 esse módulo não existe mais e a CLI quebra com
     `ModuleNotFoundError: No module named 'pkg_resources'`.

3. **Verificar limites de requisições**: confira os créditos da sua conta Shodan. Se
   necessário, reduza a quantidade de domínios.

> As chaves do **subfinder** não ficam no `.env` nem na CLI do Shodan: elas vão em
> `~/.config/subfinder/provider-config.yaml` (`chmod 600`), no formato de **listas** — cada
> fonte aceita várias chaves e o subfinder faz rodízio quando uma estoura o limite. Se o
> subfinder devolve pouquíssimos subdomínios, é quase sempre esse arquivo que está vazio.

## Problemas com Ferramentas

### Ferramenta não Encontrada

**Sintoma**: Mensagem de erro indicando que o script ou o binário da ferramenta não foi
encontrado.

```
Script não encontrado: WHOIS/whois_universal.py
✗ binário não encontrado: subfinder
```

**Possíveis Causas**:
1. Pipeline iniciado de fora da pasta do projeto (caminhos relativos) — veja
   [Os quatro erros que mais acontecem](#os-quatro-erros-que-mais-acontecem)
2. `pdtm` instalado com `sudo` (binário invisível, não ausente) — idem
3. Caminho incorreto no arquivo de configuração
4. Dependência Python ou binário realmente não instalado

**Soluções**:

1. **Verificar o caminho no arquivo de configuração**. O caminho é relativo à raiz do
   repositório. Edite `pipeline_config.yaml` e confira `tools.<ferramenta>.script`:

   ```yaml
   tools:
     whois:
       enabled: true
       script: WHOIS/whois_universal.py
       index: whois
   ```

   O `index` recebe o prefixo `analise_superficie_` na hora de indexar (`whois` →
   `analise_superficie_whois`).

2. **Instalar as dependências**:

   #### Linux/WSL (bash)

   ```bash
   # Dependências Python (na raiz do repositório, com o venv ativo)
   pip install -r requirements.txt
   ```

   O `requirements.txt` inclui: `elasticsearch>=8,<9`, `dnspython`, `python-whois`, `pyyaml`,
   `requests`, `feedparser`, `shodan`, `tqdm`, `python-dateutil`, `mcp<2`, `python-dotenv` e
   `setuptools<80`. **Três pins são de propósito** e o motivo está escrito no arquivo:

   | Pin | Por quê |
   | --- | --- |
   | `elasticsearch>=8,<9` | a 9.x removeu `timeout=` do construtor; o pipeline usa `request_timeout=` |
   | `mcp<2` | a 2.x renomeou `FastMCP` → `MCPServer`, e o código usa a API v1 |
   | `setuptools<80` | a CLI do Shodan importa `pkg_resources`, removido no ≥81 |

   Binários externos do COLETOR (ProjectDiscovery e utilitários): `subfinder`, `httpx`,
   `naabu`, `tlsx`, `nuclei`, além de `dig`, `jq`, `awk`, `column`, `tee`, `bc` e o `pdtm`.
   Veja o [Guia de Instalação](./INSTALLATION.md).

3. **Conferir onde o coletor procura os binários.** A ordem é: `$PD_BIN_DIR` →
   `pdtm -sp -silent` → `~/.pdtm/go/bin` → `PATH`.

   ```bash
   pdtm -sp -silent
   export PD_BIN_DIR="$(pdtm -sp -silent)"
   ```

### Erro na Execução de uma Ferramenta

**Sintoma**: Uma ferramenta é executada, mas falha com um erro. Observe que `run_pipeline()`
**continua** executando as demais ferramentas e retorna sucesso mesmo que uma etapa falhe no
meio — por isso é importante ler os logs.

**Possíveis Causas**:
1. Dependências ausentes (quase sempre: Python do sistema em vez do venv)
2. Entrada (arquivo de domínios) vazia ou inválida
3. Erro interno do script ou da ferramenta externa

**Soluções**:

1. **Verificar dependências**:

   #### Linux/WSL (bash)

   ```bash
   # Módulos Python, pelo interpretador que o pipeline vai usar
   ./.venv/bin/python3 -c "import elasticsearch, yaml, dns.resolver, whois, feedparser, shodan, dotenv; print('OK')"

   # Binários externos
   command -v subfinder httpx naabu tlsx nuclei dig jq bc column
   ```

2. **Executar a ferramenta manualmente** para reproduzir o erro.

   As ferramentas têm interfaces de linha de comando **diferentes** — use exatamente os
   parâmetros de cada uma:

   #### Linux/WSL (bash)

   - **WHOIS** (`WHOIS/whois_universal.py`): `-d/--dominio`, `-l/--lista`, `-o/--output`,
     `--list-tlds`.
     ```bash
     ./.venv/bin/python3 WHOIS/whois_universal.py -d exemplo.com.br
     ./.venv/bin/python3 WHOIS/whois_universal.py -l dominios.txt -o whois_results.json
     ```
   - **DNS** (`DNS/dns-security-analyzer.py`): domínio **posicional** ou `-f/--file` (lista),
     `-o/--output`, `-d/--dir` (um **diretório**, não um domínio).
     ```bash
     ./.venv/bin/python3 DNS/dns-security-analyzer.py -f dominios.txt -d saida_dns/
     ```
   - **COLETOR** (`COLETOR/coletor.sh`): o diretório de saída vem pela **variável de
     ambiente** `OUT_DIR`, e o arquivo de domínios como argumento posicional.
     ```bash
     OUT_DIR=saida_coletor bash COLETOR/coletor.sh dominios.txt
     ```
     > Passar `OUT_DIR` como argumento (`coletor.sh dominios.txt OUT_DIR=x`) **não funciona**
     > — nesse caso os resultados caem em `./out`.
   - **SHODAN** (`SHODAN/unified_shodan_scanner.py`): argumentos **posicionais** (sem flags).
     ```bash
     ./.venv/bin/python3 SHODAN/unified_shodan_scanner.py dominios.txt saida_shodan/
     ```

   > Nenhuma dessas ferramentas (nem o `run_pipeline.sh`/`adint_pipeline.py`) possui opção
   > `--verbose`/`-v`. Veja a seção [Logs e Diagnóstico](#logs-e-diagnóstico).

### `naabu` avisa que está rodando sem privilégio

**Sintoma**: no meio da coleta aparece

```
[INF] Running CONNECT scan with non root privileges
```

**Isso não é erro.** O `coletor.sh` chama o naabu **sem `sudo`**, e sem privilégio ele faz
**CONNECT scan** em vez de SYN scan. A linha é informativa: está dizendo o **modo**, não uma
falha. Não "conserte" com `sudo` — além de desnecessário, o `sudo` é exatamente o que cria o
problema nº 1 desta página quando usado no `pdtm`.

O que o naabu de fato exige é a `libpcap` no sistema (pacote `libpcap-dev`). Sem ela, a
execução falha com erro de biblioteca — aí sim é um erro.

### `nuclei` devolve 0 achados

**Sintoma**: o nuclei termina com sucesso e **nenhum** achado.

**Isso pode ser uma de duas coisas opostas**:

1. o alvo foi verificado e está limpo (ou protegido por um **WAF** que barrou os templates);
2. o alvo **caiu**, mudou de IP, bloqueou você por rate-limit ou nunca respondeu — e o
   scanner não chegou a verificar nada.

> **"Zero achados" e "zero verificado" são a mesma saída e coisas opostas.** Um scanner que
> não alcançou o alvo encerra com sucesso e relatório vazio. Antes de concluir que algo está
> limpo, confirme que o alvo responde.

**Como confirmar** antes de concluir qualquer coisa:

#### Linux/WSL (bash)

```bash
# O alvo está vivo agora?
curl -sS -o /dev/null -w '%{http_code}\n' https://exemplo.com.br

# O httpx viu hosts vivos? O coletor só passa ao nuclei o que o httpx confirmou vivo.
wc -l saida_coletor/httpx/urls_alive.txt

# Se o arquivo estiver vazio, o nuclei foi pulado — e você vê isso no log do coletor:
#   nenhum host vivo (httpx) — nuclei pulado
```

Se o `urls_alive.txt` estiver vazio, o problema está **antes** do nuclei: resolução DNS,
subdomínios, ou o alvo fora do ar. Zero achados ali não diz nada sobre a segurança do alvo.

### Ferramenta Muito Lenta

**Sintoma**: Uma ferramenta demora muito para ser executada.

**Possíveis Causas**:
1. Muitos domínios para processar
2. Limitações de recursos ou de rede

**Soluções**:

1. **Reduzir o número de domínios**: use um `dominios.txt` menor para testes.

2. **Ajustar o comportamento da ferramenta**:
   > A seção `tool_settings` do `pipeline_config.yaml` (ex.: `coletor.threads`,
   > `coletor.rate_limit`) **não é lida pelo código** — ela é apenas informativa. Para mudar
   > threads, rate-limit ou timeouts de fato, execute a ferramenta manualmente com as flags
   > dela ou edite as chamadas dentro do `COLETOR/coletor.sh`.

3. **Aumentar recursos**: se possível, aumente memória/CPU disponíveis.

## Problemas com Elasticsearch

> Nos exemplos abaixo os nomes de índice são os **índices gerais reais** do projeto. Substitua
> pelo índice que você está investigando:
> `analise_superficie_metadata`, `analise_superficie_whois`, `analise_superficie_dns`, `analise_superficie_shodan`,
> `analise_superficie_coletor_httpx`, `analise_superficie_coletor_naabu`, `analise_superficie_coletor_certs`, `analise_superficie_coletor_san`, `analise_superficie_coletor_nuclei`,
> `vazamentos_dados` (Telegram) e `rss-feeds` (feeds RSS).

### Índice não Criado

**Sintoma**: Um índice esperado não aparece no Elasticsearch — tipicamente os **subíndices do
coletor** (`analise_superficie_coletor_httpx`, `_naabu`, `_certs`, `_san`, `_nuclei`).

**Possíveis Causas**:
1. `action.auto_create_index` bloqueando a criação automática (veja [Bugs Conhecidos Já Corrigidos](#bugs-conhecidos-já-corrigidos))
2. A ferramenta falhou e não gerou arquivos de saída
3. Arquivo de saída vazio (o pipeline ignora arquivos de tamanho zero)

**Soluções**:

1. **Conferir a configuração de auto-criação.** No **Docker**, isso já vem pronto no
   `docker-compose.yml` (variável de ambiente `action.auto_create_index`) — basta usar o
   compose do repositório. Na instalação **nativa**, é o `ELK/elastisearch.yml`:

   ```yaml
   action.auto_create_index: analise_superficie_*,vazamentos_dados,rss-feeds*,.monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*
   ```

   Confirme que você copiou esse arquivo para `config\elasticsearch.yml` e reiniciou o
   serviço.

2. **Verificar os índices existentes**:

   #### Linux/WSL (bash)

   ```bash
   curl -s "http://localhost:9200/_cat/indices/analise_superficie_*?v"
   ```

3. **Verificar os logs** do pipeline (`adint_pipeline.log`) para confirmar que a ferramenta
   rodou e gerou arquivos. O `adint_pipeline.py` cria os índices-base (ex.:
   `analise_superficie_coletor`) pelo método `create_index`, mas os **subíndices** do coletor
   dependem da auto-criação do Elasticsearch.

4. **Criar o índice manualmente** (se realmente necessário):

   ```bash
   curl -X PUT "localhost:9200/analise_superficie_coletor_httpx" -H 'Content-Type: application/json' -d'
   {
     "settings": {
       "number_of_shards": 1,
       "number_of_replicas": 0
     }
   }'
   ```

### Erro de Mapeamento

**Sintoma**: Erro ao indexar documentos devido a problemas de mapeamento.

```
mapper_parsing_exception: failed to parse field [campo] of type [tipo]
```

**Possíveis Causas**:
1. Tipo de campo incompatível com o mapeamento dinâmico
2. Campo que aparece com tipos diferentes em documentos distintos

> **Como o mapeamento é montado.** Nos índices que o pipeline cria explicitamente, ele
> declara `company` e `company_slug` como `text` com subcampo `.keyword`, `pipeline_run` como
> `keyword`, `timestamp` como `date` (aceitando `yyyyMMdd_HHmmss`, `yyyy-MM-dd`,
> `yyyy-MM-dd'T'HH:mm:ss` e `epoch_millis`) e um *dynamic template* que mapeia **toda string
> nova** como `text` + `.keyword` (`ignore_above: 256`). Os **subíndices do coletor** nascem
> por auto-criação, com o mapeamento dinâmico padrão do Elasticsearch — é daí que vêm as
> diferenças de tipo entre índices do mesmo Data View.

**Soluções**:

1. **Verificar o mapeamento atual**:
   ```bash
   curl -X GET "localhost:9200/analise_superficie_dns/_mapping?pretty"
   ```

2. **Atualizar o mapeamento** (apenas adições são permitidas em um índice existente):
   ```bash
   curl -X PUT "localhost:9200/analise_superficie_dns/_mapping" -H 'Content-Type: application/json' -d'
   {
     "properties": {
       "campo_problematico": {
         "type": "text",
         "fields": {
           "keyword": { "type": "keyword", "ignore_above": 256 }
         }
       }
     }
   }'
   ```

3. **Recriar o índice** (quando o tipo não pode ser alterado), usando reindexação:
   ```bash
   # 1. Criar novo índice com o mapeamento correto
   curl -X PUT "localhost:9200/analise_superficie_dns_novo" -H 'Content-Type: application/json' -d'
   { "mappings": { "properties": { "campo_problematico": { "type": "text" } } } }'

   # 2. Reindexar os dados
   curl -X POST "localhost:9200/_reindex" -H 'Content-Type: application/json' -d'
   { "source": { "index": "analise_superficie_dns" }, "dest": { "index": "analise_superficie_dns_novo" } }'

   # 3. Excluir o índice antigo e criar um alias com o nome original
   curl -X DELETE "localhost:9200/analise_superficie_dns"
   curl -X POST "localhost:9200/_aliases" -H 'Content-Type: application/json' -d'
   { "actions": [ { "add": { "index": "analise_superficie_dns_novo", "alias": "analise_superficie_dns" } } ] }'
   ```

### Erro de Bulk Indexing

**Sintoma**: Erro ao indexar documentos em lote.

```
bulk_reject_message: rejected execution of bulk
```

> O pipeline usa `elasticsearch.helpers.bulk`. Em caso de falha no bulk, ele automaticamente
> tenta reenviar **documento por documento** (veja `send_to_elasticsearch` em
> `adint_pipeline.py`). Não há parâmetro `bulk_size` configurável no YAML — essa chave **não
> é lida** pelo código.

**Possíveis Causas**:
1. Fila de escrita do Elasticsearch saturada
2. Recursos insuficientes no servidor

**Soluções**:

1. **Aumentar a fila de escrita** do Elasticsearch (em `elasticsearch.yml`):
   ```yaml
   thread_pool.write.queue_size: 1000
   ```

2. **Reduzir a carga**: processe menos domínios por execução.

3. **Verificar a saúde do cluster** (veja [Diagnóstico do Elasticsearch](#diagnóstico-do-elasticsearch)).

## Problemas com Dados

### Dados Ausentes

**Sintoma**: Alguns dados esperados não estão presentes nos resultados.

**Possíveis Causas**:
1. A ferramenta correspondente falhou (lembre-se: o pipeline segue adiante mesmo com falhas)
2. Arquivo de domínios vazio ou mal formatado
3. `feed`/`telegram` não rodam no pipeline automático
4. Chaves de API ausentes (o `.env` não foi lido — veja o erro nº 4 no topo)

**Soluções**:

1. **Verificar os logs** em `adint_pipeline.log`.

2. **Verificar a entrada**:

   #### Linux/WSL (bash)

   ```bash
   cat dominios.txt     # um domínio por linha, sem http://, sem vírgulas
   ```

3. **Coletar feeds e Telegram separadamente** (não fazem parte de `run_pipeline()`):
   - Feeds RSS → índice `rss-feeds`:
     ```bash
     ./.venv/bin/python3 FEED/rss_feed.py collect-send --feeds-file FEED/feeds.yaml
     ```
     O `--feeds-file` é **obrigatório**. O `feeds.yaml` tem o formato
     `{ Categoria: { Nome: URL } }`.
   - Telegram → índice `vazamentos_dados` (veja [Problemas com o Telegram](#problemas-com-o-telegram)).

### Dados Duplicados

**Sintoma**: Alguns documentos aparecem duplicados.

**Possíveis Causas**:
1. Múltiplas execuções do pipeline para a mesma empresa
2. Documentos sem um `id` estável (o Elasticsearch gera um `_id` novo a cada envio)

> Como o pipeline funciona: quando o documento possui um campo `id`, o `_id` gerado é
> `"<company_slug>_<id>"` (evitando colisões entre empresas e reindexando o mesmo registro).
> Documentos **sem** `id` recebem um `_id` automático — logo, reexecuções geram novos
> documentos. **Não existe** script de deduplicação no projeto, e a chave `deduplication` no
> YAML **não é lida** pelo código.

**Soluções**:

1. **Identificar as execuções** por `pipeline_run`/`timestamp`:
   ```bash
   curl -X GET "localhost:9200/analise_superficie_whois/_search?pretty" -H 'Content-Type: application/json' -d'
   {
     "size": 0,
     "query": { "term": { "company_slug.keyword": "minhaempresa" } },
     "aggs": { "runs": { "terms": { "field": "pipeline_run" } } }
   }'
   ```

2. **Remover as execuções antigas** mantendo apenas a mais recente, filtrando por
   `company_slug` e `pipeline_run` com `_delete_by_query`:
   ```bash
   curl -X POST "localhost:9200/analise_superficie_whois/_delete_by_query" -H 'Content-Type: application/json' -d'
   {
     "query": {
       "bool": {
         "must":     [ { "term": { "company_slug.keyword": "minhaempresa" } } ],
         "must_not": [ { "term": { "pipeline_run": "20250610_143000" } } ]
       }
     }
   }'
   ```

> Em `term`, use **`company_slug.keyword`**: o campo base é `text` (analisado), e um `term`
> sobre ele pode não casar com slugs que tenham maiúsculas, pontos ou hífens.

### Dados Incorretos

**Sintoma**: Alguns dados nos resultados estão incorretos.

**Possíveis Causas**:
1. Erro na coleta ou no processamento
2. Dados incorretos na própria fonte (WHOIS de registrar, cache de DNS, banco do Shodan)

**Soluções**:

1. **Reexecutar a ferramenta manualmente** e inspecionar a saída (veja os comandos em
   [Erro na Execução de uma Ferramenta](#erro-na-execução-de-uma-ferramenta)). Lembre que o
   WHOIS é uma consulta a terceiros: o que vem de volta é o que o registrar publica, e o
   formato varia por TLD.

   Exemplo de saída normalizada (dados **anonimizados**):

   ```json
   {
     "dominio": "exemplo.com.br",
     "titular": "EMPRESA EXEMPLO LTDA",
     "documento": "00.000.000/0001-00",
     "email_admin": "contato@exemplo.com.br",
     "company_slug": "minhaempresa",
     "timestamp": "20250610_143000"
   }
   ```

   > Dados de WHOIS são **dados pessoais e corporativos reais**. Ao colar saída em slides,
   > relatórios ou issues, anonimize como acima.

2. **Corrigir pontualmente** via `_update_by_query`, sempre **filtrando pela empresa** para
   não afetar outras:
   ```bash
   curl -X POST "localhost:9200/analise_superficie_shodan/_update_by_query" -H 'Content-Type: application/json' -d'
   {
     "script": {
       "source": "ctx._source.campo = params.valor",
       "params": { "valor": "valor_correto" }
     },
     "query": {
       "bool": {
         "must": [
           { "term": { "company_slug.keyword": "minhaempresa" } },
           { "term": { "ip": "203.0.113.10" } }
         ]
       }
     }
   }'
   ```

## Problemas com o Telegram

> O Telegram **não** roda pelo pipeline automático. O fluxo é: criar a sessão
> (`TELEGRAM/criar_sessao.py`), baixar com `TELEGRAM/download_Combo.py` e importar com
> `TELEGRAM/import_to_elk.py`, que grava no índice **`vazamentos_dados`** (ou no que estiver
> em `TELEGRAM_INDEX`).
>
> **As credenciais vêm do `.env`**, lido com `python-dotenv`: `TELEGRAM_API_ID`,
> `TELEGRAM_API_HASH`, `TELEGRAM_PHONE`, `TELEGRAM_CHANNEL_ID`, `TELEGRAM_INDEX`. Não edite
> os scripts para colocar credenciais neles.

### Erro de Autenticação

**Sintoma**: Erro ao autenticar com a API do Telegram.

```
AuthorizationError: You're not authorized to use this API
```

**Possíveis Causas**:
1. `TELEGRAM_API_ID`/`TELEGRAM_API_HASH`/`TELEGRAM_PHONE` vazios ou errados no `.env`
2. O `.env` não foi lido porque você rodou de outra pasta (erro nº 4 no topo)
3. Sessão expirada
4. Conta limitada pelo Telegram

**Soluções**:

1. **Conferir o `.env`** (sem imprimir os valores numa tela compartilhada):

   #### Linux/WSL (bash)

   ```bash
   cd <pasta-do-projeto>
   grep -c '^TELEGRAM_API_ID=.\+' .env     # 1 = preenchido, 0 = vazio
   ```

   `api_id` e `api_hash` saem de <https://my.telegram.org/apps>.

2. **Reautenticar** criando a sessão de novo (ele pede o código de login):

   ```bash
   ./.venv/bin/python3 TELEGRAM/criar_sessao.py
   # ou, sem baixar nada:
   ./.venv/bin/python3 TELEGRAM/download_Combo.py --dry-run
   ```

3. **Conferir o canal.** `TELEGRAM_CHANNEL_ID` é o ID numérico, no formato
   `-100XXXXXXXXXX`. Descubra o do seu canal com:

   ```bash
   ./.venv/bin/python3 TELEGRAM/nome_grupos.py
   ```

   > O `download_Combo.py` traz um ID de canal como **valor padrão** no código, usado quando
   > `TELEGRAM_CHANNEL_ID` está vazio. Se você não definiu o seu, pode estar batendo num
   > canal que não é o que você quer — defina sempre no `.env`.

4. **Criar uma nova aplicação** em <https://my.telegram.org/apps> se a conta estiver limitada,
   e atualizar os valores no `.env`.

### Erro ao Baixar Arquivos

**Sintoma**: Erro ao baixar arquivos do Telegram.

```
FloodWaitError: A wait of X seconds is required
```

**Soluções**:

1. **Aguardar** o tempo indicado pelo próprio Telegram e tentar de novo. Não insista em
   loop: o Telegram aumenta a punição.

2. **Reduzir a quantidade** de arquivos por execução. As flags reais do `download_Combo.py`
   são `--limit`, `--ext`, `--since AAAA-MM-DD` e `--dry-run`:

   #### Linux/WSL (bash)

   ```bash
   ./.venv/bin/python3 TELEGRAM/download_Combo.py --limit 5 --ext .txt --since 2025-01-01
   ```

   > Não existem as opções `--output-dir` nem `--days`. O diretório de download é fixo no
   > código (`TELEGRAM/downloads_omega_cloud`).

3. **Falta o `telethon`?** Se o erro for `ModuleNotFoundError: No module named 'telethon'`,
   instale-o no venv que você está usando — veja o passo do Telegram em
   [`INSTALLATION.md`](./INSTALLATION.md). Atenção: o `TELEGRAM/requirements.txt` fixa
   `elasticsearch==7.17.0` e **derruba** o cliente 8.x do pipeline se instalado no `.venv`
   principal.

### Erro ao Importar para o Elasticsearch

**Sintoma**: Erro ao importar os combos baixados para o Elasticsearch.

**Possíveis Causas**:
1. O diretório de downloads esperado está vazio
2. Elasticsearch indisponível
3. Cliente `elasticsearch` 7.17 (do `telegram_venv`) falando com um servidor 8.x

**Soluções**:

1. **Conferir os arquivos baixados** em `TELEGRAM/downloads_omega_cloud` (caminho resolvido a
   partir do próprio script, relativo à pasta `TELEGRAM/`).

2. **Executar o importador** — ele **não recebe argumentos**:

   #### Linux/WSL (bash)

   ```bash
   ./.venv/bin/python3 TELEGRAM/import_to_elk.py
   ```

   Cada documento indexado tem apenas os campos `id` (uuid), `linha` e `arquivo_origem`. O
   host/porta vêm de `ES_HOST`/`ES_PORT` no `.env` (padrão `localhost:9200`) e o índice de
   `TELEGRAM_INDEX` (padrão `vazamentos_dados`).

3. **Se estiver usando o `telegram_venv`** e aparecer erro de versão/compatibilidade de
   cliente, rode o importador pelo `.venv` do pipeline, que tem o cliente 8.x.

## Bugs Conhecidos Já Corrigidos

Esta seção documenta dois problemas reais que já foram **corrigidos** no projeto. Ela serve de
referência caso você esteja usando uma cópia antiga dos arquivos e observe os mesmos sintomas.

### 1. Cliente Elasticsearch e o parâmetro `timeout`

**Sintoma (antes da correção)**: o pipeline falhava logo na conexão com um erro semelhante a:

```
TypeError: __init__() got an unexpected keyword argument 'timeout'
```

**Causa**: o cliente Python `elasticsearch` **removeu** o antigo parâmetro `timeout=` do
construtor.

**Correção aplicada**: `adint_pipeline.py` passou a usar `request_timeout=` em
`connect_to_elasticsearch`:

```python
self.es = Elasticsearch(
    [f"http://{self.es_config['host']}:{self.es_config['port']}"],
    request_timeout=self.es_config['timeout']
)
```

> O `requirements.txt` fixa o cliente em `elasticsearch>=8,<9` para casar com o servidor
> **8.x** do laboratório (testado no 8.15.3). `request_timeout=` funciona no cliente 8.x.

### 2. `action.auto_create_index` bloqueando os subíndices do coletor

**Sintoma (antes da correção)**: o WHOIS, o DNS e o Shodan chegavam ao Elasticsearch, mas os
resultados do **coletor** (httpx, naabu, certs, san, nuclei) **não apareciam** — os subíndices
`analise_superficie_coletor_*` simplesmente não eram criados.

**Causa**: o `ELK/elastisearch.yml` restringia `action.auto_create_index` apenas a índices de
sistema. Como os subíndices do coletor são criados **por auto-criação** (o pipeline não os cria
explicitamente), eles eram rejeitados silenciosamente.

**Correção aplicada**: a diretiva passou a liberar os índices do projeto:

```yaml
action.auto_create_index: analise_superficie_*,vazamentos_dados,rss-feeds*,.monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*
```

O `docker-compose.yml` nasceu já com a mesma liberação na variável de ambiente do container.

Correções relacionadas também já aplicadas:
- O coletor recebe o diretório de saída via variável de ambiente `OUT_DIR` (`os.environ`), não
  como argumento posicional.
- As credenciais do Telegram e a chave do Shodan saíram do código e passaram para o `.env`
  (`python-dotenv`).
- O `coletor.sh` passou a descobrir o diretório dos binários com `pdtm -sp -silent`, em vez de
  assumir um caminho fixo.
- Foi criado o `requirements.txt` na raiz do repositório.
- Foi criado o `ELK/start-elasticsearch-aula.bat` (antes referenciado, porém inexistente).

## Logs e Diagnóstico

### Logs do Pipeline

O `adint_pipeline.py` registra tudo no arquivo `adint_pipeline.log` (nível `INFO`, fixado no
código, criado **no diretório atual**) e também exibe o output das ferramentas em tempo real no
terminal.

> Não existe opção `--verbose`/`-v` no `run_pipeline.sh` nem no `adint_pipeline.py`, e a seção
> `logging` do `pipeline_config.yaml` **não é lida** pelo código. O nível de log é definido
> diretamente em `logging.basicConfig(...)` no script.

#### Linux/WSL (bash)

```bash
# Ver o log completo
cat adint_pipeline.log

# Ver apenas erros
grep "❌" adint_pipeline.log
grep -i "erro" adint_pipeline.log

# Acompanhar em tempo real
tail -f adint_pipeline.log
```

### Diagnóstico do Elasticsearch

#### Linux/WSL (bash)

```bash
# Saúde do cluster
curl -X GET "localhost:9200/_cluster/health?pretty"

# Versão do servidor (deve ser 8.x)
curl -s http://localhost:9200 | jq -r .version.number

# Índices do pipeline
curl -X GET "localhost:9200/_cat/indices/analise_superficie_*?v"

# Contagem de documentos por empresa em um índice
curl -X GET "localhost:9200/analise_superficie_whois/_count?pretty" -H 'Content-Type: application/json' -d'
{ "query": { "term": { "company_slug.keyword": "minhaempresa" } } }'

# Alocação de shards e uso de disco
curl -X GET "localhost:9200/_cat/shards?v"
curl -X GET "localhost:9200/_cat/allocation?v"
```

### Diagnóstico no Kibana (Data Views)

No Kibana 8.x, o antigo **Index Patterns** se chama **Data Views**. Se você não vê dados no
Discover, confira nesta ordem:

1. **O Data View existe?** Kibana → **Stack Management** → **Data Views** →
   **Create data view**, com o padrão `analise_superficie_*` (e um segundo, `rss-feeds*`,
   para os feeds).
2. **Campo de tempo.** Os índices que o pipeline cria mapeiam `timestamp` como `date`; os
   subíndices do coletor, criados por auto-criação, mapeiam o mesmo campo como texto. Num
   Data View que cubra os dois, `timestamp` pode aparecer como *conflict* e não servir de
   campo de tempo — escolha **"I don't want to use the time filter"**. Se você selecionou um
   campo de tempo, um intervalo errado no seletor de datas esconde **tudo**: a causa nº 1 de
   "não aparece nada" no Discover.
3. **Filtro de empresa.** Use `company_slug.keyword : "minhaempresa"`. Filtrar pelo campo
   `company_slug` cru (que é `text`) pode não casar.
4. **Dados existem mesmo?** Confirme pelo `_count` acima antes de culpar o Kibana.

### Diagnóstico de Rede

#### Linux/WSL (bash)

```bash
# Conectividade e portas
ping exemplo.com.br
nc -zv localhost 9200

# Resolução DNS (o pacote apt do "dig" é "dnsutils")
dig exemplo.com.br
```

### Diagnóstico de Recursos

#### Linux/WSL (bash)

```bash
top          # CPU
free -h      # memória
df -h        # disco
ps aux | grep -E "python3|elasticsearch"

# Com Docker:
docker stats
docker compose logs --tail 50 es
```

### Reiniciar Serviços

#### Linux/WSL (bash)

```bash
# Docker (caminho recomendado), na raiz do projeto
docker compose restart es kibana

# Instalado como serviço do sistema
sudo systemctl restart elasticsearch
sudo systemctl restart kibana
```

#### Windows (PowerShell)

```powershell
# Instalação nativa: feche a janela do Elasticsearch (Ctrl+C) e rode de novo
.\ELK\start-elasticsearch-aula.bat
```

### Limpar Dados (com cuidado!)

> **Atenção**: os índices são **gerais** e contêm dados de **todas as empresas**. **Nunca**
> apague índices inteiros se quiser remover apenas uma empresa. Para limpar os dados de uma
> única empresa, use `_delete_by_query` filtrando por `company_slug.keyword`:

#### Linux/WSL (bash)

```bash
# Remover TODOS os documentos de uma empresa, em todos os índices do pipeline
curl -X POST "localhost:9200/analise_superficie_*/_delete_by_query" -H 'Content-Type: application/json' -d'
{ "query": { "term": { "company_slug.keyword": "minhaempresa" } } }'
```

Para recomeçar totalmente do zero (apagando dados de **todas** as empresas), e só então:

```bash
# Apaga TODOS os índices do pipeline — afeta todas as empresas!
curl -X DELETE "localhost:9200/analise_superficie_*"

# Limpa o diretório local de resultados
rm -rf pipeline_results/*

# Com Docker, o equivalente nuclear (apaga o volume es-data):
docker compose down -v
```

---

Precisa de mais detalhes? A instalação completa, a referência de uso de cada ferramenta e o
esquema dos campos indexados estão no [Guia de Instalação](./INSTALLATION.md); a visão geral
do fluxo e a tabela rápida de sintomas, no [README](../README.md). Cada script do projeto
também tem um cabeçalho explicando uso e saída — comece por ele antes de abrir uma issue.
