#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
COLETOR DE FEEDS RSS -> Elasticsearch (ILM + alias + bulk)
==========================================================
CLI com argparse, nao interativo. Modulo FEED do curso ADINT.

O QUE FAZ
  Le uma lista de fontes RSS/Atom de `feeds.yaml`, baixa as ultimas entradas de
  cada fonte, normaliza tudo em JSON e indexa no Elasticsearch sob um alias de
  escrita com ILM (rollover + expurgo automatico).

POR QUE RSS SERVE A INTELIGENCIA DE AMEACAS
  Um feed RSS/Atom e um XML que o proprio site publica com as ultimas materias:
  titulo, link, data, resumo e tags. Para ADINT e a melhor fonte de "o que
  acabou de acontecer", porque e:
    - PUBLICO    : nao pede login, token nem contrato — e OSINT puro;
    - BARATO     : uma requisicao HTTP por fonte, sem cota de API pra estourar;
    - ATUALIZADO : o fornecedor publica em minutos, nao em relatorio trimestral;
    - PADRONIZADO: NVD, fabricante e blog chegam no mesmo esquema, entao da pra
                   agregar e comparar fontes diferentes no mesmo painel.
  Com CVE + noticia + vazamento num indice unico, voce cruza o que saiu no
  mundo com a superficie de ataque do SEU alvo (o "relatorio de exposicao" da
  aula). O feed e o CONTRAPONTO PUBLICO dos canais de Telegram: a fonte publica
  diz que a FALHA EXISTE; o canal do Telegram diz que ALGUEM JA ESTA USANDO.

COMO RODAR  (da raiz do projeto, com o Python do venv)
  # 1) preparar o ES: politica ILM + template + indice inicial com alias
  ./.venv/bin/python3 FEED/rss_feed.py setup \
      --feeds-file FEED/feeds.yaml --es-host localhost --es-port 9200

  # 2) coletar e salvar os JSONs em disco (nao toca no ES)
  ./.venv/bin/python3 FEED/rss_feed.py collect \
      --feeds-file FEED/feeds.yaml --output-dir rss_feeds

  # 3) enviar os JSONs ja coletados (varredura recursiva de *.json)
  ./.venv/bin/python3 FEED/rss_feed.py send \
      --feeds-file FEED/feeds.yaml --input rss_feeds \
      --es-host localhost --es-port 9200

  # coletar e enviar numa rodada so, filtrando os ultimos 7 dias
  ./.venv/bin/python3 FEED/rss_feed.py collect-send \
      --feeds-file FEED/feeds.yaml --output-dir rss_feeds --days 7 \
      --es-host localhost --es-port 9200

  Flags de ES aceitas em TODOS os subcomandos: --es-host, --es-port,
  --es-scheme {http,https}, --es-user, --es-pass, --es-ssl, --es-no-verify e
  --index (alias de escrita; default `rss-feeds`).
  ATENCAO: --feeds-file e OBRIGATORIO em todos os subcomandos, inclusive em
  `setup` e `send` — o parser exige mesmo onde o conteudo nem e usado.

O QUE PRODUZ
  - Em disco:  <output-dir>/<Categoria>/<Nome_Do_Feed>.json, no formato
               {"feed_info": {...},
                "entries": [{title, link, published, summary, author, tags,
                             content_hash}, ...]}
  - No ES:     alias de escrita `rss-feeds` -> indice `rss-feeds-000001`
               (rollover a cada 30d/20gb; documentos apagados com 180 dias
               pela politica ILM `rss-feeds-ilm`).
  Conferir o que entrou:
    curl -s "http://localhost:9200/_cat/indices/rss-feeds-*?v"
    curl -s "http://localhost:9200/rss-feeds/_count"

O QUE PRECISA
  - Python 3.10+ e:  pip install feedparser requests 'elasticsearch>=8,<9' pyyaml
  - Elasticsearch 8.x no ar (`docker compose up -d` na raiz do projeto)
  - FEED/feeds.yaml com as fontes (como acrescentar: veja load_feeds_file())
  - saida de internet para o dominio de cada feed
  - RSS_MAX_ENTRIES (opcional): teto de entradas por feed; default 100

AVISOS
  - Coleta PASSIVA: so faz GET no feed publico do site. Nao manda pacote pra
    alvo nenhum e nao substitui autorizacao pra qualquer atividade ativa.
  - "0 documentos" NAO e "nada aconteceu". Leia o bloco de datas vazias em
    send_to_elasticsearch(): ja houve bug aqui que relatava sucesso com o
    indice vazio.
  - FONTE MORRE. Feed que virou 404, que passou a responder 403 atras de WAF ou
    que entrega XML quebrado e rotina, nao excecao: veja fetch_feed().
  - Rodar de hora em hora e seguro: a indexacao e IDEMPOTENTE (content_hash
    como _id, com _op_type="create"). Veja send_to_elasticsearch().
"""

import argparse, os, json, logging, hashlib, time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

import requests, feedparser
from elasticsearch import Elasticsearch, helpers

try:
    import yaml  # opcional (YAML)
    HAS_YAML = True
except Exception:
    # Sem PyYAML o script ainda roda, mas so aceita --feeds-file em JSON.
    HAS_YAML = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("rss-elk")

# Teto de entradas por feed. Alguns feeds (OpenAI, Hugging Face) devolvem o
# historico INTEIRO (1000+ entradas) e inundam o indice, distorcendo as
# agregacoes do Dia 2. 100 e generoso e deixa todos os feeds comparaveis.
#
# Ajuste sem editar o codigo:  RSS_MAX_ENTRIES=300 ./.venv/bin/python3 ...
# Detalhe que confunde: o corte e aplicado ANTES do filtro --days (veja
# save_feed_to_json). Num feed muito prolixo, pedir "--days 30" pode devolver
# menos do que voce espera, porque so as 100 entradas mais recentes chegaram a
# ser avaliadas. Se faltar historico, suba o teto em vez de culpar a fonte.
MAX_ENTRIES_PER_FEED = int(os.environ.get("RSS_MAX_ENTRIES", "100"))

# -------------------- Loader de feeds externos (YAML/JSON) --------------------
def load_feeds_file(path: str) -> Dict[str, Dict[str, str]]:
    """Carrega o arquivo de fontes (--feeds-file) e valida o formato.

    O `feeds.yaml` e o unico lugar onde as fontes vivem: o codigo nao tem
    nenhuma URL fixa. O formato tem exatamente dois niveis —
    {CATEGORIA: {NOME DO FEED: URL}}:

        CVEs:
          CVEFeed Latest: https://exemplo.invalido/rssfeed/latest.xml
        Cybersecurity:
          Nome Que Voce Escolher: https://outro-exemplo.invalido/feed/

    COMO O ALUNO ACRESCENTA UMA FONTE
      1. Ache o feed no site (link "RSS", /feed/, /rss.xml, /index.xml, ou
         procure por <link type="application/rss+xml"> no HTML da pagina).
      2. TESTE ANTES de confiar:
           curl -sI  https://site.invalido/feed/        # quer 200, nao 404/403
           curl -s   https://site.invalido/feed/ | head # quer XML com <item>
      3. Acrescente a linha `  Nome Do Feed: URL` sob a categoria desejada —
         ou crie uma categoria nova so escrevendo `MinhaCategoria:` na coluna 0.
      4. Rode `collect` e confira a contagem de entradas no log.

    O que a categoria faz: ela vira a pasta de saida em disco e o campo
    `category` do documento no ES — e por ela que os paineis do Kibana
    separam "CVEs" de "Vendors". O NOME do feed e a chave de ligacao entre o
    JSON salvo e a categoria (veja categorize_feed()); se renomear o feed no
    YAML depois de ja ter coletado, os JSONs antigos caem em "Unknown".

    Cuidados de YAML que queimam tempo em aula:
      - indentacao com ESPACOS, nunca TAB;
      - URL com `:` nao precisa de aspas aqui porque o `: ` do separador vem
        antes, mas se o NOME do feed tiver `:` ou `#`, ponha o nome entre
        aspas;
      - nada de URL duplicada: a chave e o nome, entao dois nomes diferentes
        apontando pra mesma URL indexam a mesma noticia duas vezes com
        `feed_name` diferente.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        if not HAS_YAML:
            raise RuntimeError("PyYAML não instalado. `pip install pyyaml`")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    # Validacao do formato: falhar aqui, com mensagem clara, e muito melhor que
    # descobrir o YAML torto no meio da coleta.
    if not isinstance(data, dict):
        raise ValueError("feeds-file deve ser um objeto {categoria: {nome: url}}")
    for cat, feeds in data.items():
        if not isinstance(feeds, dict):
            raise ValueError(f"categoria '{cat}' deve mapear para objeto {{nome: url}}")
        for name, url in feeds.items():
            if not isinstance(url, str) or not url.strip():
                raise ValueError(f"feed inválido em '{cat}':'{name}'")
    return data


# ------------------------------- Processador ---------------------------------
class RSSToELK:
    """Coletor + indexador. As duas metades sao independentes de proposito:
    `collect` so escreve JSON em disco e `send` so le JSON e fala com o ES.
    Separar e didatico (da pra inspecionar o JSON antes de indexar) e pratico
    (se o ES cair, a coleta nao se perde — basta rodar `send` depois)."""

    def __init__(self, es_config: Optional[dict] = None, feeds_by_category: Optional[dict] = None, index_alias: str = "rss-feeds"):
        # Uma unica Session para todos os feeds: reaproveita conexao TCP/TLS e
        # deixa a coleta bem mais rapida que um requests.get() solto por feed.
        self.session = requests.Session()
        # User-Agent proprio e boa educacao (o dono do site ve quem bateu) e,
        # em alguns sites, evita o bloqueio de cliente sem identificacao.
        # NAO espere milagre: contra WAF (CISA/Akamai, por exemplo) trocar o
        # User-Agent nao resolve nada. Veja fetch_feed().
        self.session.headers.update({"User-Agent": "RSS-ELK/1.1"})
        self.es_config = es_config or {'host': 'localhost', 'port': 9200, 'scheme': 'http', 'use_ssl': False, 'verify_certs': True}
        self.es: Optional[Elasticsearch] = None
        self.feeds_by_category = feeds_by_category or {}
        self.index_alias = index_alias

    # --------- ES ---------
    def connect_to_elasticsearch(self) -> bool:
        """Abre a conexao com o Elasticsearch e confirma com um ping.

        Compatível com elasticsearch-py 8/9 (sync). Nao levanta excecao: devolve
        False e quem chamou decide (o main() encerra com SystemExit(1)).
        O ping e importante — sem ele o erro so apareceria no bulk, ja no fim.
        """
        try:
            params = {
                'hosts': [f"{self.es_config['scheme']}://{self.es_config['host']}:{self.es_config['port']}"],
                'request_timeout': 30,  # v9 prefere request_timeout
                'retry_on_timeout': True,
                'max_retries': 3
            }
            # v9: basic_auth; v8 ainda aceita http_auth
            if self.es_config.get('username') and self.es_config.get('password'):
                params['basic_auth'] = (self.es_config['username'], self.es_config['password'])
            elif self.es_config.get('username') and self.es_config.get('password_env'):
                params['basic_auth'] = (self.es_config['username'], os.environ.get(self.es_config['password_env'], ''))
            if self.es_config.get('use_ssl', False):
                params['verify_certs'] = self.es_config.get('verify_certs', True)

            self.es = Elasticsearch(**params)
            if self.es.ping():
                log.info("✅ Conectado ao Elasticsearch")
                return True
            log.error("❌ Falha ao conectar (ping)")
            return False
        except Exception as e:
            log.error(f"❌ Erro ao conectar ao ES: {e}")
            self.es = None
            return False

    def ensure_ilm_and_template(self) -> None:
        """Cria/atualiza ILM, template e índice inicial com alias de escrita.

        Os tres pedacos, na ordem, porque um depende do outro:

        1. POLITICA ILM (`rss-feeds-ilm`) — o ciclo de vida do indice. Feed
           cresce pra sempre; sem ILM o disco do laboratorio enche. Aqui:
           rollover (abre indice novo) a cada 30 dias ou 20 GB, e apaga o que
           passar de 180 dias.
        2. TEMPLATE (`rss-feeds-template`) — diz ao ES como mapear os campos de
           QUALQUER indice `rss-feeds-*` criado dali pra frente. Sem template, o
           ES adivinha o tipo pelo primeiro documento, e uma adivinhacao errada
           (data virando `text`) so aparece quando o painel nao agrega.
        3. INDICE INICIAL + ALIAS — escrevemos sempre no alias `rss-feeds`, e o
           alias aponta pro indice atual (`rss-feeds-000001`, depois -000002...).
           E o alias que faz o rollover ser invisivel pra quem indexa.

        E idempotente: roda em todo `send` e nao reclama se ja existir. Os
        `except` sao de proposito largos — num laboratorio sem privilegio de ILM
        o template ainda vale a pena.
        """
        if not self.es:
            raise RuntimeError("ES não conectado")

        # ILM: hot -> rollover; delete -> expurgo. Ajuste os numeros se o seu
        # laboratorio for pequeno (ex.: max_age 7d / min_age 30d).
        try:
            self.es.ilm.put_lifecycle(policy="rss-feeds-ilm", body={
                "policy": {"phases": {
                    "hot": {"actions": {"rollover": {"max_age": "30d", "max_size": "20gb"}}},
                    "delete": {"min_age": "180d", "actions": {"delete": {}}}
                }}
            })
        except Exception as e:
            log.warning(f"ILM: {e}")

        # Template: vale para todo indice que casar com `rss-feeds-*`. Mexer no
        # template NAO reescreve indice que ja existe — so vale para os novos.
        try:
            self.es.indices.put_index_template(name="rss-feeds-template", body={
                "index_patterns": [f"{self.index_alias}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1, "number_of_replicas": 1,
                        "index.refresh_interval": "1s",
                        # ---------------------------------------------------
                        # ARMADILHA CLASSICA: DATA VAZIA DERRUBA O DOCUMENTO
                        # ---------------------------------------------------
                        # Num campo mapeado como `date`, o ES NAO aceita string
                        # vazia: ele REJEITA O DOCUMENTO INTEIRO com
                        # "failed to parse date field ... cannot parse empty
                        # date". E muito comum — tem feed que publica <item>
                        # sem <pubDate>, ou com data em formato que o
                        # feedparser nao entende.
                        # `ignore_malformed` manda o ES ignorar SO O CAMPO
                        # problematico e indexar o resto do documento. Esta e a
                        # segunda metade da defesa; a primeira e converter a
                        # data vazia para None antes do envio (veja
                        # send_to_elasticsearch).
                        # Era este o bug que indexava 0 documentos relatando
                        # sucesso: o ES recusava tudo e o script contava os
                        # ENVIADOS, nao os ACEITOS.
                        "index.mapping.ignore_malformed": True,
                        "index.lifecycle.name": "rss-feeds-ilm",
                        "index.lifecycle.rollover_alias": self.index_alias
                    },
                    # Mapeamento explicito: `keyword` para o que se filtra e
                    # agrega (feed_name, category, link), `text` para o que se
                    # busca por palavra (title, summary). `title.raw` da as duas
                    # coisas no mesmo campo: busca em `title`, agregacao em
                    # `title.raw`.
                    "mappings": {"properties": {
                        "@timestamp": {"type": "date"},
                        "feed_name": {"type":"keyword"},
                        "feed_title": {"type":"text"},
                        "feed_description": {"type":"text"},
                        "feed_link": {"type":"keyword"},
                        "feed_updated": {"type":"date"},   # <- campo `date`: ver armadilha acima
                        "entry_id": {"type":"keyword"},
                        "title": {"type":"text", "fields":{"raw":{"type":"keyword","ignore_above":256}}},
                        "link": {"type":"keyword"},
                        "published": {"type":"date"},      # <- campo `date`: ver armadilha acima
                        "summary": {"type":"text"},
                        "author": {"type":"keyword"},
                        "tags": {"type":"keyword","ignore_above":256},
                        "content_hash": {"type":"keyword"},  # chave de idempotencia (= _id)
                        "category": {"type":"keyword"},
                        "source_type": {"type":"keyword"}
                    }}
                }
            })
            log.info("🧩 template criado/atualizado")
        except Exception as e:
            log.warning(f"template: {e}")

        # Índice inicial + alias. O sufixo -000001 e exigencia do rollover: o
        # ILM incrementa esse numero. `is_write_index` marca qual indice recebe
        # a escrita feita no alias.
        try:
            if not self.es.indices.exists_alias(name=self.index_alias):
                self.es.indices.create(index=f"{self.index_alias}-000001",
                                       aliases={self.index_alias: {"is_write_index": True}},
                                       ignore=400)
        except Exception as e:
            log.warning(f"índice inicial/alias: {e}")

    # --------- Coleta ---------
    def fetch_feed(self, url: str):
        """Baixa e parseia um feed. Devolve o objeto do feedparser ou None.

        =====================================================================
        FONTES MORREM — e isso faz parte do trabalho, nao e acidente
        =====================================================================
        Manter uma lista de feeds e manutencao continua. Os quatro jeitos de
        uma fonte morrer, todos ja vistos no `feeds.yaml` deste curso:

          404 / endpoint mudou  — o site reorganizou o blog e o /feed/ foi
              embora (abuse.ch, Elastic Security Labs), ou a fonte APOSENTOU o
              RSS de proposito: o NVD aposentou o nvd-rss.xml e hoje so oferece
              a API JSON 2.0. Nao tem o que consertar na URL: a fonte acabou.

          403 atras de WAF     — o servidor responde, mas o WAF corta. E o caso
              dos avisos da CISA (Akamai). TROCAR O USER-AGENT NAO RESOLVE WAF:
              o bloqueio e por reputacao de IP, fingerprint de TLS e
              comportamento, nao pela string que voce manda. Se um navegador
              normal tambem toma 403, pare de brincar com cabecalho — a saida e
              a API oficial da fonte ou outra rota de rede. Insistir com
              retentativa so queima o seu IP mais rapido.

          XML malformado       — HTTP 200, corpo quebrado. O feedparser levanta
              a flag `bozo` e normalmente devolve 0 entradas (ja aconteceu com
              o blog do MSRC). Note que aqui isso e so WARNING: o feed segue
              adiante e pode salvar um JSON com `entries: []`.

          200 e vazio          — a fonte trocou o formato e o parser nao acha
              mais <item>/<entry> (arXiv). O caso mais traicoeiro, porque NAO
              DA ERRO NENHUM.

        COMO O ALUNO PERCEBE QUE UMA FONTE MORREU
          - no log da coleta: `tentativa 1/3 falhou`, `erro em <url>`,
            `⚠️ falha: <nome>`, `bozo em <url>` ou `(0 entradas)` no 💾 salvo;
          - no disco: um JSON com `"entries": []`;
          - no ES, o jeito mais honesto — contar documentos por fonte e ver
            quem parou de aparecer:
              curl -s "http://localhost:9200/rss-feeds/_search?size=0" \
                -H 'Content-Type: application/json' -d '{"aggs":{"por_fonte":
                {"terms":{"field":"feed_name","size":100}}}}'
            Fonte viva publica toda semana. Fonte com contagem congelada ha
            dias esta morta, mesmo que o script nao tenha dado erro.
          - regra de ouro do curso: "zero achados" e "zero verificado" sao a
            mesma saida e coisas opostas. Antes de concluir que "nao houve
            noticia", confirme que a coleta chegou na fonte.

        Quando uma fonte morre, documente e siga: no `feeds.yaml` deste
        projeto as fontes mortas ficam COMENTADAS no fim do arquivo, com o
        motivo e a data do teste. Isso evita o proximo aluno perder uma hora
        reanimando um feed que o fornecedor desligou.

        Sobre a retentativa: 3 tentativas com espera crescente (2s, 4s, 6s)
        resolvem instabilidade de rede e 429/5xx momentaneo.
        """
        last_err = None
        for attempt in range(3):
            try:
                # timeout SEMPRE. Sem ele, um feed que aceita a conexao e nunca
                # responde travaria a coleta inteira.
                r = self.session.get(url, timeout=20)
                r.raise_for_status()   # 4xx/5xx viram excecao -> cai no retry
                feed = feedparser.parse(r.content)
                # `bozo` = o feedparser conseguiu algo, mas o XML esta fora do
                # padrao. Nao e fatal (muito feed real e levemente torto), mas
                # se vier com 0 entradas, suspeite do formato da fonte.
                if getattr(feed, 'bozo', False):
                    log.warning(f"bozo em {url}: {getattr(feed, 'bozo_exception', None)}")
                return feed
            except Exception as e:
                last_err = e
                sleep_s = 2*(attempt+1)
                log.warning(f"tentativa {attempt+1}/3 falhou {url}: {e} (retry {sleep_s}s)")
                time.sleep(sleep_s)
        # Desistiu: devolve None e collect_feeds() segue para o proximo feed.
        # Uma fonte morta NAO derruba a coleta das outras — de proposito.
        log.error(f"erro em {url}: {last_err}")
        return None

    @staticmethod
    def _safe_name(name: str) -> str:
        """Nome de feed -> nome de arquivo. "SANS Internet Storm Center (ISC)"
        tem espaco e parentese; em nome de arquivo isso da dor de cabeca em
        shell e no Windows. Troca tudo que nao for alfanumerico/._- por "_"."""
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

    def save_feed_to_json(self, feed, feed_name: str, filename: str, min_datetime: Optional[datetime]) -> int:
        """Salva feed em JSON. Se min_datetime for definido, filtra entradas anteriores.

        Esta funcao e o "TRATAR" do pipeline: tira o que interessa do XML e
        grava um JSON com esquema estavel, igual para toda fonte. Devolve a
        quantidade de entradas salvas (0 tambem e resposta valida — veja
        fetch_feed() sobre fontes mortas).
        """
        try:
            entries = []
            # O corte do teto vem ANTES do filtro de data (veja o comentario em
            # MAX_ENTRIES_PER_FEED).
            for entry in getattr(feed, "entries", [])[:MAX_ENTRIES_PER_FEED]:
                # ---- data ----------------------------------------------------
                # `published_parsed` e a data JA normalizada pelo feedparser
                # (ele entende RFC 822, ISO 8601 e varios formatos tortos).
                # Quando a fonte nao traz data, ou traz num formato que nem o
                # feedparser decifra, `published_parsed` vem None e aqui fica
                # STRING VAZIA. Essa string vazia e a origem da armadilha de
                # data do Elasticsearch — veja send_to_elasticsearch(), que a
                # converte para None antes de indexar.
                pub_parsed = entry.get("published_parsed")
                published_iso = (datetime(*pub_parsed[:6], tzinfo=timezone.utc).isoformat() if pub_parsed else "")
                # ---- filtro temporal (--days) --------------------------------
                # Entrada SEM data nunca e descartada pelo filtro (a condicao
                # exige published_iso). E deliberado: na duvida, melhor indexar
                # uma noticia sem data do que perder a noticia.
                if min_datetime and published_iso:
                    try:
                        ts = datetime.fromisoformat(published_iso.replace("Z", "+00:00"))
                        if ts < min_datetime:
                            continue
                    except Exception:
                        pass

                # ---- IDEMPOTENCIA: o content_hash ---------------------------
                # Impressao digital da noticia = md5(titulo + link + data).
                # Esse hash vira o _id do documento no ES (veja
                # send_to_elasticsearch), e e o que permite rodar este coletor
                # de hora em hora sem duplicar: um feed RSS mostra as mesmas
                # 20 noticias a cada chamada; na 2a rodada o hash e o mesmo,
                # o _id e o mesmo, e o ES nao cria documento novo.
                # Por que titulo+link+data e nao so o link: o link e quase
                # sempre unico, mas ha feed que reaproveita URL (paginas de
                # "ultimas") e feed que muda o link mantendo a materia. Os tres
                # juntos erram menos.
                # Consequencia a conhecer: se a fonte CORRIGIR o titulo de uma
                # materia ja publicada, o hash muda e a noticia entra de novo
                # como documento novo. E o preco de nao depender de id da
                # fonte, que muita fonte nao fornece de forma estavel.
                hsrc = f"{entry.get('title','')}{entry.get('link','')}{entry.get('published','')}"
                content_hash = hashlib.md5(hsrc.encode("utf-8")).hexdigest()
                # tags: no feedparser cada tag e um objeto; o `term` e o texto.
                tags = [t.term for t in getattr(entry, "tags", []) if hasattr(t, "term")]
                entries.append({
                    "title": entry.get("title",""),
                    "link": entry.get("link",""),
                    "published": published_iso,
                    # RSS usa <description>, Atom usa <summary>: tenta os dois.
                    "summary": entry.get("summary", entry.get("description","")),
                    "author": entry.get("author",""),
                    "tags": tags,
                    "content_hash": content_hash
                })

            # `feed_info` descreve a FONTE; `entries`, as noticias. Os getattr
            # com default existem porque feed quebrado pode nao ter nem
            # `feed.title`. `collected_at` e a hora da COLETA (nao a da
            # publicacao) — serve para auditar quando voce viu aquilo.
            data = {
                "feed_info": {
                    "name": feed_name,
                    "title": getattr(feed.feed, "title", feed_name) if hasattr(feed, "feed") else feed_name,
                    "description": getattr(feed.feed, "description", "") if hasattr(feed, "feed") else "",
                    "link": getattr(feed.feed, "link", "") if hasattr(feed, "feed") else "",
                    "updated": getattr(feed.feed, "updated", "") if hasattr(feed, "feed") else "",
                    "collected_at": datetime.now(timezone.utc).isoformat()
                },
                "entries": entries
            }
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            log.info(f"💾 salvo: {filename} ({len(entries)} entradas)")
            return len(entries)
        except Exception as e:
            log.error(f"salvar JSON: {e}")
            return 0

    def collect_feeds(self, output_dir: str, days: Optional[int]) -> None:
        """Percorre todas as categorias/feeds e salva um JSON por fonte.

        Saida em disco: <output_dir>/<Categoria>/<Nome_Do_Feed>.json
        A pasta por categoria nao e enfeite: e ela que o `send` usa para
        reconstruir o campo `category` do documento.
        """
        os.makedirs(output_dir, exist_ok=True)
        min_dt = None
        if days and days > 0:
            min_dt = datetime.now(timezone.utc) - timedelta(days=days)
            log.info(f"⏱️ janela: últimos {days} dias (min_datetime={min_dt.isoformat()})")

        for category, feeds in self.feeds_by_category.items():
            log.info(f"📚 Categoria: {category}")
            catdir = os.path.join(output_dir, category.replace("/", "_"))
            os.makedirs(catdir, exist_ok=True)
            for feed_name, url in feeds.items():
                log.info(f"🔍 {feed_name} - {url}")
                feed = self.fetch_feed(url)
                if not feed:
                    # Fonte morta/bloqueada: avisa e vai pra proxima. Este
                    # "⚠️ falha:" e o primeiro sinal de que a lista precisa de
                    # manutencao.
                    log.warning(f"⚠️ falha: {feed_name}")
                    continue
                safe = self._safe_name(feed_name)
                self.save_feed_to_json(feed, feed_name, os.path.join(catdir, f"{safe}.json"), min_dt)
        log.info("✅ coleta concluída")

    # --------- Envio ---------
    def load_json_feed(self, path: str) -> Optional[dict]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.error(f"carregar {path}: {e}")
            return None

    def categorize_feed(self, feed_name: str) -> str:
        """Descobre a categoria de um feed pelo NOME, consultando o feeds.yaml.

        Por isso o `--feeds-file` e exigido tambem no `send`. Se o documento
        cair em "Unknown" no ES, a causa quase sempre e uma destas: o nome do
        feed foi renomeado no YAML depois da coleta, ou voce esta enviando
        JSONs coletados com um feeds.yaml diferente do atual.
        """
        for category, feeds in self.feeds_by_category.items():
            if feed_name in feeds:
                return category
        return "Unknown"

    def send_to_elasticsearch(self, src: str) -> None:
        """Le os JSONs (arquivo ou pasta, recursivo) e indexa via Bulk API.

        `src` pode ser um .json ou um diretorio — neste caso varre tudo que
        termina em .json, em qualquer subpasta.
        """
        if not self.es:
            log.error("ES não conectado!")
            return
        self.ensure_ilm_and_template()

        files: List[str] = []
        if os.path.isfile(src) and src.endswith(".json"):
            files = [src]
        elif os.path.isdir(src):
            for root, _, fs in os.walk(src):
                for f in fs:
                    if f.endswith(".json"):
                        files.append(os.path.join(root, f))
        else:
            log.error(f"caminho inválido: {src}")
            return

        log.info(f"📤 enviando {len(files)} arquivos...")
        total = 0
        for i, jf in enumerate(sorted(files), 1):
            log.info(f"[{i}/{len(files)}] {os.path.basename(jf)}")
            data = self.load_json_feed(jf)
            if not data: 
                continue
            feed_info = data.get("feed_info", {})
            feed_name = feed_info.get("name", os.path.splitext(os.path.basename(jf))[0])
            category = self.categorize_feed(feed_name)

            # Monta a lista de acoes do Bulk. Um unico request com N operacoes
            # e ordens de grandeza mais rapido que N requests.
            actions = []
            for e in data.get("entries", []):
                # @timestamp e o eixo de tempo dos paineis do Kibana. Entrada
                # sem data recebe "agora" — assim ela NAO desaparece do painel
                # por falta de eixo. Repare que, diferente de `published`, aqui
                # nunca pode ficar vazio.
                ts = e.get("published") or datetime.now(timezone.utc).isoformat()
                srcdoc = {
                    "@timestamp": ts, "feed_name": feed_name,
                    "feed_title": feed_info.get("title",""),
                    "feed_description": feed_info.get("description",""),
                    "feed_link": feed_info.get("link",""),
                    # =====================================================
                    # ARMADILHA REAL E IMPORTANTE: STRING VAZIA EM CAMPO date
                    # =====================================================
                    # `""` NAO e data valida para o Elasticsearch. Mandar ""
                    # num campo mapeado como `date` faz o ES REJEITAR O
                    # DOCUMENTO INTEIRO ("cannot parse empty date") — nao
                    # apenas ignorar o campo. E feed sem <pubDate> e comum.
                    #
                    # Por que isso ja foi um bug grave AQUI: se o script
                    # contasse "documentos ENVIADOS" (len(actions)) em vez de
                    # "documentos ACEITOS", ele imprimiria "concluido: 1.847
                    # documentos" com o indice COMPLETAMENTE VAZIO. Falha
                    # silenciosa, relatorio de sucesso — o pior tipo de erro,
                    # porque voce so descobre na aula seguinte, quando o painel
                    # nao tem nada.
                    #
                    # A defesa aqui tem TRES camadas:
                    #   1. `or None`  (estas duas linhas) — converte "" em
                    #      null, que o ES aceita sem reclamar em campo de data;
                    #   2. `index.mapping.ignore_malformed: True` no template
                    #      (ensure_ilm_and_template) — rede de seguranca para
                    #      data em formato estranho que escape da camada 1;
                    #   3. contar SUCESSOS reais no bulk, logo abaixo — para o
                    #      numero do relatorio nunca mentir.
                    #
                    # Como CONFIRMAR que entrou (nao confie so no log):
                    #   curl -s "http://localhost:9200/rss-feeds/_count"
                    "feed_updated": (feed_info.get("updated") or None),   # data vazia -> null (nao "")
                    "entry_id": e.get("entry_id",""),
                    "title": e.get("title",""), "link": e.get("link",""),
                    "published": (e.get("published") or None),           # data vazia -> null (nao "")
                    "summary": e.get("summary",""),
                    "author": e.get("author",""), "tags": e.get("tags",[]),
                    "content_hash": e.get("content_hash",""),
                    "category": category, "source_type": "rss_feed"
                }
                # =============================================================
                # IDEMPOTENCIA — o conceito que permite rodar de hora em hora
                # =============================================================
                # O _id do documento NAO e gerado pelo ES: e o `content_hash`
                # calculado na coleta (md5 de titulo+link+data). Como o hash da
                # mesma noticia e sempre o mesmo, o _id tambem e — e indexar
                # duas vezes nao gera dois documentos.
                # `_op_type: "create"` reforca isso: "crie SE NAO EXISTIR". Se
                # o _id ja estiver no indice, o ES recusa aquela operacao
                # (version_conflict) e o documento original fica INTACTO. E a
                # escolha certa para noticia: o primeiro registro e o historico.
                # (Se o objetivo fosse ATUALIZAR o documento existente, o
                # _op_type seria "index", que sobrescreve.)
                # Resultado pratico: agende `collect-send` no cron de hora em
                # hora sem medo. Cada rodada traz as mesmas ~20 noticias do
                # feed, e so a NOVIDADE entra.
                # Ponto de atencao ao ler o log: com "create", rodada repetida
                # faz os duplicados aparecerem na contagem de REJEITADOS. Ver
                # "⚠️ N documentos rejeitados" numa 2a execucao geralmente
                # significa "a deduplicacao funcionou", nao "deu erro" — confira
                # o _count antes de se preocupar.
                doc_id = e.get("content_hash") or hashlib.md5(f"{srcdoc['title']}{srcdoc['link']}{srcdoc['published']}".encode("utf-8")).hexdigest()
                actions.append({"_index": self.index_alias, "_id": doc_id, "_op_type": "create", "_source": srcdoc})

            if actions:
                # conta SUCESSOS reais (nao len(actions)): o bug antigo relatava
                # "enviados" mesmo quando o ES rejeitava tudo em silencio
                #
                # `raise_on_error=False` -> uma entrada ruim nao aborta o lote;
                # `stats_only=True`      -> devolve (aceitos, rejeitados) em vez
                #                           da lista de erros.
                # O `ok` e a UNICA fonte de verdade do relatorio final. Se
                # quiser ver o MOTIVO de cada rejeicao durante a aula, rode o
                # bulk com stats_only=False num shell Python e imprima os erros.
                ok, errs = helpers.bulk(self.es, actions, raise_on_error=False, stats_only=True)
                total += ok
                if errs:
                    log.warning(f"⚠️ {errs} documentos rejeitados em {feed_name}")
        # "indexados (com sucesso)" e literal: e a soma dos ACEITOS pelo ES.
        # Se isso vier 0 com feeds coletados, o problema esta no ES (mapeamento,
        # permissao, auto_create_index), nao na coleta.
        log.info(f"🎉 concluído: {total} documentos indexados (com sucesso)")

# ------------------------------- CLI --------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Coleta RSS e envia para Elasticsearch (ILM + alias) — CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Flags comuns a TODOS os subcomandos. Por isso `collect` tambem aceita
    # --es-host (e nao usa) e `setup` tambem exige --feeds-file (e nao usa).
    def es_opts(sp):
        sp.add_argument("--es-host", default="localhost")
        sp.add_argument("--es-port", type=int, default=9200)
        sp.add_argument("--es-scheme", default="http", choices=["http","https"])
        sp.add_argument("--es-user")
        sp.add_argument("--es-pass")
        sp.add_argument("--es-ssl", action="store_true")
        sp.add_argument("--es-no-verify", action="store_true")
        sp.add_argument("--index", default="rss-feeds", help="Alias/índice de escrita (default: rss-feeds)")
        sp.add_argument("--feeds-file", required=True, help="Arquivo YAML/JSON com feeds categorizados")

    # Os 4 subcomandos. A ordem natural na aula e: setup -> collect -> send.
    sp_collect = sub.add_parser("collect", help="Coletar feeds e salvar JSONs")
    sp_collect.add_argument("--output-dir", default="rss_feeds")
    sp_collect.add_argument("--days", type=int, default=None, help="Filtrar apenas últimos N dias")
    es_opts(sp_collect)

    sp_send = sub.add_parser("send", help="Enviar JSONs p/ Elasticsearch (busca recursiva de .json)")
    sp_send.add_argument("--input", default="rss_feeds")
    es_opts(sp_send)

    sp_both = sub.add_parser("collect-send", help="Coletar e enviar numa rodada")
    sp_both.add_argument("--output-dir", default="rss_feeds")
    sp_both.add_argument("--days", type=int, default=None, help="Filtrar apenas últimos N dias")
    es_opts(sp_both)

    sp_setup = sub.add_parser("setup", help="Criar/atualizar ILM + template + índice inicial (alias)")
    es_opts(sp_setup)
    return p

def make_proc(args) -> RSSToELK:
    """Traduz os argumentos da CLI no objeto que faz o trabalho.

    Usuario e senha do ES so entram se os DOIS vierem. Preferir sempre variavel
    de ambiente a senha na linha de comando: o que voce digita no shell fica no
    historico e aparece pra quem roda `ps`.
    """
    es_cfg = {
        'host': args.es_host, 'port': args.es_port, 'scheme': args.es_scheme,
        'use_ssl': bool(args.es_ssl), 'verify_certs': not bool(args.es_no_verify)
    }
    if args.es_user and args.es_pass:
        es_cfg['username'] = args.es_user; es_cfg['password'] = args.es_pass
    feeds = load_feeds_file(args.feeds_file)
    return RSSToELK(es_cfg, feeds, index_alias=args.index)

def main():
    # Despacho simples: cada subcomando chama os metodos na ordem certa.
    # Repare que `collect` nao conecta no ES — da pra coletar com o ES
    # desligado e enviar depois com `send`.
    args = build_parser().parse_args()
    proc = make_proc(args)
    if args.cmd == "collect":
        proc.collect_feeds(args.output_dir, days=args.days)
    elif args.cmd == "send":
        if not proc.connect_to_elasticsearch(): raise SystemExit(1)
        proc.send_to_elasticsearch(args.input)
    elif args.cmd == "collect-send":
        proc.collect_feeds(args.output_dir, days=args.days)
        if not proc.connect_to_elasticsearch(): raise SystemExit(1)
        proc.send_to_elasticsearch(args.output_dir)
    elif args.cmd == "setup":
        if not proc.connect_to_elasticsearch(): raise SystemExit(1)
        proc.ensure_ilm_and_template()

if __name__ == "__main__":
    # Dependencias: pip install feedparser requests 'elasticsearch>=8,<9' pyyaml
    # (o `<9` nao e capricho — veja a nota de versoes no README do projeto)
    main()
