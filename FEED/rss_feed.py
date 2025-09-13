#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RSS -> Elasticsearch (ILM + alias + bulk) | CLI (argparse, não interativo)

Exemplos de uso:
  # Coletar usando feeds externos e salvar JSONs
  python rss_elk.py collect --feeds-file feeds.yaml --output-dir rss_feeds

  # Enviar os JSONs (busca recursiva) para o ES
  python rss_elk.py send --feeds-file feeds.yaml --input rss_feeds --es-host localhost --es-port 9200

  # Coletar e enviar numa rodada só, filtrando últimos 7 dias
  python rss_elk.py collect-send --feeds-file feeds.yaml --output-dir rss_feeds --days 7 --es-host localhost --es-port 9200

  # Preparar ES (ILM + template + índice inicial com alias)
  python rss_elk.py setup --es-host localhost --es-port 9200
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
    HAS_YAML = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("rss-elk")

# -------------------- Loader de feeds externos (YAML/JSON) --------------------
def load_feeds_file(path: str) -> Dict[str, Dict[str, str]]:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        if not HAS_YAML:
            raise RuntimeError("PyYAML não instalado. `pip install pyyaml`")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

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
    def __init__(self, es_config: Optional[dict] = None, feeds_by_category: Optional[dict] = None, index_alias: str = "rss-feeds"):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RSS-ELK/1.1"})
        self.es_config = es_config or {'host': 'localhost', 'port': 9200, 'scheme': 'http', 'use_ssl': False, 'verify_certs': True}
        self.es: Optional[Elasticsearch] = None
        self.feeds_by_category = feeds_by_category or {}
        self.index_alias = index_alias

    # --------- ES ---------
    def connect_to_elasticsearch(self) -> bool:
        """Compatível com elasticsearch-py 8/9 (sync)."""
        try:
            params = {
                'hosts': [f"{self.es_config['scheme']}://{self.es_config['host']}:{self.es_config['port']}"],
                'request_timeout': 30,  # v9 prefere request_timeout
                'retry_on_timeout': True,
                'max_retries': 3
            }
            # v9: basic_auth; v8 ainda aceita http_auth
            if self.es_config.get('username') and self.es_config.get('password_env'):
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
        """Cria/atualiza ILM, template e índice inicial com alias de escrita."""
        if not self.es:
            raise RuntimeError("ES não conectado")

        # ILM
        try:
            self.es.ilm.put_lifecycle(policy="rss-feeds-ilm", body={
                "policy": {"phases": {
                    "hot": {"actions": {"rollover": {"max_age": "30d", "max_size": "20gb"}}},
                    "delete": {"min_age": "180d", "actions": {"delete": {}}}
                }}
            })
        except Exception as e:
            log.warning(f"ILM: {e}")

        # Template
        try:
            self.es.indices.put_index_template(name="rss-feeds-template", body={
                "index_patterns": [f"{self.index_alias}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1, "number_of_replicas": 1,
                        "index.refresh_interval": "1s",
                        "index.lifecycle.name": "rss-feeds-ilm",
                        "index.lifecycle.rollover_alias": self.index_alias
                    },
                    "mappings": {"properties": {
                        "@timestamp": {"type": "date"},
                        "feed_name": {"type":"keyword"},
                        "feed_title": {"type":"text"},
                        "feed_description": {"type":"text"},
                        "feed_link": {"type":"keyword"},
                        "feed_updated": {"type":"date"},
                        "entry_id": {"type":"keyword"},
                        "title": {"type":"text", "fields":{"raw":{"type":"keyword","ignore_above":256}}},
                        "link": {"type":"keyword"},
                        "published": {"type":"date"},
                        "summary": {"type":"text"},
                        "author": {"type":"keyword"},
                        "tags": {"type":"keyword","ignore_above":256},
                        "content_hash": {"type":"keyword"},
                        "category": {"type":"keyword"},
                        "source_type": {"type":"keyword"}
                    }}
                }
            })
            log.info("🧩 template criado/atualizado")
        except Exception as e:
            log.warning(f"template: {e}")

        # Índice inicial + alias
        try:
            if not self.es.indices.exists_alias(name=self.index_alias):
                self.es.indices.create(index=f"{self.index_alias}-000001",
                                       aliases={self.index_alias: {"is_write_index": True}},
                                       ignore=400)
        except Exception as e:
            log.warning(f"índice inicial/alias: {e}")

    # --------- Coleta ---------
    def fetch_feed(self, url: str):
        last_err = None
        for attempt in range(3):
            try:
                r = self.session.get(url, timeout=20)
                r.raise_for_status()
                feed = feedparser.parse(r.content)
                if getattr(feed, 'bozo', False):
                    log.warning(f"bozo em {url}: {getattr(feed, 'bozo_exception', None)}")
                return feed
            except Exception as e:
                last_err = e
                sleep_s = 2*(attempt+1)
                log.warning(f"tentativa {attempt+1}/3 falhou {url}: {e} (retry {sleep_s}s)")
                time.sleep(sleep_s)
        log.error(f"erro em {url}: {last_err}")
        return None

    @staticmethod
    def _safe_name(name: str) -> str:
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

    def save_feed_to_json(self, feed, feed_name: str, filename: str, min_datetime: Optional[datetime]) -> int:
        """Salva feed em JSON. Se min_datetime for definido, filtra entradas anteriores."""
        try:
            entries = []
            for entry in getattr(feed, "entries", []):
                # published ISO
                pub_parsed = entry.get("published_parsed")
                published_iso = (datetime(*pub_parsed[:6], tzinfo=timezone.utc).isoformat() if pub_parsed else "")
                # filtro temporal
                if min_datetime and published_iso:
                    try:
                        ts = datetime.fromisoformat(published_iso.replace("Z", "+00:00"))
                        if ts < min_datetime:
                            continue
                    except Exception:
                        pass

                hsrc = f"{entry.get('title','')}{entry.get('link','')}{entry.get('published','')}"
                content_hash = hashlib.md5(hsrc.encode("utf-8")).hexdigest()
                tags = [t.term for t in getattr(entry, "tags", []) if hasattr(t, "term")]
                entries.append({
                    "title": entry.get("title",""),
                    "link": entry.get("link",""),
                    "published": published_iso,
                    "summary": entry.get("summary", entry.get("description","")),
                    "author": entry.get("author",""),
                    "tags": tags,
                    "content_hash": content_hash
                })

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
        for category, feeds in self.feeds_by_category.items():
            if feed_name in feeds:
                return category
        return "Unknown"

    def send_to_elasticsearch(self, src: str) -> None:
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

            actions = []
            for e in data.get("entries", []):
                ts = e.get("published") or datetime.now(timezone.utc).isoformat()
                srcdoc = {
                    "@timestamp": ts, "feed_name": feed_name,
                    "feed_title": feed_info.get("title",""),
                    "feed_description": feed_info.get("description",""),
                    "feed_link": feed_info.get("link",""),
                    "feed_updated": feed_info.get("updated",""),
                    "entry_id": e.get("entry_id",""),
                    "title": e.get("title",""), "link": e.get("link",""),
                    "published": e.get("published",""), "summary": e.get("summary",""),
                    "author": e.get("author",""), "tags": e.get("tags",[]),
                    "content_hash": e.get("content_hash",""),
                    "category": category, "source_type": "rss_feed"
                }
                doc_id = e.get("content_hash") or hashlib.md5(f"{srcdoc['title']}{srcdoc['link']}{srcdoc['published']}".encode("utf-8")).hexdigest()
                actions.append({"_index": self.index_alias, "_id": doc_id, "_op_type": "create", "_source": srcdoc})

            if actions:
                helpers.bulk(self.es, actions, raise_on_error=False)
                total += len(actions)
        log.info(f"🎉 concluído: {total} documentos enviados")

# ------------------------------- CLI --------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Coleta RSS e envia para Elasticsearch (ILM + alias) — CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

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
    es_cfg = {
        'host': args.es_host, 'port': args.es_port, 'scheme': args.es_scheme,
        'use_ssl': bool(args.es_ssl), 'verify_certs': not bool(args.es_no_verify)
    }
    if args.es_user and args.es_pass_env:
        es_cfg['username'] = args.es_user; es_cfg['password_env'] = args.es_pass_env
    feeds = load_feeds_file(args.feeds_file)
    return RSSToELK(es_cfg, feeds, index_alias=args.index)

def main():
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
    # pip install feedparser requests elasticsearch pyyaml
    main()
