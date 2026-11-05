#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COLETOR TELEGRAM -> ELASTICSEARCH  (o script final do modulo)

Junta tudo que o bloco ensinou:
  - sessao em ~/.adint/telegram/ (nao polui a pasta do projeto)
  - _id = chat_id:msg_id          -> rodar duas vezes NAO duplica
  - texto = m.message             -> cru, sem marcacao
  - urls  = das ENTITIES          -> o link mascarado que o texto nao tem
  - anexo: nome/bytes/mime        -> sem baixar um byte
  - remetente: os 4 casos reais   -> canal, admin anonimo, pessoa, conta morta
  - mapeamento EXPLICITO          -> urls e keyword, anexo_bytes e long

    python3 coletor_cve_leak.py
"""
import os
import re

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from telethon.sync import TelegramClient

CANAIS = [('CVEDetector', 'telegram_cve'), ('breachdetect', 'telegram_leak')]
LIMITE = int(os.environ.get('TG_LIMIT', '100'))
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)

MAPA = {'mappings': {'properties': {
    'canal':       {'type': 'keyword'},
    'chat_id':     {'type': 'long'},
    'msg_id':      {'type': 'long'},
    'data':        {'type': 'date'},
    'remetente':   {'type': 'keyword'},
    'texto':       {'type': 'text'},
    'urls':        {'type': 'keyword'},      # keyword: para agregar por dominio
    'cve_ids':     {'type': 'keyword'},
    'anexo_nome':  {'type': 'keyword'},
    'anexo_bytes': {'type': 'long'},         # long: 1,4 GB nao cabe em integer
    'anexo_mime':  {'type': 'keyword'},
    'views':       {'type': 'long'},
}}}


def quem_mandou(m):
    """Os 4 casos. A ordem importa: post_author ANTES de get_chat()."""
    if m.from_id is None:
        if m.post_author:
            return '%s (admin anonimo)' % m.post_author
        return getattr(m.chat, 'title', None) or '(canal)'
    r = m.sender
    if r is None:
        return '(conta removida)'
    return (' '.join(filter(None, [r.first_name, r.last_name]))
            or r.username or '(sem nome)')


def documento(m, canal, indice):
    f = m.file
    texto = m.message or ''
    return {'_index': indice, '_id': '%s:%s' % (m.chat_id, m.id), '_source': {
        'canal': canal,
        'chat_id': m.chat_id,
        'msg_id': m.id,
        'data': m.date.isoformat(),
        'editada_em': m.edit_date.isoformat() if m.edit_date else None,
        'remetente': quem_mandou(m),
        'texto': texto,
        # TextUrl (mascarado) tem .url; Url cru NAO tem — nele a URL e o texto.
        # Pegar so os que tem .url perde todo link nao mascarado.
        'urls': [(e.url if getattr(e, 'url', None) else trecho)
                 for e, trecho in m.get_entities_text()
                 if type(e).__name__ in ('MessageEntityUrl', 'MessageEntityTextUrl')],
        'cve_ids': sorted({x.upper() for x in CVE_RE.findall(texto)}),
        'anexo_nome': getattr(f, 'name', None),
        'anexo_bytes': getattr(f, 'size', None),
        'anexo_mime': getattr(f, 'mime_type', None),
        'views': m.views,
        'album_id': m.grouped_id,
    }}


load_dotenv()
es = Elasticsearch([os.environ.get('ES_URL', 'http://localhost:9200')],
                   request_timeout=30)
if not es.ping():
    raise SystemExit('Elasticsearch fora do ar')

cliente = TelegramClient(os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint')),
                         int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()
if not cliente.is_user_authorized():
    raise SystemExit('sessao invalida — rode criar_sessao.py')
print('conta: %s' % cliente.get_me().first_name)

for canal, indice in CANAIS:
    if not es.indices.exists(index=indice):
        es.indices.create(index=indice, **MAPA)
        print('indice %s criado com mapeamento explicito' % indice)

    docs = [documento(m, canal, indice)
            for m in cliente.iter_messages(canal, limit=LIMITE)]
    ok, erros = helpers.bulk(es, docs, raise_on_error=False, stats_only=True)

    com_url = sum(1 for d in docs if d['_source']['urls'])
    com_cve = sum(1 for d in docs if d['_source']['cve_ids'])
    com_anexo = sum(1 for d in docs if d['_source']['anexo_nome'])
    print('%-14s coletadas=%-4d indexadas=%-4d rejeitadas=%-3d '
          'com_url=%-4d com_cve=%-4d com_anexo=%d'
          % (canal, len(docs), ok, erros, com_url, com_cve, com_anexo))

cliente.disconnect()
print('')
print('rode de novo: o _id e chat_id:msg_id, entao nada duplica.')
