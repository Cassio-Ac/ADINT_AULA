#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
m.message x m.text, e o que acontece na busca.

Use junto com o print de https://t.me/s/CrazyHuntersTeam/15

    python3 url_escondida.py
"""
import json
import os
import urllib.request
import urllib.error

from dotenv import load_dotenv
from telethon.sync import TelegramClient

CANAL, MSG = 'CrazyHuntersTeam', 15
ONION = '7i6sfmfvmqfaabjksckwrttu3nsbopl3xev2vbxbkghsivs5lqp4yeqd.onion'
ES, IDX = 'http://localhost:9200', 'telegram_exemplo'


def es(metodo, caminho, corpo=None):
    d = json.dumps(corpo).encode() if corpo is not None else None
    req = urllib.request.Request(ES + caminho, data=d, method=metodo,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())


load_dotenv()
cliente = TelegramClient(os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint')),
                         int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()
m = cliente.get_messages(CANAL, ids=MSG)
cliente.parse_mode = 'markdown'
texto = cliente.get_messages(CANAL, ids=MSG).text
cliente.disconnect()

print('=' * 78)
print('m.message          (%d caracteres)' % len(m.message))
print('=' * 78)
print(m.message)

print()
print('=' * 78)
print('m.text             (%d caracteres)' % len(texto))
print('=' * 78)
print(texto)

# ------------------------------------------------------------------ a busca
es('DELETE', '/' + IDX)
es('PUT', '/' + IDX, {'mappings': {'properties': {
    'origem': {'type': 'keyword'}, 'texto': {'type': 'text'}}}})
es('PUT', '/%s/_doc/1?refresh=true' % IDX, {'origem': 'm.message', 'texto': m.message})
es('PUT', '/%s/_doc/2?refresh=true' % IDX, {'origem': 'm.text', 'texto': texto})

r = es('POST', '/%s/_search' % IDX,
       {'query': {'match_phrase': {'texto': ONION}}, '_source': ['origem']})
achou = sorted(h['_source']['origem'] for h in r['hits']['hits'])

print()
print('=' * 78)
print('BUSCA NO ELASTIC POR  %s' % ONION[:40])
print('=' * 78)
for campo in ('m.message', 'm.text'):
    print('   indexando %-12s -> %s' % (campo, 'ACHOU' if campo in achou else 'NAO ACHOU'))
