#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMBO -> ELASTICSEARCH: credencial vazada vira POLITICA DE SENHA.

Le o arquivo do baixa_arquivo_aberto.py e indexa com os campos que o SOC
consome para montar a Custom Banned Password List do Entra ID.

POR QUE A SENHA VAI EM CLARO
----------------------------
Guardar so o hash responde "a senha X vazou?" — mas exige que voce ja saiba
qual X perguntar. Threat intel nao advinha: precisa VER as senhas para achar
o padrao. Se os funcionarios vazam "Empresa@2024", "Empresa@2025", o produto
nao e a senha — e o termo-base "empresa", que vai para a lista de bloqueio.
Entra ID casa termo-base com fuzzy e leetspeak, entao e isso que ele quer.

O controle aqui nao e fingir que nao temos o dado. E QUEM alcanca o indice.
Este indice nao vai para producao compartilhada e nao se projeta em tela.

    python3 manda_combo_elastic.py
"""
import hashlib
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers
from telethon.sync import TelegramClient

CANAL, MSG = 'COMBOWORKON', 258
PASTA = os.path.expanduser(os.environ.get('ADINT_DOWNLOADS', '~/adint_downloads'))   # fora do repo e do OneDrive
ARQ = os.path.join(PASTA, 'Good emails 2501 Brazile 1600 .txt')
IDX = 'telegram_combo_br'
FONTE = '%s/%d' % (CANAL, MSG)

# canarios FICTICIOS: .example e reservado (RFC 2606), nao existe aluno real
CANARIOS = ['aluno.a@adint.example:adint@123456',
            'aluno.b@adint.example:Adint@2026',
            'aluno.c@adint.example:adint123']
FONTE_CANARIO = 'ADINT-FICTICIO'

MAPA = {'mappings': {'properties': {
    'email':        {'type': 'keyword'},
    'dominio':      {'type': 'keyword'},
    'senha':        {'type': 'keyword'},   # em claro: e o insumo da analise
    'senha_sha256': {'type': 'keyword'},   # para cruzar com outras fontes
    'senha_len':    {'type': 'integer'},
    'senha_base':   {'type': 'keyword'},   # <- o que vai para o Entra ID
    'sufixo_num':   {'type': 'keyword'},   # ano/sequencia no fim
    'tem_maiuscula': {'type': 'boolean'},
    'tem_numero':   {'type': 'boolean'},
    'tem_simbolo':  {'type': 'boolean'},
    'fonte':        {'type': 'keyword'},
    'coletado_em':  {'type': 'date'},
}}}

RX = re.compile(r'^([^\s:]+)@([^\s:]+):(.*)$')
RX_BASE = re.compile(r'[A-Za-zÀ-ÿ]{3,}')
RX_SUF = re.compile(r'(\d{1,6})\W*$')
agora = datetime.now(timezone.utc).isoformat()


def decompoe(senha):
    """Separa o que a politica de senha precisa saber."""
    letras = RX_BASE.findall(senha)
    base = max(letras, key=len).lower() if letras else None
    suf = RX_SUF.search(senha)
    return {
        'senha': senha,
        'senha_sha256': hashlib.sha256(senha.encode()).hexdigest(),
        'senha_len': len(senha),
        'senha_base': base,
        'sufixo_num': suf.group(1) if suf else None,
        'tem_maiuscula': any(c.isupper() for c in senha),
        'tem_numero': any(c.isdigit() for c in senha),
        'tem_simbolo': any(not c.isalnum() for c in senha),
    }


# ------------------------------------------------- 1) baixa, se nao tiver
load_dotenv()
if os.path.exists(ARQ):
    print('ja no disco: %s (%d bytes)' % (os.path.basename(ARQ), os.path.getsize(ARQ)))
else:
    print('baixando de https://t.me/%s/%d ...' % (CANAL, MSG))
    cli = TelegramClient(os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint')),
                         int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
    cli.connect()
    if not cli.is_user_authorized():
        raise SystemExit('sessao invalida — rode criar_sessao.py')
    m = cli.get_messages(CANAL, ids=MSG)
    os.makedirs(PASTA, exist_ok=True)
    ARQ = m.download_media(file=ARQ)
    cli.disconnect()
    print('baixado: %s (%d bytes)' % (os.path.basename(ARQ), os.path.getsize(ARQ)))

# ------------------------------------------------- 2) parseia
docs, ruins = [], 0
for linha in CANARIOS + list(open(ARQ, encoding='utf-8-sig', errors='replace')):
    linha = linha.strip()
    if not linha:
        continue
    g = RX.match(linha)
    if not g:
        ruins += 1
        continue
    user, dom, senha = g.groups()
    src = {'email': '%s@%s' % (user.lower(), dom.lower()),
           'dominio': dom.lower(),
           'fonte': FONTE_CANARIO if linha in CANARIOS else FONTE,
           'coletado_em': agora}
    src.update(decompoe(senha))
    docs.append({'_index': IDX,
                 '_id': hashlib.sha1(linha.encode()).hexdigest(),
                 '_source': src})

es = Elasticsearch([os.environ.get('ES_URL', 'http://localhost:9200')],
                   request_timeout=30)
if not es.ping():
    raise SystemExit('Elasticsearch fora do ar')
if not es.indices.exists(index=IDX):
    es.indices.create(index=IDX, **MAPA)
    print('indice %s criado' % IDX)
ok, erros = helpers.bulk(es, docs, raise_on_error=False, stats_only=True)
es.indices.refresh(index=IDX)
print('indexadas=%d  descartadas=%d  rejeitadas=%d' % (ok, ruins, erros))

A = lambda **kw: es.search(index=IDX, size=0, **kw)['aggregations']

print('')
print('=== 1. O PRODUTO: termos-base para a banned list do Entra ID ===')
for b in A(aggs={'b': {'terms': {'field': 'senha_base', 'size': 12}}})['b']['buckets']:
    print('   %-20s %4d contas' % (b['key'], b['doc_count']))

print('')
print('=== 2. sufixo numerico (ano? sequencia?) ===')
for b in A(aggs={'s': {'terms': {'field': 'sufixo_num', 'size': 8}}})['s']['buckets']:
    print('   %-10s %4d' % (b['key'], b['doc_count']))

print('')
print('=== 3. composicao: a politica atual seguraria essas senhas? ===')
tot = es.count(index=IDX)['count']
for campo in ('tem_maiuscula', 'tem_numero', 'tem_simbolo'):
    n = es.count(index=IDX, query={'term': {campo: True}})['count']
    print('   %-16s %5d de %d  (%4.1f%%)' % (campo, n, tot, 100.0 * n / tot))
for b in A(aggs={'l': {'terms': {'field': 'senha_len', 'size': 6,
                                 'order': {'_count': 'desc'}}}})['l']['buckets']:
    print('   %d caracteres .... %d contas' % (b['key'], b['doc_count']))

print('')
print('=== 4. as senhas mais reusadas (o ranking que o SOC pede) ===')
for b in A(aggs={'p': {'terms': {'field': 'senha', 'size': 8}}})['p']['buckets']:
    print('   %-22s %4d contas' % (b['key'], b['doc_count']))

print('')
print('=== 5. o aluno A vazou? com qual senha? ===')
r = es.search(index=IDX, query={'term': {'email': 'aluno.a@adint.example'}},
              source=['email', 'senha', 'senha_base', 'fonte'])
for h in r['hits']['hits']:
    s = h['_source']
    print('   %s -> senha=%r  base=%r  (%s)'
          % (s['email'], s['senha'], s['senha_base'], s['fonte']))

print('')
print('=== 6. quem mais usa o termo-base "adint"? ===')
r = es.search(index=IDX, query={'term': {'senha_base': 'adint'}}, size=10,
              source=['email', 'senha'])
print('   %d conta(s):' % r['hits']['total']['value'])
for h in r['hits']['hits']:
    print('      %-26s %s' % (h['_source']['email'], h['_source']['senha']))
print('   -> banir o TERMO "adint" pega as tres variacoes de uma vez.')
