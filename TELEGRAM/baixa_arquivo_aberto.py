#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Um POST, varios ARQUIVOS: o album.

    https://t.me/COMBOWORKON/258
No app voce ve UM post com seis .txt. A API devolve SEIS mensagens,
costuradas pelo mesmo m.grouped_id. Escolhemos uma e baixamos.

Nenhuma credencial e impressa: usuario e senha saem mascarados.
"""
import json
import os
import re
from collections import Counter

from dotenv import load_dotenv
from telethon.sync import TelegramClient

CANAL, MSG = 'COMBOWORKON', 258
DESTINO = os.path.expanduser(os.environ.get('ADINT_DOWNLOADS', '~/adint_downloads'))   # fora do repo e do OneDrive
CAMPOS = ('id', 'name', 'ext', 'mime_type', 'size', 'width', 'height',
          'duration', 'title', 'performer', 'emoji', 'sticker_set')

load_dotenv()
cliente = TelegramClient(os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint')),
                         int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()

escolhida = cliente.get_messages(CANAL, ids=MSG)
vizinhas = cliente.get_messages(CANAL, ids=list(range(MSG - 6, MSG + 7)))
album = [x for x in vizinhas if x and x.grouped_id == escolhida.grouped_id]

print('grouped_id %s  ->  %d mensagens, %d arquivos, UM post no app'
      % (escolhida.grouped_id, len(album), sum(1 for x in album if x.document)))
print('')
print('%-6s %-38s %9s %7s %8s' % ('msg', 'arquivo', 'bytes', 'alegado', 'B/linha'))
print('-' * 74)
for x in album:
    nome = x.file.name
    n = re.search(r'(\d+)\s*\.txt$', nome)
    n = int(n.group(1)) if n else None
    marca = '  <-- escolhida' if x.id == MSG else ''
    print('%-6s %-38s %9d %7s %8s%s'
          % (x.id, nome[:37], x.file.size, n or '-',
             '%.1f' % (x.file.size / float(n)) if n else '-', marca))

# o m.file de TODAS, para comparar
dump = {'grouped_id': str(escolhida.grouped_id),
        'arquivos': [{p: getattr(x.file, p, None) for p in CAMPOS} for x in album]}
with open('album_%s_%d.json' % (CANAL, MSG), 'w', encoding='utf-8') as fp:
    json.dump(dump, fp, ensure_ascii=False, indent=2, default=str)
print('')
print('m.file de cada um -> album_%s_%d.json' % (CANAL, MSG))

os.makedirs(DESTINO, exist_ok=True)
caminho = escolhida.download_media(file=os.path.join(DESTINO, escolhida.file.name))
cliente.disconnect()

linhas = [l for l in open(caminho, encoding='utf-8-sig', errors='replace')
          .read().replace('\r\n', '\n').split('\n') if l.strip()]
alegado = int(re.search(r'(\d+)\s*\.txt$', escolhida.file.name).group(1))
print('')
print('baixei a %d: abriu sem senha, %d linhas -> o nome %s'
      % (MSG, len(linhas), 'CONFERE' if len(linhas) == alegado else 'MENTIU'))

print('')
print('--- formato (tudo mascarado) ---')
RX = re.compile(r'^([^\s:]+)@([^\s:]+):(.*)$')
provedores = Counter()
for i, l in enumerate(linhas):
    g = RX.match(l.strip())
    if not g:
        continue
    user, dom, senha = g.groups()
    provedores[dom.lower()] += 1
    if i < 3:
        print('   %s@%s:%s' % (user[:2] + '*' * (len(user) - 2), dom, '*' * len(senha)))

print('')
print('--- provedores (o dominio e o ACHADO, nao a vitima) ---')
for d, n in provedores.most_common(5):
    print('   %-22s %5d  (%4.1f%%)' % (d, n, 100.0 * n / len(linhas)))
