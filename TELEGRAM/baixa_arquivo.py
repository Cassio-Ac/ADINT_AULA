#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Baixa um anexo protegido por senha. A senha esta no TEXTO da mensagem.

Exemplo: https://t.me/crackcodes/7264
   anexo ... PAKISTANIROUTERBYNIGHTKID.rar  (307 KB)
   senha ... no corpo, marcada como SPOILER (aparece BORRADA no app)

>>> ESTE SCRIPT NAO ABRE, NAO EXTRAI E NAO DESCOMPACTA O ARQUIVO. <<<
Arquivo de canal de crime pode conter malware. Abrir e decisao de quem abre,
em maquina isolada, por conta e risco. O script entrega o arquivo e a senha.

Rode DEPOIS do baixa_arquivo_aberto.py: aquele abre, este nao.

    python3 baixa_arquivo.py
"""
import json
import os

from dotenv import load_dotenv
from telethon.sync import TelegramClient
from telethon.tl.types import MessageEntitySpoiler, MessageEntityCode

CAMPOS_FILE = ('id', 'name', 'ext', 'mime_type', 'size', 'width', 'height',
               'duration', 'title', 'performer', 'emoji', 'sticker_set')


def salva_file(m, saida):
    """Despeja m.file num JSON: a visao unificada, e de onde ela vem."""
    f = m.file
    d = {'m_file': {p: getattr(f, p, None) for p in CAMPOS_FILE},
         'de_onde_vem_o_name': [str(a) for a in m.document.attributes],
         'document_cru': m.document.to_dict()}
    with open(saida, 'w', encoding='utf-8') as fp:
        json.dump(d, fp, ensure_ascii=False, indent=2, default=str)
    cheios = sum(1 for v in d['m_file'].values() if v is not None)
    print('   m.file -> %s  (%d de %d propriedades preenchidas)'
          % (saida, cheios, len(CAMPOS_FILE)))

CANAL, MSG = 'crackcodes', 7264
TETO = 50 * 1024 * 1024
DESTINO = os.path.expanduser(os.environ.get('ADINT_DOWNLOADS', '~/adint_downloads'))   # fora do repo e do OneDrive

load_dotenv()
cliente = TelegramClient(os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint')),
                         int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()
m = cliente.get_messages(CANAL, ids=MSG)

print('=' * 72)
print('1. O ANEXO — metadado, antes de baixar')
print('=' * 72)
print('   nome .... %s' % m.file.name)
print('   bytes ... %d  (%.0f KB)' % (m.file.size, m.file.size / 1024.0))
print('   mime .... %s' % m.file.mime_type)
salva_file(m, 'file_%s_%d.json' % (CANAL, MSG))

print()
print('=' * 72)
print('2. A SENHA — esta no texto, marcada como SPOILER')
print('=' * 72)
senha = None
for e, trecho in m.get_entities_text():
    if isinstance(e, (MessageEntitySpoiler, MessageEntityCode)):
        senha = trecho.strip()
print('   senha ... %s' % senha)
print('   (no app aparece BORRADA; pela API vem em texto puro)')

print()
print('=' * 72)
print('3. O PORTAO — tamanho conferido ANTES do download')
print('=' * 72)
if m.file.size > TETO:
    print('   acima do teto de %d MB — nao baixa.' % (TETO // 1048576))
    cliente.disconnect()
    raise SystemExit(0)
print('   %.0f KB <= %d MB: pode baixar.' % (m.file.size / 1024.0, TETO // 1048576))

os.makedirs(DESTINO, exist_ok=True)
caminho = m.download_media(file=os.path.join(DESTINO, m.file.name))
cliente.disconnect()
print('   baixado em %s' % caminho)
print('   %d bytes no disco' % os.path.getsize(caminho))

print()
print('=' * 72)
print('4. E PARAMOS AQUI')
print('=' * 72)
print('   arquivo: %s' % caminho)
print('   senha .: %s' % senha)
print()
print('   O script NAO abriu o .rar. Arquivo de canal de crime pode conter')
print('   malware — quem abrir, abre em maquina isolada e por sua conta.')
print('   Coletar e abrir sao decisoes SEPARADAS: colete muito, abra pouco.')
