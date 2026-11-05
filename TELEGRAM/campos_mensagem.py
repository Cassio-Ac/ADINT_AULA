#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Os campos de UMA mensagem do Telegram: na tela em 5 familias, e TODOS num JSON.

    python3 campos_mensagem.py                      # @breachdetect
    python3 campos_mensagem.py TelegramTips         # canal com anexo
    python3 campos_mensagem.py TelegramTips --mostrar   # despeja o JSON na tela

O JSON sai com tres camadas:
    cru_tl        -> m.to_dict(): a estrutura TL inteira, com os campos vazios
    propriedades  -> o acucar do Telethon (text, chat_id, sender_id, ...)
    entities      -> ja recortadas com get_entities_text()
"""
import datetime
import json
import os
import sys

from dotenv import load_dotenv
from telethon.sync import TelegramClient

load_dotenv()
SESSAO = os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint'))
ARGS = [a for a in sys.argv[1:] if not a.startswith('--')]
CANAL = ARGS[0] if ARGS else 'breachdetect'
MOSTRAR = '--mostrar' in sys.argv

cliente = TelegramClient(SESSAO, int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()

m = cliente.get_messages(CANAL, limit=1)[0]     # a mensagem do topo
print('canal:', CANAL, '| mensagem', m.id)

print()
print('--- 1. IDENTIDADE: quem e onde ---')
print('m.id .......... ', m.id, '  <- unico NESTE chat, nao global')
print('m.chat_id ..... ', m.chat_id, '  <- canal leva o prefixo -100')
print('m.sender_id ... ', m.sender_id, '  <- negativo=canal, positivo=pessoa')
print('m.from_id ..... ', m.from_id, '  <- None em canal: quem assina e o canal')
print('m.post_author . ', m.post_author, '  <- preenchido se for admin anonimo')

print()
print('--- 2. TEMPO: quando ---')
print('m.date ........ ', m.date, ' tz=', m.date.tzinfo, ' <- SEMPRE UTC')
print('m.edit_date ... ', m.edit_date, '  <- None se nunca editou')

print()
print('--- 3. CONTEUDO: o que diz ---')
print('len(m.message)  ', len(m.message or ''), '  <- cru, e o que se indexa')
print('len(m.text) ... ', len(m.text or ''), '  <- com markdown remontado')
print('message==text?  ', m.message == m.text)
print('entities (a formatacao, que tambem e DADO):')
for e, trecho in m.get_entities_text():          # nao fatie na mao: offsets UTF-16
    tipo = type(e).__name__.replace('MessageEntity', '')
    print('   %-12s %-30r %s' % (tipo, trecho[:28], getattr(e, 'url', '') or ''))

print()
print('--- 4. ANEXO: veio arquivo? (sem baixar um byte) ---')
f = m.file
print('m.media ....... ', type(m.media).__name__ if m.media else None)
print('nome .......... ', getattr(f, 'name', None))
print('bytes ......... ', getattr(f, 'size', None))
print('mime .......... ', getattr(f, 'mime_type', None))

print()
print('--- 5. ALCANCE: quanta gente viu ---')
print('m.views ....... ', m.views)
print('m.forwards .... ', m.forwards)


# ------------------------------------------------------------------ o JSON
def serializa(o):
    """datetime vira texto; bytes viram um rotulo (nao cabem em JSON)."""
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return '<%d bytes>' % len(o)
    return str(o)


PROPS = ['text', 'raw_text', 'chat_id', 'sender_id', 'is_reply', 'is_channel',
         'is_group', 'is_private', 'reply_to_msg_id', 'button_count']

dados = {
    'canal': CANAL,
    'cru_tl': m.to_dict(),
    'propriedades': {p: getattr(m, p, None) for p in PROPS},
    'arquivo': None if f is None else {
        'name': f.name, 'size': f.size, 'mime_type': f.mime_type, 'ext': f.ext},
    'entities': [
        {'tipo': type(e).__name__.replace('MessageEntity', ''),
         'offset': e.offset, 'length': e.length,
         'trecho': trecho, 'url': getattr(e, 'url', None)}
        for e, trecho in m.get_entities_text()
    ],
}

saida = 'campos_%s_%s.json' % (CANAL.lstrip('@'), m.id)
with open(saida, 'w', encoding='utf-8') as fp:
    json.dump(dados, fp, ensure_ascii=False, indent=2, default=serializa)

texto = json.dumps(dados, ensure_ascii=False, indent=2, default=serializa)
print()
print('--- JSON COM TODOS OS CAMPOS ---')
print('campos TL crus .. ', len(dados['cru_tl']))
print('preenchidos ..... ', sum(1 for v in dados['cru_tl'].values() if v is not None))
print('vazios (None) ... ', sum(1 for v in dados['cru_tl'].values() if v is None))
print('entities ........ ', len(dados['entities']))
print('linhas do JSON .. ', texto.count('\n') + 1)
print('arquivo ......... ', os.path.abspath(saida))

if MOSTRAR:
    print()
    print(texto)

cliente.disconnect()
