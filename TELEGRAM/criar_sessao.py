#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cria o arquivo .session do Telegram. Roda UMA vez por conta.

    export TELEGRAM_API_ID=12345678
    export TELEGRAM_API_HASH=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    export TELEGRAM_PHONE=+5561999999999
    python3 criar_sessao.py
"""
import os
from getpass import getpass

from dotenv import load_dotenv
from telethon.sync import TelegramClient              # .sync: script sem await
from telethon.errors import SessionPasswordNeededError

load_dotenv()                                         # le o .env da pasta atual

API_ID = int(os.environ['TELEGRAM_API_ID'])
API_HASH = os.environ['TELEGRAM_API_HASH']
PHONE = os.environ['TELEGRAM_PHONE']

# basename(): se alguem puser caminho no .env, fica so o nome
NOME = os.path.basename(os.environ.get('TELEGRAM_SESSION', 'sessao_adint'))

# fora de /mnt/c: la o chmod 600 e ignorado em silencio
SESSAO = os.path.expanduser('~/.adint/telegram/' + NOME)
os.makedirs(os.path.dirname(SESSAO), exist_ok=True)

cliente = TelegramClient(SESSAO, API_ID, API_HASH)
cliente.connect()                                     # connect(), nao start():
                                                      # start() PERGUNTA o telefone

if cliente.is_user_authorized():
    print('ja autorizado como', cliente.get_me().first_name)
else:
    cliente.send_code_request(PHONE)

    # getpass, nao input(): o que nao aparece na tela nao vaza na gravacao
    codigo = getpass('codigo recebido (nao aparece): ')
    try:
        cliente.sign_in(PHONE, codigo)
    except SessionPasswordNeededError:                # a conta tem 2FA
        cliente.sign_in(password=getpass('senha 2FA (nao aparece): '))

    print('sessao criada para', cliente.get_me().first_name)

os.chmod(SESSAO + '.session', 0o600)                  # so o dono le
print('arquivo:', SESSAO + '.session')
print('este arquivo autentica como voce. nao commite, nao suba em nuvem.')

cliente.disconnect()
