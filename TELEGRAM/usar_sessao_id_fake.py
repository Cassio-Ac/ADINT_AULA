#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEMONSTRACAO: o api_id e o api_hash abaixo sao FALSOS. Um "1" e 32 zeros.
E mesmo assim este script entra na conta.

Por que funciona
----------------
O .session e um SQLite. A tabela `sessions` guarda dc_id, server_address, port
e uma auth_key de 256 bytes. NAO guarda api_id nem api_hash — medido.
A autorizacao inteira esta na auth_key.

O construtor do Telethon exige os tres argumentos, mas so confere PRESENCA:
    TelegramClient(S)              -> TypeError: missing 2 required arguments
    TelegramClient(S, None, None)  -> ValueError: cannot be empty or None
    TelegramClient(S, 0, '')       -> ValueError: cannot be empty or None
    TelegramClient(S, 1, '0'*32)   -> funciona, autorizado=True
Checagem de presenca feita pela BIBLIOTECA; nao de autenticidade pelo Telegram.

A conclusao que importa
-----------------------
Voce protege o api_hash: ele esta no .env, o .env esta no .gitignore.
Mas quem rouba o .session nao precisa dele. Poe 1 e 32 zeros e entra.
O arquivo de 28 KB E a credencial. Esta guardando a chave certa?

NAO use este arquivo como modelo: aqui as credenciais falsas sao o PONTO.
Em codigo de verdade use usar_sessao.py, que le as reais do .env — assim,
se a sessao morrer, voce recebe ApiIdInvalidError em vez de um erro confuso.
"""
import os

from telethon.sync import TelegramClient

SESSAO = os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint'))

cliente = TelegramClient(SESSAO, 1, '0' * 32)      # <-- FALSOS, de proposito
cliente.connect()

assert cliente.is_user_authorized(), 'sessao invalida — rode criar_sessao.py'

print('autenticado como:', cliente.get_me().first_name)
print('titulo do canal:', cliente.get_entity('breachdetect').title)

cliente.disconnect()
