#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Usa a sessao que o criar_sessao.py gerou.
Sem telefone, sem codigo, sem senha: o .session ja carrega a autorizacao.
"""
import os

from dotenv import load_dotenv
from telethon.sync import TelegramClient

load_dotenv()
SESSAO = os.path.expanduser('~/.adint/telegram/' + os.environ.get('TELEGRAM_SESSION', 'sessao_adint'))

# api_id/api_hash: o construtor EXIGE, mas a autorizacao esta na auth_key do
# .session — medido: com valores falsos a conexao funciona igual. Quem autentica
# e o ARQUIVO, nao as credenciais do app.
cliente = TelegramClient(SESSAO, int(os.environ['TELEGRAM_API_ID']),
                         os.environ['TELEGRAM_API_HASH'])
cliente.connect()                       # connect(), nao start(): start() PERGUNTA

assert cliente.is_user_authorized(), 'sessao invalida — rode criar_sessao.py'

print('autenticado como:', cliente.get_me().first_name)
print('titulo do canal:', cliente.get_entity('breachdetect').title)

cliente.disconnect()
