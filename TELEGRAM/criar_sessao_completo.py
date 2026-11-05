#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CRIAR SESSAO TELEGRAM — passo 1 do modulo Telegram (versao 2026)
=================================================================
Faz o primeiro login e grava um arquivo <nome>.session. A partir dai os
coletores autenticam sem pedir codigo de novo. Roda uma vez por conta.

O QUE MUDOU EM 2026, E POR QUE (cada item e um bug real da versao anterior):

  1. A senha de 2FA era lida com input(), que ECOA NA TELA. Numa aula projetada
     ou gravada, isso publica a senha permanente da conta. O codigo de 5 digitos
     expira; a senha 2FA nao. Agora os dois usam getpass() — nao aparece nada.

  2. API_ID era convertido com int() em escopo de MODULO. Com a variavel vazia
     (que e o padrao do .env.example) o script morria com ValueError cru antes
     de chegar na mensagem amigavel. Agora valida-se o texto ANTES de converter.

  3. O telefone inteiro e o api_id eram impressos. Telefone e o identificador de
     login da conta — e pivot para SIM-swap e para desanonimizar o coletor.
     Agora sai mascarado.

  4. O .session nascia no diretorio corrente, que pode ser um repo git ou uma
     pasta sincronizada. Agora o caminho e FORCADO para ~/.adint/telegram/ e o
     script RECUSA gravar dentro de repo git, OneDrive/Dropbox ou /mnt/c.
     Observado na pratica: chmod 600 NAO funciona em /mnt/c (DrvFs ignora);
     no ext4 do WSL funciona. Por isso o destino e o home do WSL.

  5. 2FA era detectado procurando a palavra "password" na MENSAGEM do erro.
     Funciona por sorte e quebra quando o texto muda. Agora e
     except SessionPasswordNeededError — que e o nome que se pesquisa quando da erro.

  6. Nao havia tratamento de FloodWait, ApiIdInvalid, PhoneNumberBanned etc.
     Cada um virava traceback. Agora cada um tem uma linha dizendo o que fazer.

CONFIG — do .env na raiz do projeto, ou de variavel de ambiente:
  TELEGRAM_API_ID    = 12345678
  TELEGRAM_API_HASH  = 32 caracteres hexadecimais
  TELEGRAM_PHONE     = +5561999999999
  TELEGRAM_SESSION   = nome_da_sessao        (sem o sufixo .session)

Uso:
  /opt/adint-venv/bin/python3 criar_sessao.py
  /opt/adint-venv/bin/python3 criar_sessao.py --conferir    (so checa, nao loga)
"""
import argparse
import os
import re
import sys
from getpass import getpass
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# telethon.sync (e NAO "from telethon import") porque este script e SINCRONO:
# ele para e espera voce digitar o codigo. O .sync embrulha cada metodo para
# rodar o event loop por baixo, e e o que permite chamar sem await.
#
# Se voce trocar por "from telethon import TelegramClient", TODA chamada passa a
# devolver uma coroutine — e o pior nao e o crash: e que uma coroutine e TRUTHY,
# entao "if cliente.is_user_authorized():" entra no ramo do SIM sem ter verificado
# nada. Erro silencioso antes do erro barulhento.
from telethon.sync import TelegramClient
from telethon.errors import (
    ApiIdInvalidError,
    FloodWaitError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberBannedError,
    PhoneNumberInvalidError,
    SessionPasswordNeededError,
)

# onde a sessao PODE nascer: ext4 do WSL, onde chmod realmente vale
PASTA_PADRAO = Path.home() / '.adint' / 'telegram'

PROIBIDOS = ('onedrive', 'dropbox', 'google drive', 'icloud', '/mnt/c', '/mnt/d')


def mascara_tel(t):
    t = (t or '').strip()
    if len(t) < 6:
        return '(invalido)'
    return t[:3] + '*' * (len(t) - 5) + t[-2:]


def le_config():
    """Le e VALIDA antes de converter. Devolve (api_id, api_hash, phone, sessao)."""
    erros = []

    bruto = os.environ.get('TELEGRAM_API_ID', '').strip()
    if not bruto:
        erros.append('TELEGRAM_API_ID esta vazio')
    elif not bruto.isdigit():
        erros.append('TELEGRAM_API_ID deve ser so numero (ex.: 1234567); '
                     'valor atual tem %d caractere(s) nao numerico(s)'
                     % sum(1 for c in bruto if not c.isdigit()))
    api_id = int(bruto) if bruto.isdigit() else None

    api_hash = os.environ.get('TELEGRAM_API_HASH', '').strip()
    if not api_hash:
        erros.append('TELEGRAM_API_HASH esta vazio')
    elif not re.fullmatch(r'[0-9a-fA-F]{32}', api_hash):
        erros.append('TELEGRAM_API_HASH deve ter 32 caracteres hexadecimais '
                     '(o atual tem %d)' % len(api_hash))

    phone = os.environ.get('TELEGRAM_PHONE', '').strip().replace(' ', '')
    if not phone:
        erros.append('TELEGRAM_PHONE esta vazio')
    elif not re.fullmatch(r'\+\d{10,15}', phone):
        erros.append('TELEGRAM_PHONE deve vir em formato internacional, '
                     'comecando com + (ex.: +5561999999999)')

    sessao = os.environ.get('TELEGRAM_SESSION', '').strip() or 'sessao_adint'
    if '/' in sessao or '\\' in sessao:
        erros.append('TELEGRAM_SESSION deve ser so o NOME, sem caminho — '
                     'o diretorio e escolhido pelo script')
    return api_id, api_hash, phone, sessao, erros


def dentro_de_git(p: Path):
    """Sobe a arvore procurando .git — controle EXECUTADO, nao aviso em docstring."""
    for pai in [p] + list(p.parents):
        if (pai / '.git').exists():
            return pai
    return None


def resolve_caminho(nome):
    PASTA_PADRAO.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(PASTA_PADRAO, 0o700)
    except Exception:
        pass
    destino = PASTA_PADRAO / nome

    baixo = str(destino).lower()
    for ruim in PROIBIDOS:
        if ruim in baixo:
            print('[X] RECUSADO: o caminho da sessao contem "%s".' % ruim)
            print('    Sessao e credencial: nao pode nascer em pasta sincronizada')
            print('    nem em /mnt/c (onde chmod 600 e silenciosamente ignorado).')
            sys.exit(2)

    repo = dentro_de_git(PASTA_PADRAO)
    if repo:
        print('[X] RECUSADO: %s esta dentro do repo git %s' % (PASTA_PADRAO, repo))
        sys.exit(2)
    return destino


def protege(caminho: Path):
    """chmod 600 e CONFERE se pegou — em DrvFs nao pega, e e melhor saber."""
    arq = Path(str(caminho) + '.session')
    if not arq.exists():
        return
    try:
        os.chmod(arq, 0o600)
    except Exception as e:
        print('    aviso: chmod falhou (%s)' % type(e).__name__)
        return
    modo = arq.stat().st_mode & 0o777
    if modo == 0o600:
        print('    permissao ... 0600 (conferido)')
    else:
        print('    AVISO: pedi 0600 mas o arquivo esta %04o — o filesystem ignorou.' % modo)


def main():
    ap = argparse.ArgumentParser(description='Cria a sessao do Telegram.')
    ap.add_argument('--conferir', action='store_true',
                    help='so verifica config e sessao existente; nao faz login')
    args = ap.parse_args()

    print('=' * 64)
    print('CRIAR SESSAO TELEGRAM')
    print('=' * 64)

    api_id, api_hash, phone, nome, erros = le_config()
    if erros:
        print('[X] configuracao incompleta:')
        for e in erros:
            print('    - %s' % e)
        print('')
        print('    Crie o app em https://my.telegram.org/apps')
        print('    App title / Short name: use algo como adintaula2026')
        print('    (5-32 caracteres, so letras e numeros — acento ou espaco')
        print('     fazem o site devolver erro generico sem dizer qual campo)')
        sys.exit(1)

    destino = resolve_caminho(nome)
    print('  telefone .... %s' % mascara_tel(phone))
    print('  api_id ...... definido (%d digitos)' % len(str(api_id)))
    print('  api_hash .... definido (32 hex)')
    print('  sessao ...... %s.session' % destino)
    print('=' * 64)

    cliente = TelegramClient(str(destino), api_id, api_hash)
    try:
        cliente.connect()

        if cliente.is_user_authorized():
            eu = cliente.get_me()
            print('')
            print('[v] JA AUTORIZADO como %s (id %s).' % (eu.first_name, eu.id))
            print('    O arquivo .session existe e vale. Nada a fazer.')
            protege(destino)
            return

        if args.conferir:
            print('')
            print('[!] Nao ha sessao valida. Rode sem --conferir para criar.')
            return

        print('')
        print('[>] Enviando codigo para %s ...' % mascara_tel(phone))
        cliente.send_code_request(phone)

        # getpass: o codigo NAO aparece na tela nem na gravacao
        codigo = getpass('[?] Codigo recebido no Telegram (nao sera exibido): ').strip()

        try:
            cliente.sign_in(phone, codigo)
        except SessionPasswordNeededError:
            # a conta tem verificacao em duas etapas
            senha = getpass('[?] Senha da nuvem / 2FA (nao sera exibida): ')
            cliente.sign_in(password=senha)

        eu = cliente.get_me()
        print('')
        print('[v] SESSAO CRIADA. Usuario: %s (id %s)' % (eu.first_name, eu.id))
        print('    arquivo ..... %s.session' % destino)
        protege(destino)
        print('')
        print('    Este arquivo AUTENTICA COMO VOCE, sem senha e sem codigo.')
        print('    Nao commite, nao suba em nuvem, nao mande por chat.')

    except ApiIdInvalidError:
        print('[X] api_id e api_hash nao combinam. Confira o par em my.telegram.org/apps.')
        sys.exit(2)
    except PhoneNumberInvalidError:
        print('[X] Numero invalido. Use formato internacional: +5561999999999')
        sys.exit(2)
    except PhoneNumberBannedError:
        print('[X] Este numero esta banido no Telegram. Nao adianta repetir.')
        sys.exit(2)
    except PhoneCodeInvalidError:
        print('[X] Codigo errado. Rode de novo e digite com atencao.')
        sys.exit(2)
    except PhoneCodeExpiredError:
        print('[X] Codigo expirou. Rode de novo para receber outro.')
        sys.exit(2)
    except PasswordHashInvalidError:
        print('[X] Senha de 2FA incorreta.')
        sys.exit(2)
    except FloodWaitError as e:
        print('[X] O Telegram exigiu espera de %ds (~%d min).'
              % (e.seconds, e.seconds // 60))
        print('    Isso NAO e bug. Pedir codigo varias vezes seguidas causa isso.')
        print('    Espere o tempo todo antes de tentar de novo — repetir so piora.')
        sys.exit(3)
    finally:
        try:
            cliente.disconnect()
        except Exception:
            pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('')
        print('[!] cancelado pelo usuario')
        sys.exit(1)
