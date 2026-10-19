#!/usr/bin/env python3
"""
CRIAR SESSAO TELEGRAM  (passo 2 do modulo Telegram)
===================================================

O QUE FAZ
  Faz o PRIMEIRO LOGIN na sua conta do Telegram e grava o resultado num arquivo
  `.session`. Esse arquivo e o que permite aos coletores do curso
  (coletor_cve_leak.py e companhia) ler canais sem pedir codigo toda vez.
  Roda uma vez por conta; depois disso o script so confirma que a sessao vale.

FLUXO COMPLETO QUE A AULA ENSINA
  1. CRIAR O APP — acesse  https://my.telegram.org/apps  e faca login com o
     numero da conta. Preencha o formulario ("App title" e "Short name"
     quaisquer; plataforma "Other" serve). Salve.
  2. OBTER AS CREDENCIAIS — a mesma pagina mostra, uma unica vez de forma
     comoda, o `api_id` (numero) e o `api_hash` (32 caracteres hex). Guarde no
     `.env`, NUNCA no codigo. Esse par identifica o APLICATIVO, nao a conta:
     quem pega so o api_id/api_hash ainda precisaria do seu numero e do codigo.
  3. PRIMEIRO LOGIN (este script) — o Telegram envia um CODIGO DE 5 DIGITOS.
     Importante: o codigo chega como mensagem DENTRO do proprio Telegram (chat
     "Telegram", oficial), nao por SMS, se voce ja tiver o app instalado. Digite
     o codigo no prompt.
  4. 2FA, se a conta tiver — com verificacao em duas etapas ativada, depois do
     codigo o Telegram pede a SENHA da nuvem (a que voce cadastrou nas
     configuracoes do app, nao o codigo). O script detecta e pergunta.
  5. ARQUIVO DE SESSAO — ao final existe `<TELEGRAM_SESSION>.session`, um banco
     SQLite com a chave de autorizacao. A partir daqui nenhum coletor pede
     codigo de novo.

COMO RODAR  (da pasta do projeto, com o Python do venv)
  ./.venv/bin/python3 TELEGRAM/criar_sessao.py
  Nao tem flag: tudo vem do `.env`. E INTERATIVO (vai pedir o codigo no
  terminal), entao nao coloque no cron.

CONFIG LIDA DO .env  (NUNCA hardcode credencial)
  TELEGRAM_API_ID   = SEU_API_ID            # numero, de my.telegram.org/apps
  TELEGRAM_API_HASH = SEU_API_HASH          # 32 caracteres hex
  TELEGRAM_PHONE    = +55DDDXXXXXXXX        # formato internacional, com o +
  TELEGRAM_SESSION  = session_aula          # nome/caminho do arquivo .session

O QUE PRODUZ
  - `<TELEGRAM_SESSION>.session`  (ex.: session_aula.session), criado na pasta
    de onde voce RODOU o comando — se rodar da raiz do projeto, ele cai na
    raiz, nao em TELEGRAM/. Pode aparecer tambem um `.session-journal`
    temporario do SQLite.
  - Nada vai para o Elasticsearch neste passo.

O QUE PRECISA
  - Python 3.10+ e:  pip install telethon python-dotenv
  - uma conta de Telegram ja ativa, com acesso ao numero
  - app criado em my.telegram.org/apps e `.env` preenchido

# =========================================================================
# 🔴 O PONTO MAIS IMPORTANTE DESTE ARQUIVO
#    O `.session` E UMA CREDENCIAL. TRATE COMO SENHA — na verdade, pior.
# =========================================================================
  Quem tiver o seu arquivo `.session` AGE COMO A SUA CONTA: le suas conversas,
  manda mensagem no seu nome, entra e sai de grupos, ve seus contatos. E faz
  isso SEM SENHA e SEM SEGUNDO FATOR, porque a autorizacao ja esta concluida
  dentro do arquivo — o 2FA protege o LOGIN, e o login ja aconteceu. Copiar o
  arquivo para outra maquina basta.

  Regras, sem excecao:
    - NUNCA comite. Esta no `.gitignore` do projeto (`*.session`,
      `*.session-journal`, `*.session*`) e isso e PROPOSITAL: a regra existe
      para a credencial nao escapar num `git add .` distraido. Nao remova, nao
      force com `git add -f`.
    - NUNCA envie para ninguem — nem pro professor, nem pro colega, nem em
      canal de suporte, nem anexado em "me ajuda a debugar".
    - NUNCA deixe em pasta sincronizada (Drive, OneDrive, Dropbox, iCloud) nem
      em backup automatico para nuvem de terceiro.
    - Nao projete o arquivo nem o conteudo do `.env` em tela compartilhada.
    - Permissao restrita:  chmod 600 session_aula.session
    - Vazou, ou voce suspeita que vazou? Encerre a sessao pelo app oficial:
      Configuracoes > Dispositivos > Encerrar todas as outras sessoes. Isso
      invalida o arquivo. Depois apague o `.session` e rode este script de novo.
    - Terminou o exercicio? Apague o arquivo. Credencial que nao existe nao
      vaza.

⚠️ OPSEC — COMO FAZER ESSE TIPO DE COLETA
  - USE UM NUMERO DESCARTAVEL, nao o seu numero pessoal. A coleta do modulo
    seguinte envolve entrar em canais de CVE e de vazamento; sua conta fica
    visivel como membro, com nome e foto, e seu numero pode estar exposto
    dependendo das suas configuracoes de privacidade. Antes de qualquer coleta,
    no app oficial: Privacidade > Numero de telefone > "Ninguem", e Foto/Ultimo
    acesso restritos.
  - USE UM AMBIENTE APARTADO: VM ou container dedicado a esta atividade, nao a
    maquina em que voce trabalha. Nada de misturar com a conta e os dados do
    dia a dia.
  - Uma conta por finalidade. Nao reaproveite a conta de coleta para nada
    pessoal, e nao reaproveite a pessoal para coleta.
  - Entrar em canal de vazamento tem risco e implicacao legal — leia os avisos
    de OPSEC no cabecalho de coletor_cve_leak.py ANTES de ir para o passo 3.
"""
import os
import sys

from telethon.sync import TelegramClient
from dotenv import load_dotenv

# Carrega o .env do DIRETORIO ATUAL. Se "falta config no .env" aparecer com o
# .env preenchido, voce rodou de outra pasta — e o mesmo motivo faz o
# .session ser gravado onde voce nao esperava.
load_dotenv()

# Credenciais e nome da sessao vem SO do ambiente. Nenhum valor real neste
# arquivo: codigo vai pro Git, credencial nao.
API_ID = int(os.environ.get("TELEGRAM_API_ID", "0"))   # numero do app
API_HASH = os.environ.get("TELEGRAM_API_HASH", "")     # hash do app (32 hex)
PHONE = os.environ.get("TELEGRAM_PHONE", "")           # +55DDDXXXXXXXX
# Nome base do arquivo de sessao; o Telethon acrescenta ".session".
SESSION = os.environ.get("TELEGRAM_SESSION", "session_aula")


def main():
    print("=" * 60)
    print("🔑 CRIAR SESSAO TELEGRAM")
    print("=" * 60)
    # Falha cedo e com mensagem clara: sem as tres variaveis nao da pra tentar.
    if not API_ID or not API_HASH or not PHONE:
        print("❌ Falta config no .env: TELEGRAM_API_ID / API_HASH / PHONE")
        print("   (crie o app em https://my.telegram.org/apps)")
        sys.exit(1)

    # Eco so do que NAO e segredo: telefone, api_id e nome do arquivo. O
    # api_hash NUNCA e impresso — terminal vira print, log e gravacao de aula.
    print(f"📱 Telefone: {PHONE}")
    print(f"🆔 API ID:   {API_ID}")
    print(f"📁 Sessao:   {SESSION}.session")
    print("=" * 60)

    # O primeiro argumento e o NOME DA SESSAO: o Telethon abre (ou cria)
    # "<SESSION>.session" ali. `connect()` apenas abre o socket; nao autentica.
    client = TelegramClient(SESSION, API_ID, API_HASH)
    client.connect()

    # Sessao reaproveitavel: se o arquivo ja existe e ainda vale, nao ha nada a
    # fazer — e por isso que os coletores nao pedem codigo. Repare no que isso
    # significa para a seguranca: o arquivo, sozinho, autentica.
    if client.is_user_authorized():
        me = client.get_me()
        print(f"\n✅ Ja autorizado como {me.first_name} (id {me.id}).")
        print("   Nada a fazer — o arquivo .session ja existe e vale.")
        client.disconnect()
        return

    # Passo 3 do fluxo: pede o codigo. Ele chega no chat oficial "Telegram"
    # dentro do app (ou por SMS, se voce nao tiver sessao ativa em lugar
    # nenhum). Codigo tem validade curta — se demorar, rode de novo.
    print(f"\n📲 Enviando codigo de verificacao para {PHONE}...")
    client.send_code_request(PHONE)
    # `input` nao mascara o que voce digita. Nao faca este passo com a tela
    # compartilhada ou gravando: o codigo aparece na tela.
    codigo = input("🔐 Digite o codigo recebido no Telegram: ").strip()

    try:
        client.sign_in(PHONE, codigo)
    except Exception as e:
        # Passo 4: conta com verificacao em 2 etapas (2FA) pede senha.
        # O Telethon levanta SessionPasswordNeededError, cuja mensagem contem
        # "password" — e o que este teste detecta. Qualquer outro erro (codigo
        # invalido, codigo expirado, numero errado) e relancado de proposito,
        # para voce LER o erro em vez de o script insistir no escuro.
        # Atencao: a senha pedida aqui e a senha da NUVEM (2FA), nao o codigo.
        if "password" in str(e).lower() or "2fa" in str(e).lower():
            senha = input("🔒 Conta tem 2FA. Digite a senha: ").strip()
            client.sign_in(password=senha)
        else:
            raise

    # Passo 5: a sessao esta gravada. O arquivo abaixo e, de agora em diante,
    # uma CREDENCIAL ATIVA da conta — leia o bloco 🔴 no cabecalho.
    # Sugestao de higiene imediata:  chmod 600 <arquivo>.session
    me = client.get_me()
    print(f"\n✅ Sessao criada! Usuario: {me.first_name} (id {me.id})")
    print(f"📁 Arquivo gerado: {SESSION}.session")
    print("⚠️  NAO compartilhe esse arquivo — ele autentica como voce.")
    client.disconnect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl+C no meio do login: sai limpo. Se um arquivo .session incompleto
        # tiver sido criado, apague antes de tentar de novo.
        print("\n⚠️ cancelado")
        sys.exit(1)
