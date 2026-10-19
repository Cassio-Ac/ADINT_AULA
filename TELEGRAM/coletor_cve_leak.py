#!/usr/bin/env python3
"""
COLETOR DE CVE E LEAK (TELEGRAM) -> Elasticsearch   (passo 3 do modulo)
======================================================================

O QUE FAZ
  Le as ultimas mensagens de CANAIS PUBLICOS do Telegram voltados a threat
  intel — um que publica CVEs recem-divulgadas, outro que anuncia vazamentos —
  extrai os identificadores de CVE do texto e indexa tudo no Elasticsearch.
  Um canal = um indice (`telegram_cve`, `telegram_leak`), seguindo a regra
  "1 coletor = 1 indice" do curso.

O QUE ELE COLETA, E DE ONDE
  - DE ONDE: canais PUBLICOS, acessiveis a qualquer conta. Nada de grupo
    privado, nada de convite fechado — a lista esta em CANAIS, abaixo.
  - O QUE: metadados e TEXTO da mensagem (id, data, corpo, se tem midia) e os
    CVE-IDs encontrados. NAO baixa arquivo nenhum, de proposito (veja OPSEC).
  - PARA QUE: o campo `cve_ids` e a PONTE com o resto do pipeline. Cruzando-o
    com o que o Shodan/nuclei viu na superficie do alvo, voce sai de "existe
    uma falha no mundo" para "existe uma falha no MEU alvo e alguem ja esta
    falando dela" — e isso que vira o relatorio de exposicao.
  - CONTRAPONTO: o feed RSS (modulo FEED) diz que a FALHA EXISTE; o canal do
    Telegram diz que ALGUEM JA ESTA USANDO ou VENDENDO. Uma fonte sozinha
    conta meia historia.

POR QUE ESTES CANAIS
  As mensagens ja vem em JSON estruturado dentro do texto
    {Source, Title, Content, Detection Date, Type}
  entao da pra extrair o CVE ID por regex e usar o Type (exploit poc,
  ransomware, ...) como categoria, sem heuristica frageil.

COMO RODAR  (da pasta do projeto, com o Python do venv)
  ./.venv/bin/python3 TELEGRAM/coletor_cve_leak.py
  Nao tem flag: toda a configuracao vem do `.env` / variaveis de ambiente.
  Para uma rodada mais curta ou mais longa, use TG_LIMIT:
      TG_LIMIT=20  ./.venv/bin/python3 TELEGRAM/coletor_cve_leak.py
      TG_LIMIT=500 ./.venv/bin/python3 TELEGRAM/coletor_cve_leak.py

PRE-REQUISITOS
  - sessao criada (veja criar_sessao.py) e o `.session` acessivel da pasta
    onde voce roda o comando
  - Elasticsearch no ar
  - a conta precisa CONSEGUIR LER os canais; canal publico normalmente ja
    responde sem entrar, mas pode exigir que voce esteja inscrito
  - pip install telethon 'elasticsearch>=8,<9' python-dotenv

CONFIG (.env)
  TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_SESSION
  ES_URL   (default http://localhost:9200)
  TG_LIMIT (mensagens por canal; default 100)

O QUE PRODUZ
  Documentos nos indices `telegram_cve` e `telegram_leak`, com os campos
  canal, tipo, msg_id, data, texto, cve_ids, source, titulo, conteudo,
  detection_date, categoria e tem_midia. Nenhum arquivo em disco.
  Conferir:
    curl -s "http://localhost:9200/telegram_cve/_count"
    curl -s "http://localhost:9200/telegram_leak/_count"
    # quais CVEs apareceram:
    curl -s "http://localhost:9200/telegram_cve/_search?size=0" \
      -H 'Content-Type: application/json' \
      -d '{"aggs":{"cves":{"terms":{"field":"cve_ids","size":20}}}}'

# =========================================================================
# ⚠️ OPSEC E LEGAL — LEIA ANTES DE RODAR
# =========================================================================
  - ENTRAR EM CANAL DE VAZAMENTO TEM RISCO. Sua conta fica visivel como
    membro; muitos desses canais sao operados por criminosos e monitorados por
    terceiros. Use conta/numero descartavel e ambiente apartado (VM ou
    container dedicado), nunca a sua conta pessoal nem a maquina de trabalho —
    veja o bloco de OPSEC em criar_sessao.py.
  - NUNCA ABRA ARQUIVO BAIXADO NA MAQUINA PRINCIPAL. Anexo de canal desses e
    vetor de malware (instalador "crackeado", PDF, planilha com macro, ZIP com
    senha para furar antivirus). Se precisar analisar, faca em VM descartavel,
    sem rede e sem pasta compartilhada com o host. Este coletor nao baixa
    arquivo — ele so registra `tem_midia: true`, e isso e proposital.
  - DADO DE VAZAMENTO CONTEM DADO PESSOAL DE TERCEIROS. Tratar esse material
    e TRATAMENTO DE DADO PESSOAL com todas as consequencias da LGPD
    (Lei 13.709/2018): precisa de base legal, finalidade definida,
    minimizacao e seguranca. Dependendo do que se faz, ha risco criminal.
    Nao e exercicio sem consequencia — e por isso que a coleta aqui se limita
    a METADADO E TEXTO.
  - NAO BAIXE NEM REDISTRIBUA OS PACOTES DE DADOS. Repassar base vazada,
    inclusive "so para o grupo da turma", e disseminacao. O objetivo da aula e
    MEDIR exposicao (existe um vazamento mencionando o meu dominio?), nao
    colecionar o conteudo vazado.
  - Encontrou dado da sua propria organizacao? Isso e incidente: acione o
    processo interno de resposta. Nao saia confirmando credencial em sistema de
    producao.
  - Canal muda: o que hoje e "publico de CVE" pode virar outra coisa. Reavalie
    a lista antes de cada aula.
"""
import os
import re
import json

from telethon.sync import TelegramClient
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

# Carrega o .env do DIRETORIO ATUAL — rode sempre da mesma pasta onde esta o
# .env e o arquivo .session, senao o script "nao acha" a sessao.
load_dotenv()

# Credenciais so do ambiente. Nenhum valor real neste arquivo.
API_ID = int(os.environ.get("TELEGRAM_API_ID", "0"))
API_HASH = os.environ.get("TELEGRAM_API_HASH", "")
# Mesmo nome de sessao usado em criar_sessao.py — e o arquivo .session que
# autentica (CREDENCIAL: veja o cabecalho de criar_sessao.py).
SESSION = os.environ.get("TELEGRAM_SESSION", "session_aula")
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
# Quantas mensagens por canal. Comece baixo (TG_LIMIT=20) na primeira vez:
# limite alto na primeira rodada e o caminho mais curto pra tomar FloodWait.
LIMIT = int(os.environ.get("TG_LIMIT", "100"))

# Canais monitorados. 1 canal = 1 indice (mesma logica de "1 coletor = 1 indice").
#
# Formato de cada item:
#   username -> @usuario do canal PUBLICO (sem o @), ou use o id numerico no
#               formato -100XXXXXXXXXX se o canal nao tiver username
#   tipo     -> rotulo que vai pro campo `tipo` do documento
#   index    -> indice de destino no Elasticsearch
#
# Para acrescentar uma fonte, inclua um dicionario novo aqui. Antes disso:
# (1) confirme que o canal e PUBLICO, (2) releia o bloco de OPSEC no cabecalho,
# (3) comece com TG_LIMIT baixo. Canal morre e e renomeado como qualquer outra
# fonte — se `get_entity` falhar, e aqui que se corrige.
CANAIS = [
    {"username": "CVEDetector", "tipo": "cve", "index": "telegram_cve"},
    {"username": "breachdetect", "tipo": "leak", "index": "telegram_leak"},
]

# CVE-ANO-NUMERO (4 a 7 digitos). Usado pra extrair IDs do texto livre.
# O formato oficial e CVE-AAAA-N{4,}: 4 digitos ate 2014, mais que isso depois
# (por isso o {4,7}). `IGNORECASE` porque canal escreve "cve-2026-1234" tambem;
# a normalizacao para maiusculas acontece em coletar_canal().
# AJUSTE AQUI se precisar casar outros identificadores (GHSA, MS, KB...).
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_corpo(texto: str) -> dict:
    """As mensagens vem como JSON com ruido no fim (emoji + link t.me).
    Pega do primeiro '{' ao ultimo '}' e tenta parsear. Devolve {} se falhar.

    ---------------------------------------------------------------------
    O PARSING, EM DETALHE — E ONDE AJUSTAR SE O CANAL MUDAR DE FORMATO
    ---------------------------------------------------------------------
    A mensagem crua nao e JSON puro: e JSON COM ENFEITE em volta, mais ou
    menos assim (exemplo ilustrativo, nao copiado de canal real):

        🔴 Novo alerta
        {"Source": "...", "Title": "...", "Content": "...",
         "Detection Date": "2026-10-17", "Type": "exploit poc"}
        👉 Assine: https://t.me/...

    `json.loads` no texto inteiro falharia por causa do emoji e do link. A
    tatica aqui e recortar do PRIMEIRO "{" ao ULTIMO "}" e parsear so isso —
    simples, e aguenta mudanca no enfeite sem precisar de ajuste.

    Limites conhecidos desta abordagem (e sao limites aceitaveis, nao bugs):
      - se a mensagem tiver DOIS blocos JSON, o recorte do primeiro "{" ao
        ultimo "}" pega os dois juntos e o parse falha -> devolve {};
      - se o texto tiver "{" solto (ex.: um trecho de codigo), idem;
      - quando falha, devolve {} e o documento ainda e indexado: `texto` crua e
        `cve_ids` continuam preenchidos, so os campos estruturados (source,
        titulo, conteudo, detection_date, categoria) ficam None. Preferimos
        perder estrutura a perder a mensagem.

    SE O CANAL MUDAR DE FORMATO, mexa em dois lugares:
      1. AQUI, na extracao — se o canal parar de mandar JSON e passar a usar
         texto corrido ou Markdown, troque o recorte por regex/split proprio e
         devolva um dicionario com as MESMAS chaves;
      2. em coletar_canal(), no mapeamento `corpo.get("Source")` etc. — se as
         chaves do JSON mudarem de nome ("Type" -> "category", por exemplo),
         e la que se aponta pro nome novo.
    Como voce percebe a mudanca: a contagem de mensagens continua normal, mas
    `categoria`/`titulo` chegam todos nulos no ES. Diagnostico rapido:
      curl -s "http://localhost:9200/telegram_cve/_search?size=1&_source=texto,titulo,categoria"
    """
    if not texto:
        return {}
    i, j = texto.find("{"), texto.rfind("}")
    if i >= 0 and j > i:
        try:
            return json.loads(texto[i:j + 1])
        except Exception:
            # Falha de parse NAO descarta a mensagem — veja a docstring.
            return {}
    return {}


def coletar_canal(cli, canal) -> list:
    """Baixa as ultimas LIMIT mensagens do canal e monta os documentos do ES.

    RATE LIMIT / FloodWait — RESPEITE, NAO ACELERE
    ----------------------------------------------
    O Telegram impoe limite de uso na API. Quando voce pede demais, ele nao
    devolve erro generico: devolve um FLOOD_WAIT_X, que significa literalmente
    "espere X segundos". X pode ser 30, pode ser 300, pode ser horas.
    O Telethon trata isso automaticamente para esperas curtas: ele DORME o
    tempo pedido e continua, sozinho. Se o script parecer "travado" no meio de
    um canal, ele provavelmente esta cumprindo uma espera — e isso e o
    comportamento CORRETO. Deixe terminar.
    Esperas longas (acima do limiar interno do Telethon) viram excecao e
    interrompem a coleta; a solucao e esperar e rodar de novo depois, com
    TG_LIMIT menor.

    O QUE O ALUNO NAO DEVE FAZER:
      - NAO rode em loop apertado nem em paralelo com varias contas;
      - NAO reduza/remova espera, nem tente "driblar" o FloodWait;
      - NAO suba TG_LIMIT para milhares na primeira rodada;
      - NAO reexecute em sequencia por impaciencia (ver o proximo paragrafo: a
        reexecucao e segura para os DADOS, mas cada rodada gasta cota).
    Insistir nao acelera nada: aumenta o X, e o Telegram pode LIMITAR OU BANIR
    a conta. Numa coleta de ADINT, cota e recurso finito — gaste com intencao.
    Rodando de hora em hora com TG_LIMIT modesto voce acompanha o canal sem
    nunca encostar no limite, exatamente porque a indexacao e idempotente.
    """
    # get_entity resolve o @username para a entidade do canal. E aqui que da
    # erro se o canal foi renomeado, apagado, virou privado ou a conta nao tem
    # acesso. Essa chamada tambem consome cota: evite rodadas desnecessarias.
    ent = cli.get_entity(canal["username"])
    docs = []
    # iter_messages pagina sozinho, do mais recente para o mais antigo, e e ele
    # que cumpre as esperas de rate limit entre as paginas.
    for m in cli.iter_messages(ent, limit=LIMIT):
        texto = m.message or ""   # mensagem so com midia tem texto vazio
        corpo = parse_corpo(texto)
        # Regex no TEXTO CRU (nao no JSON extraido): assim pegamos CVE citada
        # no enfeite, na legenda ou em mensagem fora de formato. `set` elimina
        # repeticao na mesma mensagem; `.upper()` normaliza; `sorted` deixa a
        # lista estavel, o que ajuda a comparar documentos entre rodadas.
        cves = sorted({x.upper() for x in CVE_RE.findall(texto)})
        docs.append({
            "_index": canal["index"],
            # =================================================================
            # IDEMPOTENCIA POR msg_id — O CONCEITO CENTRAL DESTE SCRIPT
            # =================================================================
            # O _id do documento e o ID DA MENSAGEM no canal. Esse id e unico e
            # imutavel dentro do canal, entao:
            #   - a mesma mensagem sempre gera o MESMO _id;
            #   - reexecutar o coletor NAO duplica nada: o ES reconhece o _id e
            #     sobrescreve o documento no lugar, em vez de criar outro
            #     (helpers.bulk usa _op_type "index" por padrao);
            #   - cada rodada pega as ultimas LIMIT mensagens, que se sobrepoem
            #     as da rodada anterior — e exatamente essa sobreposicao que
            #     garante nao perder mensagem entre execucoes.
            # Sem isso, rodar de hora em hora encheria o indice de copias e
            # qualquer contagem ("quantas mencoes a esta CVE?") viraria mentira.
            # Como a operacao e sobrescrita, mensagem EDITADA no canal tem a
            # versao atualizada no indice — util aqui, mas perceba que o
            # historico da edicao nao fica guardado.
            # (Compare com FEED/rss_feed.py: la o _id e um HASH DO CONTEUDO,
            # porque feed RSS nao da id estavel. Mesma ideia, chave diferente.)
            "_id": str(m.id),          # idempotente: reexecutar NAO duplica
            "_source": {
                "canal": canal["username"],
                "tipo": canal["tipo"],
                "msg_id": m.id,                        # mesmo valor do _id
                "data": m.date.isoformat(),            # data de publicacao (UTC)
                "texto": texto,                        # texto cru, sempre preservado
                "cve_ids": cves,                       # <- ponte com o Shodan
                # -------- campos vindos do JSON da mensagem ------------------
                # Chegam None quando o parse falha (veja parse_corpo). Se TODOS
                # vierem None em TODAS as mensagens, o canal mudou de formato.
                # E AQUI que se ajusta o nome das chaves se o canal renomea-las.
                "source": corpo.get("Source"),
                "titulo": corpo.get("Title"),
                "conteudo": corpo.get("Content"),
                "detection_date": corpo.get("Detection Date"),
                "categoria": corpo.get("Type"),        # exploit poc, ransomware...
                # So REGISTRA que havia anexo — nao baixa. Decisao de OPSEC:
                # anexo de canal de vazamento e vetor de malware. Veja o
                # cabecalho.
                "tem_midia": m.media is not None,
            },
        })
    return docs


def main():
    print("=" * 60)
    print(f"📡 COLETOR CVE/LEAK  | sessao={SESSION} | limite={LIMIT}/canal")
    print("=" * 60)

    # Checa o ES ANTES de gastar cota do Telegram: nao faz sentido coletar e
    # depois descobrir que nao ha onde gravar.
    es = Elasticsearch([ES_URL], request_timeout=30)
    if not es.ping():
        print(f"❌ Elasticsearch inacessivel em {ES_URL}")
        return

    # Reusa o arquivo .session criado no passo 2. Nenhum codigo e pedido aqui —
    # e justamente por isso que o arquivo e uma credencial.
    cli = TelegramClient(SESSION, API_ID, API_HASH)
    cli.connect()
    if not cli.is_user_authorized():
        # Sessao ausente/expirada (ou voce rodou de outra pasta e o .session
        # nao foi encontrado — ele e procurado no diretorio atual).
        print("❌ Sessao nao autorizada — rode criar_sessao.py primeiro.")
        cli.disconnect()
        return
    # Confirmacao de QUAL conta esta coletando. Confira: coleta em canal de
    # vazamento tem de sair da conta descartavel, nunca da pessoal.
    me = cli.get_me()
    print(f"✅ Conta: {me.first_name} (id {me.id})")

    total_msgs = total_cve_msgs = total_cve_ids = 0
    for canal in CANAIS:
        print(f"\n📥 {canal['username']}  ({canal['tipo']})")
        docs = coletar_canal(cli, canal)
        com_cve = [d for d in docs if d["_source"]["cve_ids"]]
        # Bulk: um request com todas as mensagens do canal.
        # `raise_on_error=False` -> documento ruim nao aborta o lote;
        # `stats_only=True`      -> devolve (aceitos, rejeitados).
        # `indexadas` e a contagem de ACEITOS pelo ES, nao de enviados: numero
        # de relatorio tem de refletir o que realmente entrou no indice.
        # Como o _id e o msg_id e a operacao e sobrescrita, numa 2a rodada
        # `indexadas` continua alto SEM o indice crescer — confira com _count,
        # nao pelo log.
        ok, errs = helpers.bulk(es, docs, raise_on_error=False, stats_only=True)
        print(f"   coletadas={len(docs)}  indexadas={ok}  mensagens_com_CVE={len(com_cve)}")
        if errs:
            print(f"   ⚠️ {errs} rejeitadas")
        total_msgs += len(docs)
        total_cve_msgs += len(com_cve)
        # Soma de OCORRENCIAS de CVE (uma CVE citada em 3 mensagens conta 3).
        # Para contar CVEs DISTINTAS, use a agregacao `terms` sobre `cve_ids`
        # no ES — o exemplo de curl esta no cabecalho.
        total_cve_ids += sum(len(d["_source"]["cve_ids"]) for d in docs)

    # Sempre desconecta: deixar a sessao pendurada atrapalha a proxima rodada.
    cli.disconnect()
    print(f"\n{'=' * 60}")
    print(f"✅ FIM | mensagens={total_msgs} | com CVE={total_cve_msgs} | CVE IDs extraidos={total_cve_ids}")
    print(f"   indices: " + ", ".join(c["index"] for c in CANAIS))


if __name__ == "__main__":
    # Lembrete final: este script NAO baixa arquivo e NAO deve ser adaptado pra
    # isso. Metadado e texto bastam pra medir exposicao — e e onde o risco
    # tecnico e legal fica sob controle. Leia o cabecalho.
    main()
