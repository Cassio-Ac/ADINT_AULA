"""
Consulta WHOIS de qualquer domínio falando o protocolo "na mão": abre um socket
na porta 43 do servidor do registro, manda o nome do domínio, lê a resposta em
texto puro e extrai os campos úteis com regex, devolvendo tudo em JSON.

Uso:
    # um domínio, resultado impresso na tela
    python3 WHOIS/whois_universal.py -d exemplo.com.br

    # lista de domínios (um por linha), resultado em arquivo
    python3 WHOIS/whois_universal.py -l dominios.txt -o resultados.json

    # um domínio salvando direto em arquivo
    python3 WHOIS/whois_universal.py -d exemplo.com -o resultado.json

    # ver quais TLDs este script sabe consultar
    python3 WHOIS/whois_universal.py --list-tlds

Produz:
    JSON com uma lista de objetos, um por domínio consultado: os campos
    normalizados (titular, datas, nameservers, status...) mais "domain",
    "server" e "tld". Campo que o registro não devolveu vira null, e domínio
    que falhou vira um objeto com a chave "erro" em vez dos campos.
    Com -o, grava no arquivo indicado (caminho relativo à pasta onde você rodou
    o comando). Sem -o, imprime na tela depois das linhas de progresso.

Precisa:
    - Python 3.10+ e só a biblioteca padrão (socket, re, json, argparse)
    - saída de rede na porta 43/TCP. É a primeira coisa a checar quando tudo dá
      timeout: rede corporativa e Wi-Fi de hotel costumam bloquear a 43
    - nenhuma chave de API

Autorização:
    WHOIS é consulta a um registro público: o pacote vai para o servidor do
    registro, nunca para o alvo — o domínio consultado não fica sabendo. Mesmo
    assim, só levante dados de domínios que são seus ou que você tem
    autorização escrita para analisar, e trate o resultado como dado pessoal:
    o WHOIS de .br expõe razão social, CNPJ/CPF (campo ownerid, no formato
    00.000.000/0001-00) e e-mails de pessoas físicas. Não jogue essa saída em
    slide, repositório público ou grupo de mensagens.
"""

import socket
import re
import json
import argparse
import sys
from typing import List, Dict, Optional

# ---------------------------------------------------------------------------
# Mapeamento TLD -> servidor WHOIS.
#
# Não existe "o servidor WHOIS da internet": cada registro (registry) opera o
# seu e só responde pelos domínios que administra. Perguntar um ".com.br" para
# a Verisign devolve resposta vazia ou recusa — e não um erro claro. Daí a
# tabela: o script escolhe o servidor pelo último rótulo do domínio (ver
# obter_tld abaixo).
#
# PARA ACRESCENTAR UM TLD NOVO: basta mais uma linha 'tld': 'servidor' aqui. O
# endereço oficial sai de `whois -h whois.iana.org <tld>`, que é a fonte da
# verdade. Só isso já faz a consulta funcionar; o parsing cai no genérico.
# ---------------------------------------------------------------------------
WHOIS_SERVERS = {
    'br': 'whois.registro.br',
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'biz': 'whois.neulevel.biz',
    'us': 'whois.nic.us',
    'uk': 'whois.nic.uk',
    'de': 'whois.denic.de',
    'fr': 'whois.nic.fr',
    'it': 'whois.nic.it',
    'es': 'whois.nic.es',
    'ca': 'whois.cira.ca',
    'au': 'whois.auda.org.au',
    'jp': 'whois.jprs.jp',
    'cn': 'whois.cnnic.cn',
    'ru': 'whois.tcinet.ru',
    'mx': 'whois.mx',
    'ar': 'whois.nic.ar',
    'cl': 'whois.nic.cl',
    'co': 'whois.nic.co',
    'pe': 'kero.yachay.pe',
    'tv': 'whois.nic.tv',
    'me': 'whois.nic.me',
    'io': 'whois.nic.io',
    'ly': 'whois.nic.ly',
    'cc': 'whois.nic.cc'
}

def obter_tld(dominio: str) -> str:
    """
    Extrai o TLD do domínio: o último rótulo, depois do último ponto.

    Por que só o último rótulo: quem decide a QUAL servidor perguntar é o
    registro responsável, e ele é o do TLD. "exemplo.com.br" e "exemplo.br"
    são os dois do Registro.br, então 'br' já basta — é por isso que .com.br
    não precisa de entrada própria na tabela de servidores.

    Armadilha: isto NÃO é "descobrir o domínio registrável" (não é uma Public
    Suffix List). Para "exemplo.co.uk" devolve 'uk', que serve para escolher o
    servidor, mas não use esta função para decidir qual pedaço do nome é o
    domínio da empresa.
    """
    partes = dominio.lower().split('.')
    if len(partes) >= 2:
        # Para domínios como .com.br, considerar apenas o último nível
        return partes[-1]
    # Entrada sem ponto ("localhost", um TLD solto, lixo colado do slide) sai
    # como '' e vai cair no "servidor não encontrado" mais adiante.
    return ''

def obter_servidor_whois(dominio: str) -> Optional[str]:
    """
    Determina o servidor WHOIS apropriado para o domínio.

    Devolve None quando o TLD não está na tabela — e None aqui significa
    "não sei consultar", não "domínio inexistente".
    """
    tld = obter_tld(dominio)
    return WHOIS_SERVERS.get(tld)

def consulta_whois_universal(dominio: str) -> dict:
    """
    Faz a consulta WHOIS crua e devolve o texto da resposta, sem interpretar.

    WHOIS (RFC 3912) é o protocolo mais simples que você vai ver: TCP na porta
    43, você manda uma linha de texto e lê bytes até o servidor fechar a
    conexão. Não tem cabeçalho, não tem código de status, não tem tamanho
    declarado, não tem TLS. O fluxo é literalmente:

        1. CONECTAR     socket TCP em servidor:43
        2. MANDAR       o nome do domínio seguido de "\\r\\n" (o CRLF é
                        obrigatório; sem ele muitos servidores só ficam
                        esperando o resto da linha até estourar o timeout)
        3. LER          recv() em laço até devolver b"", que é como o sistema
                        avisa que o servidor fechou — é o fechamento da
                        conexão que marca o fim da resposta
        4. DECODIFICAR  os bytes para texto (ver o laço de encodings)

    Por que socket cru em vez de uma biblioteca WHOIS: é justamente o que a
    aula quer mostrar — que WHOIS é texto em cima de TCP e que toda a
    "inteligência" de um cliente WHOIS está no parsing, não no protocolo.
    """
    try:
        servidor = obter_servidor_whois(dominio)
        if not servidor:
            return {
                "domain": dominio,
                "erro": f"Servidor WHOIS não encontrado para TLD: {obter_tld(dominio)}"
            }

        # A porta 43 é fixada pelo RFC 3912. Consulta e resposta trafegam em
        # texto claro: quem está no caminho vê o que você perguntou.
        porta = 43
        # 30s é generoso de propósito: registros pequenos e o .br sob limite de
        # consultas demoram. É aqui que se mexe para um lote grande — mas
        # cuidado, o Registro.br limita consultas por IP e, passando do limite,
        # passa a responder erro em vez de dados.
        timeout = 30

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((servidor, porta))
            # A "requisição" inteira é o nome do domínio e o CRLF. Nada mais.
            s.sendall((dominio + "\r\n").encode())
            resposta = b""
            # Lê até o servidor encerrar. Armadilha: se ele NÃO fechar (limite
            # de consultas, firewall que engole o FIN), o recv() estoura o
            # timeout, o except do fim captura e tudo o que já havia chegado é
            # descartado — você recebe "erro", não resposta parcial.
            while True:
                dados = s.recv(4096)
                if not dados:
                    break
                resposta += dados

        # Tentar decodificar com diferentes encodings.
        # Cada registro responde no encoding que quer e nenhum declara qual é:
        # o .br manda ISO-8859-1 em razão social acentuada, gTLDs modernos
        # mandam UTF-8. Tenta na ordem e fica com o primeiro que não explodir.
        # Repare que 'latin1' aceita qualquer sequência de bytes, então o laço
        # nunca chega ao fim sem sucesso — o preço é que um UTF-8 lido como
        # latin1 vira acento trocado em vez de erro visível.
        texto = ""
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        for encoding in encodings:
            try:
                texto = resposta.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        # Devolve o texto BRUTO, sem parsear. Separar coleta de interpretação é
        # o que permite conferir a resposta original quando um campo não
        # aparece no JSON final.
        return {
            "domain": dominio,
            "text": texto,
            "server": servidor,
            "tld": obter_tld(dominio)
        }
    except Exception as e:
        # Qualquer falha (DNS do servidor WHOIS, conexão recusada, timeout)
        # volta como objeto com "erro" em vez de exceção: num lote de 200
        # domínios, um que falha não pode derrubar os outros 199.
        return {"domain": dominio, "erro": str(e)}

def parse_whois_br(texto: str) -> dict:
    """
    Parser do formato do Registro.br (.br).

    POR QUE EXISTE UM PARSER POR TLD: o RFC 3912 padroniza o protocolo, não o
    conteúdo. Cada registro inventa os próprios rótulos e a própria ordem. O
    .br usa estilo RPSL, minúsculo e enxuto ("owner:", "nserver:", "created:");
    os gTLDs usam o formato do ICANN ("Registrant Name:", "Name Server:",
    "Creation Date:"). É o mesmo dado com nome diferente — então regex por TLD,
    e não um parser único que tentaria adivinhar tudo.

    Campos que só existem no .br: "ownerid" (CNPJ/CPF do titular — dado
    pessoal), "saci" (status de publicação), "nsstat"/"nslastaa" (resultado da
    última checagem de DNS feita pelo registro) e "nic-hdl-br" (identificador
    de contato, que o próprio WHOIS aceita como consulta).
    """
    # Cada chave é o nome NORMALIZADO do campo (o mesmo nome em todos os
    # parsers) e o valor é a regex que acha o rótulo do .br. É essa
    # normalização que deixa o JSON comparável entre um .br e um .com.
    regexes = {
        "domain_name": r"domain:\s*(.+)",
        "registrant_name": r"owner:\s*([^\n]+)",
        "registrant_id": r"ownerid:\s*(.+)",
        "country": r"country:\s*(.+)",
        "owner_c": r"owner-c:\s*(.+)",
        "admin_c": r"admin-c:\s*(.+)",
        "tech_c": r"tech-c:\s*(.+)",
        "billing_c": r"billing-c:\s*(.+)",
        "name_server": r"nserver:\s*(.+)",
        "nsstat": r"nsstat:\s*(.+)",
        "nslastaa": r"nslastaa:\s*(.+)",
        "saci": r"saci:\s*(.+)",
        "creation_date": r"created:\s*(.+)",
        "updated_date": r"changed:\s*(.+)",
        "expiration_date": r"expires:\s*(.+)",
        "status": r"status:\s*(.+)",
        "nic_hdl_br": r"nic-hdl-br:\s*(.+)",
        "person": r"person:\s*([^\n]+)",
        "email": r"e-mail:\s*(.+)"
    }
    
    resultado = {}
    for campo, padrao in regexes.items():
        matches = re.findall(padrao, texto)
        # Campos que legitimamente aparecem várias vezes na resposta (vários
        # nameservers, vários contatos) viram LISTA; o resto guarda só a
        # primeira ocorrência. Se você acrescentar um campo repetível, inclua o
        # nome nesta lista também, senão perde todas as ocorrências menos uma.
        #
        # Armadilha: o ramo da lista não aplica .strip(), e a resposta WHOIS
        # vem com CRLF — então esses campos podem carregar um "\r" no fim do
        # valor dentro do JSON.
        if campo in ["name_server", "nsstat", "nslastaa", "email", "person", "nic_hdl_br"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None

    return resultado

def parse_whois_com(texto: str) -> dict:
    """
    Parser do formato ICANN, usado por .com e .net (os dois na Verisign).

    ARMADILHA IMPORTANTE: .com e .net são registros "thin". A Verisign guarda
    só o esqueleto — domínio, registrar, datas, nameservers e status — e NÃO os
    dados do titular. Então registrant_name, registrant_email e companhia vêm
    quase sempre null, e isso não significa "domínio sem dono": significa que o
    dado está no registrar. O caminho é ler o campo "registrar_whois" da
    resposta e consultar aquele outro servidor. Este script não dá esse segundo
    salto, o que é um bom exercício para o aluno.
    """
    regexes = {
        "domain_name": r"Domain Name:\s*(.+)",
        "registrar": r"Registrar:\s*(.+)",
        "registrar_whois": r"Registrar WHOIS Server:\s*(.+)",
        "registrar_url": r"Registrar URL:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "updated_date": r"Updated Date:\s*(.+)",
        "expiration_date": r"Registry Expiry Date:\s*(.+)",
        "registrant_name": r"Registrant Name:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_street": r"Registrant Street:\s*(.+)",
        "registrant_city": r"Registrant City:\s*(.+)",
        "registrant_state": r"Registrant State/Province:\s*(.+)",
        "registrant_postal": r"Registrant Postal Code:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "registrant_phone": r"Registrant Phone:\s*(.+)",
        "registrant_email": r"Registrant Email:\s*(.+)",
        "admin_name": r"Admin Name:\s*(.+)",
        "admin_org": r"Admin Organization:\s*(.+)",
        "admin_email": r"Admin Email:\s*(.+)",
        "tech_name": r"Tech Name:\s*(.+)",
        "tech_org": r"Tech Organization:\s*(.+)",
        "tech_email": r"Tech Email:\s*(.+)",
        "name_server": r"Name Server:\s*(.+)",
        "status": r"Domain Status:\s*(.+)"
    }
    
    resultado = {}
    for campo, padrao in regexes.items():
        # IGNORECASE aqui (e não no parser .br) porque os registrars não são
        # consistentes na capitalização do formato ICANN: aparece "Registrar
        # URL" e "Registrar Url" na mesma base.
        matches = re.findall(padrao, texto, re.IGNORECASE)
        if campo in ["name_server", "status"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None

    return resultado

def parse_whois_generico(texto: str) -> dict:
    """
    Parser de último recurso, para os TLDs que não têm parser próprio.

    A diferença de forma: aqui cada campo tem uma LISTA de regex em vez de uma.
    O parser tenta os rótulos mais comuns na ordem e para na primeira que
    casar. Cobre a maioria dos TLDs razoavelmente e nenhum perfeitamente.

    Resultado típico: campos vazios em TLDs de formato exótico (.de responde um
    bloco mínimo; .jp e .it usam rótulos próprios). Campo null AQUI quer dizer
    "o parser genérico não achou", não "o registro não tem o dado" — confira na
    resposta crua antes de concluir qualquer coisa.
    """
    # Padrões mais gerais que funcionam para a maioria dos TLDs.
    # A ordem dentro de cada lista é a ordem de preferência: o rótulo do padrão
    # ICANN primeiro, depois as variações. Ajustar a ordem muda qual valor
    # ganha quando a resposta traz os dois rótulos.
    regexes = {
        "domain_name": [r"Domain Name:\s*(.+)", r"domain:\s*(.+)", r"Domain:\s*(.+)"],
        "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"],
        "creation_date": [r"Creation Date:\s*(.+)", r"Created:\s*(.+)", r"created:\s*(.+)", r"Registration Date:\s*(.+)"],
        "updated_date": [r"Updated Date:\s*(.+)", r"Modified:\s*(.+)", r"changed:\s*(.+)", r"Last Updated:\s*(.+)"],
        "expiration_date": [r"Registry Expiry Date:\s*(.+)", r"Expiry Date:\s*(.+)", r"expires:\s*(.+)", r"Expiration Date:\s*(.+)"],
        "registrant_name": [r"Registrant Name:\s*(.+)", r"Registrant:\s*(.+)", r"owner:\s*(.+)"],
        "registrant_org": [r"Registrant Organization:\s*(.+)", r"Organisation:\s*(.+)"],
        "registrant_country": [r"Registrant Country:\s*(.+)", r"Country:\s*(.+)", r"country:\s*(.+)"],
        "name_server": [r"Name Server:\s*(.+)", r"nserver:\s*(.+)", r"Nameserver:\s*(.+)", r"NS:\s*(.+)"],
        "status": [r"Domain Status:\s*(.+)", r"Status:\s*(.+)", r"status:\s*(.+)"]
    }
    
    resultado = {}
    for campo, padroes in regexes.items():
        matches = []
        for padrao in padroes:
            matches = re.findall(padrao, texto, re.IGNORECASE)
            # Para na primeira regex que achou algo: as seguintes são
            # alternativas para o MESMO campo, não complementos.
            if matches:
                break

        if campo in ["name_server", "status"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None
    
    return resultado

def parse_whois_universal(data: dict) -> dict:
    """
    Escolhe o parser pelo TLD e devolve o registro normalizado.

    É AQUI QUE SE LIGA UM PARSER NOVO: acrescente um ramo no if/elif abaixo
    apontando o TLD para a sua função. Sem isso, o TLD novo continua
    funcionando pelo parser genérico — só colhe menos campos.

    Para escrever o parser: copie parse_whois_br, troque as regex pelos rótulos
    que aquele registro realmente usa (rode o script sem -o e leia a resposta
    crua primeiro) e mantenha os nomes normalizados dos campos.
    """
    if "erro" in data:
        return {"domain": data["domain"], "erro": data["erro"]}

    texto = data.get("text", "")
    tld = data.get("tld", "")
    dominio = data.get("domain", "")
    servidor = data.get("server", "")

    # Verificar se retornou erro do servidor WHOIS.
    # Detecção por texto porque o WHOIS não tem código de retorno: cada
    # registro escreve a própria frase para "não existe".
    #
    # Armadilha dupla, e as duas valem para a prova:
    #  - resposta VAZIA não é domínio inexistente: pode ser limite de consultas
    #    estourado, conexão cortada ou TLD que exige flag na consulta;
    #  - "not found" é procurado em TODA a resposta, não só no começo, então um
    #    rodapé legal ou comentário do registrar com essa expressão marca como
    #    inexistente um domínio que existe. É falso positivo conhecido.
    if "No match for" in texto or "No Data Found" in texto or "not found" in texto.lower():
        return {
            "domain": dominio,
            "erro": "Domínio não encontrado no registro",
            "server": servidor,
            "tld": tld
        }
    
    # Escolher parser baseado no TLD
    if tld == 'br':
        resultado = parse_whois_br(texto)
    elif tld in ['com', 'net']:
        resultado = parse_whois_com(texto)
    else:
        resultado = parse_whois_generico(texto)

    # Adicionar informações extras.
    # Guardar "server" e "tld" no resultado não é enfeite: quando um campo vem
    # null, é o que diz se o culpado foi o registro ou o parser.
    resultado["domain"] = dominio
    resultado["server"] = servidor
    resultado["tld"] = tld
    
    return resultado

def ler_dominios_arquivo(arquivo: str) -> List[str]:
    """
    Lê a lista de domínios de um arquivo (um por linha).

    Linhas em branco são descartadas, mas NÃO há tratamento de comentário: uma
    linha "# teste" é tratada como domínio e vira um registro com "erro" no
    JSON. Mantenha o arquivo só com domínios.
    """
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            dominios = [linha.strip() for linha in f if linha.strip()]
        return dominios
    except FileNotFoundError:
        print(f"Erro: Arquivo '{arquivo}' não encontrado.")
        sys.exit(1)
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        sys.exit(1)

def processar_dominios(dominios: List[str]) -> List[Dict]:
    """
    Consulta e parseia a lista de domínios, em sequência.

    Em série de propósito: paralelizar WHOIS esbarra em limite de consultas por
    IP (o Registro.br é rigoroso) e o castigo é bloqueio temporário, não
    lentidão. Se precisar de volume, acrescente uma pausa entre as consultas
    aqui — não threads.
    """
    resultados = []

    for i, dominio in enumerate(dominios, 1):
        # Atenção: o progresso vai para a saída padrão, a MESMA onde o JSON é
        # impresso quando não se usa -o. Redirecionar com "> arquivo.json"
        # nesse caso gera um arquivo que não é JSON válido — use -o.
        print(f"Processando {i}/{len(dominios)}: {dominio}")

        # Coleta e interpretação ficam em funções separadas de propósito: dá
        # para testar o parser com um texto salvo, sem rede.
        raw_data = consulta_whois_universal(dominio)
        resultado = parse_whois_universal(raw_data)
        resultados.append(resultado)

    return resultados

def salvar_json(dados: List[Dict], arquivo: str):
    """
    Salva os dados em formato JSON.

    ensure_ascii=False mantém o acento legível no arquivo em vez de virar
    \\u00e7 — importa aqui porque o WHOIS .br vem cheio de razão social
    acentuada, e esse arquivo é o que vai ser indexado depois.
    """
    try:
        with open(arquivo, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        print(f"Resultados salvos em: {arquivo}")
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")
        sys.exit(1)

def listar_tlds_suportados():
    """
    Lista os TLDs que o script sabe consultar.

    Rode antes de um lote grande: TLD fora desta lista não é consultado, volta
    como "erro" e passa fácil batido no meio de 200 resultados.
    """
    print("TLDs suportados:")
    for tld, servidor in sorted(WHOIS_SERVERS.items()):
        print(f"  .{tld} -> {servidor}")

def main():
    parser = argparse.ArgumentParser(
        description="Consulta informações WHOIS para domínios de diversos TLDs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python whois_universal.py -d exemplo.com.br
  python whois_universal.py -d google.com
  python whois_universal.py -l dominios.txt -o resultados.json
  python whois_universal.py -d exemplo.com -o resultado.json
  python whois_universal.py --list-tlds
        """
    )
    
    # Grupo mutuamente exclusivo para domínio único ou lista.
    # required=False porque --list-tlds tem de rodar sem -d e sem -l; a
    # cobrança de "informe um dos dois" é feita à mão mais abaixo.
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-d', '--dominio', 
                      help='Domínio único para consulta')
    group.add_argument('-l', '--lista', 
                      help='Arquivo com lista de domínios (um por linha)')
    
    parser.add_argument('-o', '--output', 
                       help='Arquivo de saída em formato JSON')
    
    parser.add_argument('--list-tlds', action='store_true',
                       help='Lista todos os TLDs suportados')
    
    args = parser.parse_args()

    # --list-tlds é informativo e encerra antes de qualquer consulta de rede.
    if args.list_tlds:
        listar_tlds_suportados()
        sys.exit(0)
    
    if not args.dominio and not args.lista:
        parser.error("É necessário especificar um domínio (-d) ou uma lista (-l)")
    
    # Determinar lista de domínios
    if args.dominio:
        dominios = [args.dominio]
    else:
        dominios = ler_dominios_arquivo(args.lista)
    
    # Processar domínios
    resultados = processar_dominios(dominios)
    
    # Saída dos resultados: com -o vai para arquivo (é o modo que o pipeline
    # usa); sem -o, imprime formatado na tela para o aluno ler o resultado
    # antes de se preocupar com arquivo.
    if args.output:
        salvar_json(resultados, args.output)
    else:
        # Exibir na tela
        print("\n" + "="*50)
        print("RESULTADOS:")
        print("="*50)
        print(json.dumps(resultados, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()