#!/usr/bin/env python3
"""
unified_shodan_scanner.py — coleta PASSIVA de exposição via API do Shodan
Curso ADINT · etapa COLETAR do pipeline (COLETAR → TRATAR → ARMAZENAR → UTILIZAR)

===============================================================================
 ISTO É PASSIVO. ESTE SCRIPT NÃO TOCA NO ALVO.
===============================================================================
O Shodan já escaneou a internet — ele varre o espaço de endereçamento IPv4
continuamente, guarda banner, porta, certificado e versão de software, e vende
acesso a esse banco. Aqui você CONSULTA O BANCO DELE.

Quem recebe as suas requisições é a API do Shodan, não o alvo. O alvo não vê
nada: não aparece no log dele, não dispara WAF, não há conexão sua com ele.
As duas únicas conexões de rede deste script são (a) a resolução DNS do nome e
(b) a chamada à API do Shodan.

Isso muda o enquadramento por completo em relação ao COLETOR/coletor.sh, que
manda pacote para o alvo e exige autorização escrita. Consultar base pública de
terceiro é reconhecimento passivo, e é por isso que esta é a primeira etapa
sensata de qualquer análise: custo zero de barulho, e já diz onde olhar.

Ainda assim: o que você FAZ com o resultado continua sendo seu problema. Use
dados de terceiro só dentro de trabalho legítimo e autorizado.

-------------------------------------------------------------------------------
 O CICLO (é isto que o script faz, domínio por domínio)
-------------------------------------------------------------------------------
    domínio
      │  resolve_ip()        socket.gethostbyname — DNS, não Shodan
      ▼
    IP
      │  run_shodan_search() `shodan search hostname:<domínio>`
      │                      busca no índice por NOME
      │  run_shodan_host()   `shodan host <ip>`
      │                      tudo o que o Shodan sabe daquele ENDEREÇO
      ▼
    portas · serviços · versões · certificados · CVEs · organização · hostnames
      │
      └──> e aqui está o ponto: entre os `hostnames` do IP costumam vir NOMES
           QUE VOCÊ NÃO CONHECIA. Esses nomes voltam para o dominios.txt e o
           ciclo recomeça. Reconhecimento é iterativo: cada volta amplia a
           superfície conhecida até estabilizar.

-------------------------------------------------------------------------------
 COMO RODAR
-------------------------------------------------------------------------------
    ./.venv/bin/python3 SHODAN/unified_shodan_scanner.py
    ./.venv/bin/python3 SHODAN/unified_shodan_scanner.py dominios.txt
    ./.venv/bin/python3 SHODAN/unified_shodan_scanner.py dominios.txt saida/

Dois argumentos POSICIONAIS, e não existe nenhuma flag (nem -h, nem --help):

    argv[1]   arquivo de domínios, um por linha.  Padrão: dominios.txt
    argv[2]   diretório de saída.                 Padrão: shodan_results

Use o Python do venv. Com o Python do sistema falta o módulo `shodan` (e o
`dotenv`, que aqui é opcional mas carrega a chave).

-------------------------------------------------------------------------------
 O QUE PRECISA
-------------------------------------------------------------------------------
  pip install shodan python-dotenv     (já estão no requirements.txt)
  A CLI `shodan` tem que estar no PATH — é ela que o script chama via
  subprocess; o script não usa a biblioteca Python do Shodan.
  Chave de API: conta gratuita no shodan.io serve para a aula.

  Nota do repositório: a CLI do Shodan importa `pkg_resources`, removido no
  setuptools >= 81. Por isso o requirements.txt fixa `setuptools<80`. Se
  aparecer `ModuleNotFoundError: pkg_resources`, é isso.

-------------------------------------------------------------------------------
 DE ONDE VEM A CHAVE
-------------------------------------------------------------------------------
  1. O `load_dotenv()` abaixo lê o arquivo `.env` do DIRETÓRIO ATUAL e joga o
     conteúdo em variáveis de ambiente. Daí a regra de rodar de dentro da pasta
     do projeto: fora dela, não há .env para carregar.
  2. A variável que importa é SHODAN_API_KEY:

         SHODAN_API_KEY=sua_chave_aqui

  3. `check_shodan_cli()` primeiro testa se a CLI já está configurada; se não
     estiver, chama `shodan init $SHODAN_API_KEY`.

  ATENÇÃO: `shodan init` GRAVA a chave em disco, em ~/.shodan/api_key, em texto
  claro. A partir daí a CLI funciona sem o .env — e a chave fica lá até você
  apagar. Em máquina compartilhada, lembre-se disso. Nunca comite o .env e nunca
  projete a chave numa tela compartilhada.

-------------------------------------------------------------------------------
 CUSTO: A API TEM CRÉDITOS, E ELES ACABAM
-------------------------------------------------------------------------------
Não é ilimitado. A conta tem cota de *query credits* (conta gratuita: poucos por
mês; planos pagos, mais). Gastar crédito é a única coisa que pode dar errado de
forma irreversível neste script.

Quem consome crédito aqui:
  `shodan search hostname:<dom>`  → consome crédito de busca, 1 por página de
                                    resultado. É a chamada cara.
  `shodan host <ip>`              → consulta de host; não consome crédito de
                                    busca na maioria dos planos, mas conta para
                                    o limite de requisições por segundo.

O script faz as DUAS para CADA linha do arquivo, em sequência, sem pausa e sem
limite. Ou seja: o consumo é proporcional ao tamanho do dominios.txt, e não há
freio nenhum no código.

ONDE O ALUNO CONTROLA ISSO — é importante entender que o controle não é uma
flag, porque não existe flag:
  · NO TAMANHO DO dominios.txt. É o único acelerador. Comece com 1 ou 2 linhas.
    Rodar uma lista de 500 domínios "para ver o que dá" queima a cota do mês
    numa tarde.
  · Confira o saldo ANTES e DEPOIS:  shodan info
  · Rodou uma vez? Os resultados estão em disco. Reanalise os arquivos em vez de
    consultar de novo — consulta repetida do mesmo domínio custa igual.
  · Para adiar o custo da busca por hostname, comente a chamada a
    run_shodan_search() em process_domain(): a parte que vira JSON vem do
    `shodan host`, não dela.

-------------------------------------------------------------------------------
 O QUE PRODUZ   (em <saída>/, por padrão ./shodan_results)
-------------------------------------------------------------------------------
  <domínio>_search.txt     saída crua de `shodan search hostname:<domínio>`
                           (texto; NÃO é convertida para JSON por este script)
  <domínio>_host.txt       saída crua de `shodan host <ip>` (texto)
  json/<domínio>_host.json o _host.txt já estruturado — é este que a etapa
                           ARMAZENAR indexa no Elasticsearch

-------------------------------------------------------------------------------
 LEIA ANTES DE INTERPRETAR QUALQUER RESULTADO
-------------------------------------------------------------------------------
  1. O SHODAN DESCREVE O IP, NÃO O DONO DO SITE. Em hospedagem compartilhada,
     CDN ou cloud, aquele endereço atende dezenas de clientes. As portas, os
     serviços e os CVEs que voltam podem ser do servidor e dos VIZINHOS.
     Atribuir isso ao seu alvo é ERRO DE ANÁLISE, não achado. Há mais sobre isso
     no comentário de parse_shodan_host_txt() e de process_domain().
  2. O DADO É HISTÓRICO. O campo `Updated` diz quando o Shodan viu aquilo. Pode
     ser de semanas atrás: o serviço pode já ter sido corrigido, ou derrubado, ou
     ter piorado. Shodan diz o que ERA, não o que É.
  3. CVE DO SHODAN É INFERÊNCIA DE BANNER. Ele casa a versão anunciada no banner
     com uma lista de CVEs daquela versão. Não testou nada. Banner mentiroso,
     backport de correção da distribuição ou patch sem troca de versão produzem
     CVE que não existe na prática. É indício, não vulnerabilidade confirmada.
===============================================================================
"""
import os
import json
import re
import subprocess
import socket
import sys
from pathlib import Path

# Carrega o .env da raiz do projeto (SHODAN_API_KEY etc.)
# O try/except deixa a dependência OPCIONAL: sem python-dotenv instalado o
# script continua funcionando, desde que a chave esteja no ambiente de outra
# forma (export SHODAN_API_KEY=... ou `shodan init` já executado antes).
# load_dotenv() sem argumento procura o .env a partir do DIRETÓRIO ATUAL — é o
# motivo de rodar sempre de dentro da pasta do projeto.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

class ShodanScanner:
    """Consulta o banco do Shodan para cada domínio de uma lista.

    Nada aqui toca no alvo. O ciclo por domínio é sempre o mesmo:
    resolver o IP → buscar por hostname → buscar o host pelo IP → estruturar
    a saída de texto em JSON para a etapa ARMAZENAR.

    Os caminhos são relativos ao diretório de onde o script foi chamado, de
    propósito: o script roda na máquina de cada aluno, com outro usuário e
    outro HOME. Caminho absoluto fixo aqui seria bug.
    """

    def __init__(self, input_file="dominios.txt", output_dir="shodan_results"):
        self.input_file = input_file
        self.output_dir = output_dir
        # Os .txt crus ficam na raiz da saída; o JSON estruturado vai para
        # json/, separado porque é só ele que a etapa ARMAZENAR indexa.
        self.json_output_dir = os.path.join(output_dir, "json")

        # Criar diretórios
        # exist_ok=True: rodar duas vezes não quebra (mas SOBRESCREVE os arquivos
        # de um domínio já consultado — para guardar uma coleta, use outro
        # diretório de saída no argv[2]).
        # Cuidado: sem parents=True isto falha se o diretório pedido tiver pai
        # inexistente (ex.: "saida/2026/shodan" sem a pasta saida/2026).
        Path(self.output_dir).mkdir(exist_ok=True)
        Path(self.json_output_dir).mkdir(exist_ok=True)

    def check_shodan_cli(self):
        """Verifica se o Shodan CLI está configurado — e configura, se possível.

        Estratégia em duas tentativas:
          1. `shodan info` funciona? Então a CLI já tem chave gravada em
             ~/.shodan/api_key e não há nada a fazer.
          2. Falhou? Pega SHODAN_API_KEY do ambiente (vinda do .env) e roda
             `shodan init`, que GRAVA a chave em ~/.shodan/api_key, em texto
             claro, de forma permanente.

        `shodan info` serve de teste porque além de validar a chave ele mostra o
        SALDO DE CRÉDITOS. Vale rodar na mão antes de uma lista grande: é a
        forma de saber quanta cota você tem para gastar.

        FileNotFoundError aqui não é chave errada: é a CLI `shodan` fora do
        PATH — quase sempre o script rodando com o Python do sistema em vez do
        venv.
        """
        try:
            result = subprocess.run(['shodan', 'info'], 
                                  capture_output=True, text=True, check=True)
            print("✅ Shodan CLI configurado corretamente")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Não inicializado: tenta usar a chave do .env (SHODAN_API_KEY)
            # capture_output=True nas chamadas abaixo é proposital: impede que a
            # chave apareça no terminal (e no log da aula, se estiver gravando).
            api_key = os.environ.get('SHODAN_API_KEY')
            if api_key:
                try:
                    subprocess.run(['shodan', 'init', api_key], capture_output=True, text=True, check=True)
                    subprocess.run(['shodan', 'info'], capture_output=True, text=True, check=True)
                    print("✅ Shodan CLI inicializado via SHODAN_API_KEY (.env)")
                    return True
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
            print("[ERRO] Shodan CLI não está inicializado.")
            print("Instale com: pip install shodan")
            print("Configure a chave no .env (SHODAN_API_KEY=...) ou rode: shodan init SUA_API_KEY")
            return False 
    
    def resolve_ip(self, domain):
        """Resolve IP do domínio usando socket (equivalente ao dig)

        Primeiro elo do ciclo: o Shodan indexa por ENDEREÇO, então é preciso
        sair do nome e chegar no IP. Esta é a única consulta DNS do script — vai
        para o resolver do sistema, não para o alvo.

        LIMITAÇÃO QUE AFETA A ANÁLISE: gethostbyname() devolve UM endereço só, e
        só IPv4. Domínio atrás de CDN ou com balanceamento tem vários A records,
        e qual deles vem aqui é arbitrário (muda entre execuções). Resultado
        prático: o script descreve um dos servidores do alvo, não o conjunto —
        e um alvo só com AAAA (IPv6) é reportado como "não resolve".
        Para enxergar todos os endereços, compare com `dig +short A <domínio>`.

        Retorna None quando não resolve; é o único caso em que process_domain()
        considera o domínio uma falha.
        """
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
    
    def run_shodan_search(self, domain):
        """Executa busca por hostname no Shodan

        `shodan search hostname:<domínio>` pergunta ao índice: quais hosts o
        Shodan já viu cujo hostname contém esse domínio? É a consulta que pode
        revelar MÁQUINAS QUE VOCÊ NÃO SABIA QUE EXISTIAM — em outro IP, em outra
        cloud, em outro país. É o lado "amplia a superfície" do ciclo.

        >>> É AQUI QUE O CRÉDITO QUEIMA. <<<
        `shodan search` consome query credit, 1 por página de resultado, e o
        script chama isto uma vez por linha do dominios.txt. Lista grande = cota
        do mês. Veja a seção CUSTO no cabeçalho do arquivo.

        Duas coisas a saber sobre a saída:
          · ela sai em TEXTO e fica só no `<domínio>_search.txt`. Este script
            NÃO converte isso para JSON e NÃO indexa — só o resultado do
            `shodan host` vira JSON. Leia o .txt na mão.
          · a CLI devolve apenas a primeira página (as primeiras ~100 linhas).
            Domínio grande tem mais do que isso, e o resto não aparece.
        """
        try:
            # Nome do arquivo derivado do domínio. Se o dominios.txt tiver linha
            # torta (com "/" ou "..", por exemplo), isso vira caminho — mais um
            # motivo para o arquivo de alvos conter só domínios, um por linha.
            search_file = os.path.join(self.output_dir, f"{domain}_search.txt")
            # Lista de argumentos (não string): o subprocess passa cada item
            # direto para o executável, sem shell no meio, então não há risco de
            # a linha do arquivo ser interpretada como comando.
            cmd = ['shodan', 'search', f'hostname:{domain}']

            # stdout vai direto para o arquivo (sem passar pela memória do
            # Python); stderr é capturado para virar mensagem de erro legível.
            with open(search_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                print(f"✅ Busca por hostname salva: {search_file}")
                return True
            else:
                # Erro típico aqui: cota esgotada ("No query credits") ou chave
                # inválida. O script NÃO para — continua para o próximo domínio.
                print(f"[WARN] Erro na busca por hostname: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ERRO] Falha na busca por hostname: {str(e)}")
            return False
    
    def run_shodan_host(self, domain, ip):
        """Executa busca por IP no Shodan

        `shodan host <ip>` devolve a ficha completa daquele endereço: portas
        abertas, banner de cada serviço, versões, certificados, organização,
        geolocalização, hostnames conhecidos e CVEs inferidos. É a chamada que
        gera o dado estruturado do pipeline.

        >>>>> PONTO CRÍTICO DE INTERPRETAÇÃO <<<<<
        ISTO DESCREVE O ENDEREÇO IP. NÃO DESCREVE O DONO DO SITE.
        O arquivo é salvo como `<domínio>_host.txt` e isso é conveniência de
        nome, não um fato: o conteúdo é sobre o IP. Leia o comentário de
        parse_shodan_host_txt() antes de atribuir qualquer coisa daqui ao alvo.

        Cota: `shodan host` normalmente não consome query credit, mas conta para
        o limite de requisições por segundo da sua conta — e o script chama isto
        em sequência, sem pausa, para cada domínio.
        """
        try:
            host_file = os.path.join(self.output_dir, f"{domain}_host.txt")
            cmd = ['shodan', 'host', ip]
            
            with open(host_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"✅ Detalhes do host salvos: {host_file}")
                return host_file
            else:
                print(f"[WARN] Erro na busca por IP: {result.stderr}")
                return None
        except Exception as e:
            print(f"[ERRO] Falha na busca por IP: {str(e)}")
            return None
    
    def parse_shodan_host_txt(self, filepath):
        """Converte arquivo TXT do Shodan para estrutura JSON

        A CLI do Shodan imprime para humano, não para máquina. Este método lê
        aquele texto e monta o dicionário que vai virar JSON e ser indexado no
        Elasticsearch — é a etapa TRATAR do pipeline acontecendo aqui dentro.

        Formato que ele espera (`shodan host <ip>`):

            192.0.2.10                     <- 1ª linha: o IP (192.0.2.0/24 é a
                                              faixa reservada para exemplos)
            Hostnames: a.exemplo.com; b.exemplo.com
            City: Sao Paulo
            Country: Brazil
            Organization: Nome do provedor
            Operating System: Linux
            Updated: 2026-09-14T03:12:55
            Number of open ports: 3
            Vulnerabilities: CVE-0000-0001    CVE-0000-0002

            Ports:
            80/tcp Apache httpd
            |-- Server: Apache/2.4.x
            443/tcp nginx

        =======================================================================
         LEIA ANTES DE USAR ESTE JSON NUM RELATÓRIO
        =======================================================================
        TUDO O QUE ESTE DICIONÁRIO DESCREVE É O ENDEREÇO IP. NÃO É O SEU ALVO.

        O arquivo de saída se chama `<domínio>_host.json` e isso ENGANA: o
        conteúdo não é "a ficha do domínio", é "a ficha do IP para o qual aquele
        domínio apontava no momento da resolução".

        Em hospedagem compartilhada, CDN ou cloud, o mesmo endereço atende
        dezenas ou centenas de clientes. Então:

          ports            → são as portas DO SERVIDOR. O MySQL na 3306 e o
                             Redis na 6379 podem ser de qualquer um dos sites
                             hospedados ali, inclusive de um VIZINHO do seu alvo.
          vulnerabilities  → são CVEs inferidos do banner DO SERVIDOR. Um CVE de
                             painel de controle de hospedagem não é
                             vulnerabilidade "do alvo"; é do provedor.
          organization     → é o provedor de hospedagem, não a empresa do alvo.
                             Se você esperava o nome do cliente e veio o nome de
                             uma cloud, é sinal de infraestrutura terceirizada.
          hostnames        → aqui aparecem os NOMES DOS VIZINHOS. Dois usos
                             opostos: (a) é a melhor pista de que o IP é
                             compartilhado — vários nomes de organizações
                             diferentes no mesmo endereço; (b) nomes do MESMO
                             domínio do alvo são achado legítimo e voltam para
                             o dominios.txt, realimentando o ciclo.

        ESCREVER "o alvo tem 12 CVEs" a partir disto, sem antes verificar se o
        IP é dedicado, é ERRO DE ANÁLISE — e é o erro mais comum de quem começa.

        Como separar o alvo do vizinho:
          1. olhe `hostnames`: nomes de organizações diferentes = IP compartilhado;
          2. confirme QUAL serviço responde pelo seu domínio comparando com a
             saída do httpx (COLETOR/) e com o SAN do certificado (tlsx);
          3. na dúvida, trate como "exposição do provedor", não do alvo.

        E lembre que o dado é HISTÓRICO: `updated` diz quando o Shodan viu
        aquilo. Pode já ter sido corrigido, ou ter piorado.

        Retorna {} quando não consegue ler o arquivo ou quando ele está vazio —
        e process_domain() trata isso como "nenhum dado extraído", não como
        "nada exposto". Mais uma vez: "zero achados" e "zero verificado" são a
        mesma saída e coisas opostas.
        """
        result = {}
        ports = []

        try:
            with open(filepath, "r", encoding="utf-8") as file:
                lines = file.readlines()
        except Exception as e:
            print(f"[ERRO] Não foi possível ler {filepath}: {str(e)}")
            return {}
        
        if not lines:
            return result
        
        # Primeira linha é o IP
        # Só IPv4: um host IPv6 não casa com esta regex e a linha fica no corpo,
        # sem campo "ip" no JSON.
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', lines[0].strip()):
            result["ip"] = lines[0].strip()
            lines = lines[1:]

        # O parser é uma máquina de estados simples. `in_ports_section` divide o
        # arquivo em duas metades: antes de "Ports:" são metadados do host
        # (chave: valor); depois, blocos de porta com detalhes indentados.
        # As variáveis current_* acumulam a porta que está sendo lida até a
        # próxima aparecer — por isso há um "salva última porta" no fim do laço.
        current_port = None
        current_protocol = None
        current_service = ""
        current_details = []
        in_ports_section = False
        
        for line in lines:
            stripped = line.strip()
            
            if not stripped:
                continue
                
            # Início da seção de portas
            if stripped == "Ports:":
                in_ports_section = True
                continue
            
            # Cabeçalhos antes das portas
            # split(":", 1) com maxsplit=1 porque o valor pode conter ":"
            # (Updated traz um timestamp ISO, por exemplo).
            # Só as chaves tratadas abaixo entram no JSON; o que o Shodan
            # imprimir fora dessa lista é descartado em silêncio.
            if not in_ports_section and ":" in stripped and not stripped.startswith("|--"):
                key, value = stripped.split(":", 1)
                key = key.strip()
                value = value.strip()
                
                if key == "Hostnames":
                    # TODOS os nomes que o Shodan associa a este IP — os do seu
                    # alvo E os dos vizinhos. Nome de domínio diferente aqui é a
                    # evidência de que o IP é compartilhado. Nome novo do MESMO
                    # domínio é achado: volta para o dominios.txt.
                    result["hostnames"] = [h.strip() for h in value.split(";") if h.strip()]
                elif key == "City":
                    result["city"] = value
                elif key == "Country":
                    result["country"] = value
                elif key == "Organization":
                    # Dono do BLOCO DE IP (provedor/cloud), não necessariamente
                    # a empresa do alvo. Nome de cloud aqui = infra terceirizada.
                    result["organization"] = value
                elif key == "Operating System":
                    result["os"] = value
                elif key == "Updated":
                    # QUANDO o Shodan viu isso. O campo mais ignorado e um dos
                    # mais importantes: dado de semanas atrás descreve o passado.
                    result["updated"] = value
                elif key == "Number of open ports":
                    # int() quando der; se o Shodan mudar o formato, guarda a
                    # string crua em vez de estourar — mas aí o campo fica com
                    # tipo inconsistente no índice do Elasticsearch.
                    result["number_of_open_ports"] = int(value) if value.isdigit() else value
                elif key == "Vulnerabilities":
                    # Parse CVEs separados por tabs
                    # CVEs INFERIDOS DO BANNER DO SERVIDOR — ninguém testou nada,
                    # e podem ser de serviço de um vizinho no mesmo IP. Nunca
                    # relate como vulnerabilidade confirmada do alvo.
                    # O split é por TAB porque é assim que a CLI separa; se a
                    # versão instalada mudar para espaço ou vírgula, esta linha
                    # devolve um único "CVE" com tudo junto.
                    cves = [cve.strip() for cve in value.split('\t') if cve.strip()]
                    result["vulnerabilities"] = cves
            
            # Processa portas
            # Lembrete: portas DO SERVIDOR, não necessariamente do alvo.
            elif in_ports_section:
                # Nova porta (formato: 80/tcp Apache)
                # Grupos: 1=número, 2=protocolo, 3=resto da linha (o serviço).
                # A linha de porta não é indentada; os detalhes são — é isso que
                # distingue "nova porta" de "detalhe da porta atual".
                port_match = re.match(r'^(\d+)/(tcp|udp)\s*(.*)', stripped)

                if port_match:
                    # Salva porta anterior
                    if current_port is not None:
                        ports.append({
                            "port": current_port,
                            "protocol": current_protocol,
                            "service": current_service,
                            "details": current_details
                        })
                    
                    # Nova porta
                    current_port = int(port_match.group(1))
                    current_protocol = port_match.group(2)
                    current_service = port_match.group(3).strip()
                    current_details = []
                
                # Detalhes da porta (linhas indentadas)
                # Note que o teste usa `line` (com a indentação original), não
                # `stripped` — a indentação É a informação aqui.
                # Nestes detalhes é que vem a VERSÃO do software (Server:,
                # banner), que é o dado mais útil da ficha: é dele que sai a
                # inferência de CVE, e é ele que você confere na mão.
                elif (line.startswith(" ") or line.startswith("\t") or stripped.startswith("|--")) and current_port:
                    detail = stripped
                    if detail.startswith("|--"):
                        detail = detail[3:].strip()
                    if detail:
                        current_details.append(detail)
        
        # Salva última porta
        # Sem este bloco a ÚLTIMA porta do arquivo se perderia: ela só seria
        # gravada quando aparecesse a porta seguinte, que não existe.
        if current_port is not None:
            ports.append({
                "port": current_port,
                "protocol": current_protocol,
                "service": current_service,
                "details": current_details
            })
        
        if ports:
            result["ports"] = ports
        
        return result
    
    def save_json_result(self, domain, data):
        """Salva resultado em formato JSON

        Um arquivo por domínio, em json/. É a entrada da etapa ARMAZENAR:
        `adint_pipeline.py` lê daqui e indexa no Elasticsearch.

        É JSON indentado (um objeto por arquivo), não JSONL — diferente do
        COLETOR/, que produz JSONL porque ali são milhares de linhas. Aqui são
        poucos arquivos pequenos e legíveis a olho.

        ensure_ascii=False preserva acentuação (City: São Paulo) em vez de
        gravar \\u00e3o; indent=2 é para o aluno poder abrir e ler.
        """
        json_file = os.path.join(self.json_output_dir, f"{domain}_host.json")

        try:
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ JSON salvo: {json_file}")
            return True
        except Exception as e:
            print(f"[ERRO] Falha ao salvar JSON: {str(e)}")
            return False
    
    def process_domain(self, domain):
        """Processa um domínio completo — o ciclo inteiro para um alvo

            domínio → IP → busca por hostname → ficha do IP → JSON

        Cada volta custa: 1 query credit (a busca) + 1 consulta de host.
        Multiplicado pelo número de linhas do dominios.txt, sem pausa e sem
        limite. É o único lugar onde o consumo de cota acontece.

        CUIDADO COM O VALOR DE RETORNO: retorna True sempre que o DNS resolveu,
        mesmo que as duas consultas ao Shodan tenham falhado e nenhum JSON tenha
        sido gravado. Ou seja, o contador "Processados" do resumo final mede
        "domínios que resolveram", não "domínios com dado coletado". Confira
        olhando o diretório json/, não o número impresso no fim.
        """
        print(f"\n🔍 Processando domínio: {domain}")

        # Resolver IP
        ip = self.resolve_ip(domain)
        if not ip:
            print(f"[WARN] Não foi possível resolver IP para: {domain}")
            return False
        
        print(f"✅ IP resolvido: {ip}")
        
        # Buscar por hostname
        # >>> Esta é a chamada que GASTA QUERY CREDIT. Para rodar a aula sem
        # consumir cota, comente esta linha: o JSON do pipeline vem da consulta
        # de host logo abaixo, não desta.
        print(f"🌐 Buscando por hostname no Shodan: {domain}")
        self.run_shodan_search(domain)

        # Buscar por IP
        # Note que o retorno não é checado quanto a sucesso de conteúdo: o `if`
        # abaixo só olha se o arquivo existe.
        print(f"🌐 Buscando detalhes do IP no Shodan: {ip}")
        host_file = self.run_shodan_host(domain, ip)

        # Converter para JSON
        if host_file and os.path.exists(host_file):
            print("📄 Convertendo para JSON...")
            data = self.parse_shodan_host_txt(host_file)
            
            if data:
                self.save_json_result(domain, data)

                # Mostrar resumo
                # ===============================================================
                #  O RESUMO ABAIXO É SOBRE O IP, NÃO SOBRE O DOMÍNIO.
                # ===============================================================
                # As quatro linhas impressas aqui são a origem do erro de análise
                # mais comum do curso. Lidas rápido, parecem dizer
                #     "exemplo.com.br tem 12 portas abertas e 8 CVEs"
                # quando o que elas de fato dizem é
                #     "o IP para o qual exemplo.com.br aponta tem 12 portas e 8
                #      CVEs, somando TODOS os sites hospedados nele".
                #
                # Em hospedagem compartilhada, CDN ou cloud, as portas e os CVEs
                # podem ser do servidor e dos VIZINHOS do alvo. "Organização" é o
                # provedor, não a empresa. Antes de levar esses números para
                # qualquer relatório, confira `hostnames` no JSON: se houver
                # nomes de outras organizações no mesmo IP, ele é compartilhado e
                # nada disso é atribuível ao alvo sem verificação adicional.
                if "ip" in data:
                    print(f"     IP: {data['ip']}")
                if "number_of_open_ports" in data:
                    print(f"     Portas abertas: {data['number_of_open_ports']}")
                if "vulnerabilities" in data:
                    print(f"     CVEs encontrados: {len(data['vulnerabilities'])}")
                if "organization" in data:
                    print(f"     Organização: {data['organization']}")
            else:
                # "Nenhum dado extraído" NÃO significa "nada exposto": significa
                # que o Shodan não tem registro daquele IP (nunca varreu, ou é
                # recente), ou que a consulta falhou. Ausência de dado não é
                # evidência de ausência de exposição.
                print("[WARN] Nenhum dado extraído do arquivo host")

        print("--------------------------------------------")
        return True

    def run(self):
        """Executa o scanner completo

        Ordem proposital: valida a CLI/chave ANTES de ler a lista e antes de
        gastar o primeiro crédito. Falhar em um segundo é melhor que falhar no
        meio de uma lista grande.

        O laço é SEQUENCIAL e sem pausa entre domínios — não há rate limiting
        nem limite de quantidade no código. O freio é o tamanho do arquivo de
        entrada (veja a seção CUSTO no cabeçalho). Comece com 1 ou 2 linhas.
        """
        print("🚀 Iniciando Shodan Scanner Unificado")

        # Verificar Shodan CLI
        if not self.check_shodan_cli():
            return False

        # Verificar arquivo de entrada
        if not os.path.exists(self.input_file):
            print(f"[ERRO] Arquivo {self.input_file} não encontrado")
            return False
        
        # Processar domínios
        processed = 0
        failed = 0
        
        try:
            # Um domínio por linha; linha vazia é ignorada. Não há tratamento de
            # comentário (#) nem de http:// na frente — ponha só o nome do
            # domínio. O `.strip()` resolve espaço e o \r de arquivo editado no
            # Windows.
            with open(self.input_file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]

            # ESTE NÚMERO É O SEU ORÇAMENTO DE CRÉDITOS. Cada domínio = 1 busca
            # (query credit) + 1 consulta de host. Se o número surpreender você,
            # cancele agora com Ctrl-C: cota gasta não volta.
            print(f"📋 {len(domains)} domínios para processar")

            for domain in domains:
                if self.process_domain(domain):
                    processed += 1
                else:
                    failed += 1
        
        except Exception as e:
            print(f"[ERRO] Falha ao ler arquivo de entrada: {str(e)}")
            return False
        
        # "Processados" = domínios cujo DNS resolveu (ver process_domain), não
        # domínios com dado coletado. "Falharam" = só falha de resolução DNS.
        # Falha de API não aparece nestes números — ela aparece como [WARN]
        # durante a execução. Para saber o que realmente foi coletado, conte os
        # arquivos em json/.
        print(f"\n✅ Processamento finalizado!")
        print(f"   Processados: {processed}")
        print(f"   Falharam: {failed}")
        print(f"   Resultados TXT: {self.output_dir}")
        print(f"   Resultados JSON: {self.json_output_dir}")
        
        return True

def main():
    """Função principal

    Argumentos posicionais, sem argparse — portanto sem `-h`/`--help` e sem
    validação. Qualquer coisa passada em argv[1] é tratada como nome de arquivo
    e em argv[2] como diretório de saída.

        python3 unified_shodan_scanner.py [arquivo_dominios] [dir_saida]

    Códigos de saída: 0 = terminou, 1 = erro ou interrupção. É o que o
    `adint_pipeline.py` usa para saber se a etapa funcionou.
    """
    # Verificar argumentos
    input_file = sys.argv[1] if len(sys.argv) > 1 else "dominios.txt"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "shodan_results"

    # Criar e executar scanner
    # Atenção: o construtor cria os diretórios, e está FORA do try/except
    # abaixo — se o caminho de saída for inválido, o erro sai como traceback cru.
    scanner = ShodanScanner(input_file, output_dir)

    try:
        success = scanner.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        # Ctrl-C é saída legítima aqui: é assim que você para o consumo de cota
        # no meio da lista. O que já foi coletado fica em disco.
        print("\n[INFO] Interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] Erro inesperado: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
