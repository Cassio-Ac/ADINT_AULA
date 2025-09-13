import socket
import re
import json
import argparse
import sys
from typing import List, Dict, Optional

# Mapeamento de TLDs para servidores WHOIS
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
    Extrai o TLD do domínio
    """
    partes = dominio.lower().split('.')
    if len(partes) >= 2:
        # Para domínios como .com.br, considerar apenas o último nível
        return partes[-1]
    return ''

def obter_servidor_whois(dominio: str) -> Optional[str]:
    """
    Determina o servidor WHOIS apropriado para o domínio
    """
    tld = obter_tld(dominio)
    return WHOIS_SERVERS.get(tld)

def consulta_whois_universal(dominio: str) -> dict:
    """
    Consulta informações WHOIS para qualquer domínio
    """
    try:
        servidor = obter_servidor_whois(dominio)
        if not servidor:
            return {
                "domain": dominio,
                "erro": f"Servidor WHOIS não encontrado para TLD: {obter_tld(dominio)}"
            }

        porta = 43
        timeout = 30

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((servidor, porta))
            s.sendall((dominio + "\r\n").encode())
            resposta = b""
            while True:
                dados = s.recv(4096)
                if not dados:
                    break
                resposta += dados

        # Tentar decodificar com diferentes encodings
        texto = ""
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        for encoding in encodings:
            try:
                texto = resposta.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        return {
            "domain": dominio,
            "text": texto,
            "server": servidor,
            "tld": obter_tld(dominio)
        }
    except Exception as e:
        return {"domain": dominio, "erro": str(e)}

def parse_whois_br(texto: str) -> dict:
    """
    Parser específico para domínios .br
    """
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
        if campo in ["name_server", "nsstat", "nslastaa", "email", "person", "nic_hdl_br"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None
    
    return resultado

def parse_whois_com(texto: str) -> dict:
    """
    Parser específico para domínios .com/.net
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
        matches = re.findall(padrao, texto, re.IGNORECASE)
        if campo in ["name_server", "status"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None
    
    return resultado

def parse_whois_generico(texto: str) -> dict:
    """
    Parser genérico para outros TLDs
    """
    # Padrões mais gerais que funcionam para a maioria dos TLDs
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
            if matches:
                break
        
        if campo in ["name_server", "status"]:
            resultado[campo] = matches if matches else None
        else:
            resultado[campo] = matches[0].strip() if matches else None
    
    return resultado

def parse_whois_universal(data: dict) -> dict:
    """
    Parser universal que escolhe o método adequado baseado no TLD
    """
    if "erro" in data:
        return {"domain": data["domain"], "erro": data["erro"]}
    
    texto = data.get("text", "")
    tld = data.get("tld", "")
    dominio = data.get("domain", "")
    servidor = data.get("server", "")
    
    # Verificar se retornou erro do servidor WHOIS
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
    
    # Adicionar informações extras
    resultado["domain"] = dominio
    resultado["server"] = servidor
    resultado["tld"] = tld
    
    return resultado

def ler_dominios_arquivo(arquivo: str) -> List[str]:
    """
    Lê lista de domínios de um arquivo (um por linha)
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
    Processa uma lista de domínios e retorna os resultados
    """
    resultados = []
    
    for i, dominio in enumerate(dominios, 1):
        print(f"Processando {i}/{len(dominios)}: {dominio}")
        
        raw_data = consulta_whois_universal(dominio)
        resultado = parse_whois_universal(raw_data)
        resultados.append(resultado)
    
    return resultados

def salvar_json(dados: List[Dict], arquivo: str):
    """
    Salva os dados em formato JSON
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
    Lista todos os TLDs suportados
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
    
    # Grupo mutuamente exclusivo para domínio único ou lista
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
    
    # Saída dos resultados
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