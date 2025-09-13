#!/usr/bin/env python3
import os
import json
import re
import subprocess
import socket
import sys
from pathlib import Path

class ShodanScanner:
    def __init__(self, input_file="dominios.txt", output_dir="shodan_results"):
        self.input_file = input_file
        self.output_dir = output_dir
        self.json_output_dir = os.path.join(output_dir, "json")
        
        # Criar diretórios
        Path(self.output_dir).mkdir(exist_ok=True)
        Path(self.json_output_dir).mkdir(exist_ok=True)
    
    def check_shodan_cli(self):
        """Verifica se o Shodan CLI está configurado"""
        try:
            result = subprocess.run(['shodan', 'info'], 
                                  capture_output=True, text=True, check=True)
            print("✅ Shodan CLI configurado corretamente")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[ERRO] Shodan CLI não está inicializado.")
            print("Instale com: pip install shodan")
            print("Configure com: shodan init SUA_API_KEY")
            return False 
    
    def resolve_ip(self, domain):
        """Resolve IP do domínio usando socket (equivalente ao dig)"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
    
    def run_shodan_search(self, domain):
        """Executa busca por hostname no Shodan"""
        try:
            search_file = os.path.join(self.output_dir, f"{domain}_search.txt")
            cmd = ['shodan', 'search', f'hostname:{domain}']
            
            with open(search_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"✅ Busca por hostname salva: {search_file}")
                return True
            else:
                print(f"[WARN] Erro na busca por hostname: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ERRO] Falha na busca por hostname: {str(e)}")
            return False
    
    def run_shodan_host(self, domain, ip):
        """Executa busca por IP no Shodan"""
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
        """Converte arquivo TXT do Shodan para estrutura JSON"""
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
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', lines[0].strip()):
            result["ip"] = lines[0].strip()
            lines = lines[1:]
        
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
            if not in_ports_section and ":" in stripped and not stripped.startswith("|--"):
                key, value = stripped.split(":", 1)
                key = key.strip()
                value = value.strip()
                
                if key == "Hostnames":
                    result["hostnames"] = [h.strip() for h in value.split(";") if h.strip()]
                elif key == "City":
                    result["city"] = value
                elif key == "Country":
                    result["country"] = value
                elif key == "Organization":
                    result["organization"] = value
                elif key == "Operating System":
                    result["os"] = value
                elif key == "Updated":
                    result["updated"] = value
                elif key == "Number of open ports":
                    result["number_of_open_ports"] = int(value) if value.isdigit() else value
                elif key == "Vulnerabilities":
                    # Parse CVEs separados por tabs
                    cves = [cve.strip() for cve in value.split('\t') if cve.strip()]
                    result["vulnerabilities"] = cves
            
            # Processa portas
            elif in_ports_section:
                # Nova porta (formato: 80/tcp Apache)
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
                elif (line.startswith(" ") or line.startswith("\t") or stripped.startswith("|--")) and current_port:
                    detail = stripped
                    if detail.startswith("|--"):
                        detail = detail[3:].strip()
                    if detail:
                        current_details.append(detail)
        
        # Salva última porta
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
        """Salva resultado em formato JSON"""
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
        """Processa um domínio completo"""
        print(f"\n🔍 Processando domínio: {domain}")
        
        # Resolver IP
        ip = self.resolve_ip(domain)
        if not ip:
            print(f"[WARN] Não foi possível resolver IP para: {domain}")
            return False
        
        print(f"✅ IP resolvido: {ip}")
        
        # Buscar por hostname
        print(f"🌐 Buscando por hostname no Shodan: {domain}")
        self.run_shodan_search(domain)
        
        # Buscar por IP
        print(f"🌐 Buscando detalhes do IP no Shodan: {ip}")
        host_file = self.run_shodan_host(domain, ip)
        
        # Converter para JSON
        if host_file and os.path.exists(host_file):
            print("📄 Convertendo para JSON...")
            data = self.parse_shodan_host_txt(host_file)
            
            if data:
                self.save_json_result(domain, data)
                
                # Mostrar resumo
                if "ip" in data:
                    print(f"     IP: {data['ip']}")
                if "number_of_open_ports" in data:
                    print(f"     Portas abertas: {data['number_of_open_ports']}")
                if "vulnerabilities" in data:
                    print(f"     CVEs encontrados: {len(data['vulnerabilities'])}")
                if "organization" in data:
                    print(f"     Organização: {data['organization']}")
            else:
                print("[WARN] Nenhum dado extraído do arquivo host")
        
        print("--------------------------------------------")
        return True
    
    def run(self):
        """Executa o scanner completo"""
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
            with open(self.input_file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            print(f"📋 {len(domains)} domínios para processar")
            
            for domain in domains:
                if self.process_domain(domain):
                    processed += 1
                else:
                    failed += 1
        
        except Exception as e:
            print(f"[ERRO] Falha ao ler arquivo de entrada: {str(e)}")
            return False
        
        print(f"\n✅ Processamento finalizado!")
        print(f"   Processados: {processed}")
        print(f"   Falharam: {failed}")
        print(f"   Resultados TXT: {self.output_dir}")
        print(f"   Resultados JSON: {self.json_output_dir}")
        
        return True

def main():
    """Função principal"""
    # Verificar argumentos
    input_file = sys.argv[1] if len(sys.argv) > 1 else "dominios.txt"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "shodan_results"
    
    # Criar e executar scanner
    scanner = ShodanScanner(input_file, output_dir)
    
    try:
        success = scanner.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] Erro inesperado: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
