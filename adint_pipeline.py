#!/usr/bin/env python3
"""
ADINT Pipeline - Orquestrador de coleta e análise de inteligência

Este script coordena a execução de várias ferramentas de ADINT/OSINT e envia
os resultados para o Elasticsearch em índices gerais por tipo de dado.

Uso:
  python adint_pipeline.py --company "Empresa XYZ" --domains domains.txt --notes "Análise de segurança"
"""

import os
import sys
import json
import yaml
import time
import logging
import argparse
import subprocess
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from elasticsearch import Elasticsearch, helpers

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("adint_pipeline.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("adint-pipeline")

class ADINTPipeline:
    """Classe principal do pipeline ADINT"""
    
    def __init__(self, company_name: str, domains_file: str, notes: str = "", 
                 es_host: str = "localhost", es_port: int = 9200,
                 output_dir: str = "pipeline_results", config_file: str = "pipeline_config.yaml",
                 company_slug: str = None):
        """
        Inicializa o pipeline
        
        Args:
            company_name: Nome da empresa alvo
            domains_file: Arquivo com lista de domínios (um por linha)
            notes: Observações sobre a análise
            es_host: Host do Elasticsearch
            es_port: Porta do Elasticsearch
            output_dir: Diretório para armazenar resultados
            config_file: Arquivo de configuração do pipeline
            company_slug: Slug/apelido da empresa (opcional, gerado a partir do nome se não fornecido)
        """
        self.company_name = company_name
        self.company_slug = company_slug if company_slug else self._slugify(company_name)
        self.domains_file = domains_file
        self.notes = notes
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Diretório base do script
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Diretório de saída
        self.output_dir = os.path.join(self.base_dir, output_dir, self.company_slug)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Diretório temporário para arquivos de domínios
        self.temp_dir = os.path.join(self.output_dir, "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Copia os domínios para o diretório temporário
        self.temp_domains_file = os.path.join(self.temp_dir, "domains.txt")
        self._copy_domains_file()
        
        # Configuração do Elasticsearch
        self.es_config = {
            "host": es_host,
            "port": es_port,
            "timeout": 60
        }
        self.es = None
        
        # Prefixo para índices do Elasticsearch
        self.index_prefix = "analise_superficie"
        
        # Carrega configuração
        self.config = self._load_config(config_file)
        
        # Lê os domínios do arquivo
        domains = self._read_domains_from_file(domains_file)
        
        # Registra metadados da análise
        self.metadata = {
            "company": company_name,
            "company_slug": self.company_slug,
            "timestamp": self.timestamp,
            "notes": notes,
            "domains": domains  # Usa a lista de domínios em vez do nome do arquivo
        }
        
        # Salva metadados
        self._save_metadata()
        
    def _slugify(self, text: str) -> str:
        """Converte texto para slug (minúsculas, sem espaços, apenas alfanuméricos e underscores)"""
        import re
        text = text.lower()
        text = re.sub(r'[^a-z0-9]+', '_', text)
        text = re.sub(r'_+', '_', text)
        return text.strip('_')
    
    def _read_domains_from_file(self, domains_file: str) -> List[str]:
        """Lê os domínios do arquivo e retorna como lista"""
        domains = []
        try:
            with open(domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        domains.append(line)
            logger.info(f"Lidos {len(domains)} domínios do arquivo {domains_file}")
            return domains
        except Exception as e:
            logger.error(f"Erro ao ler domínios do arquivo {domains_file}: {e}")
            sys.exit(1)
    
    def _copy_domains_file(self):
        """Copia o arquivo de domínios para o diretório temporário"""
        try:
            with open(self.domains_file, 'r') as src, open(self.temp_domains_file, 'w') as dst:
                for line in src:
                    line = line.strip()
                    if line:
                        dst.write(f"{line}\n")
            logger.info(f"Arquivo de domínios copiado para {self.temp_domains_file}")
        except Exception as e:
            logger.error(f"Erro ao copiar arquivo de domínios: {e}")
            sys.exit(1)
    
    def _load_config(self, config_file: str) -> dict:
        """Carrega configuração do arquivo YAML"""
        config_path = os.path.join(self.base_dir, config_file)
        
        # Se o arquivo não existir, cria um com configuração padrão
        if not os.path.exists(config_path):
            default_config = {
                "tools": {
                    "whois": {
                        "enabled": True,
                        "script": "WHOIS/whois_universal.py",
                        "index": "whois"
                    },
                    "dns": {
                        "enabled": True,
                        "script": "DNS/dns-security-analyzer.py",
                        "index": "dns"
                    },
                    "coletor": {
                        "enabled": True,
                        "script": "COLETOR/coletor.sh",
                        "index": "coletor"
                    },
                    "shodan": {
                        "enabled": True,
                        "script": "SHODAN/unified_shodan_scanner.py",
                        "index": "shodan"
                    },
                    "feed": {
                        "enabled": True,
                        "script": "FEED/rss_feed.py",
                        "index": "feed"
                    },
                    "telegram": {
                        "enabled": False,
                        "script": "TELEGRAM/download_Combo.py",
                        "index": "telegram"
                    }
                },
                "elasticsearch": {
                    "index_settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    }
                }
            }
            
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            logger.info(f"Arquivo de configuração padrão criado em {config_path}")
            return default_config
        
        # Carrega configuração existente
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            sys.exit(1)
    
    def _save_metadata(self):
        """Salva metadados do pipeline"""
        metadata_file = os.path.join(self.output_dir, "metadata.json")
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            logger.info(f"Metadados salvos em {metadata_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar metadados: {e}")
    
    def connect_to_elasticsearch(self) -> bool:
        """Conecta ao Elasticsearch"""
        try:
            self.es = Elasticsearch([f"http://{self.es_config['host']}:{self.es_config['port']}"], 
                                   timeout=self.es_config['timeout'])
            
            if self.es.ping():
                logger.info("✅ Conectado ao Elasticsearch")
                return True
            else:
                logger.error("❌ Falha ao conectar ao Elasticsearch (ping falhou)")
                return False
        except Exception as e:
            logger.error(f"❌ Erro ao conectar ao Elasticsearch: {e}")
            return False
    
    def create_index(self, index_name: str) -> bool:
        """Cria índice no Elasticsearch se não existir"""
        if not self.es:
            logger.error("Elasticsearch não conectado")
            return False 
        
        # Agora usando índices gerais sem o prefixo da empresa
        full_index_name = f"{self.index_prefix}_{index_name}"
        
        try:
            if not self.es.indices.exists(index=full_index_name):
                settings = self.config.get("elasticsearch", {}).get("index_settings", {})
                self.es.indices.create(
                    index=full_index_name,
                    body={
                        "settings": settings,
                        "mappings": {
                            "properties": {
                                "company": {
                                    "type": "keyword"
                                },
                                "company_slug": {
                                    "type": "keyword"
                                },
                                "pipeline_run": {
                                    "type": "keyword"
                                },
                                "timestamp": {
                                    "type": "date",
                                    "format": "yyyy-MM-dd'T'HH:mm:ss||yyyy-MM-dd||yyyyMMdd_HHmmss||epoch_millis"
                                }
                            },
                            "dynamic_templates": [
                                {
                                    "strings_as_keywords": {
                                        "match_mapping_type": "string",
                                        "mapping": {
                                            "type": "text",
                                            "fields": {
                                                "keyword": {
                                                    "type": "keyword",
                                                    "ignore_above": 256
                                                }
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    }
                )
                logger.info(f"✅ Índice {full_index_name} criado")
            else:
                logger.info(f"Índice {full_index_name} já existe")
            return True
        except Exception as e:
            logger.error(f"❌ Erro ao criar índice {full_index_name}: {e}")
            return False
    
    def send_to_elasticsearch(self, index_name: str, data_file: str, id_field: str = None) -> bool:
        """Envia dados para o Elasticsearch"""
        if not self.es:
            logger.error("Elasticsearch não conectado")
            return False

        # Agora usando índices gerais sem o prefixo da empresa
        full_index_name = f"{self.index_prefix}_{index_name}"
        
        try:
            # Verifica se o arquivo existe
            if not os.path.exists(data_file):
                logger.error(f"Arquivo não encontrado: {data_file}")
                return False
            
            # Determina o tipo de arquivo
            if data_file.endswith('.json'):
                try:
                    with open(data_file, 'r') as f:
                        data = json.load(f)
                        
                    # Converte para lista se for um objeto
                    if isinstance(data, dict):
                        data = [data]
                except json.JSONDecodeError as e:
                    logger.error(f"Erro ao decodificar JSON em {data_file}: {e}")
                    # Tenta ler como JSONL se falhar como JSON
                    try:
                        data = []
                        with open(data_file, 'r') as f:
                            for line in f:
                                if line.strip():
                                    data.append(json.loads(line))
                        if data:
                            logger.info(f"Arquivo {data_file} tratado como JSONL após falha como JSON")
                        else:
                            logger.error(f"Não foi possível ler {data_file} nem como JSON nem como JSONL")
                            return False
                    except Exception as e2:
                        logger.error(f"Falha completa ao ler {data_file}: {e2}")
                        return False
            elif data_file.endswith('.jsonl'):
                data = []
                with open(data_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                data.append(json.loads(line))
                            except json.JSONDecodeError:
                                logger.warning(f"Ignorando linha inválida em {data_file}")
            else:
                logger.error(f"Formato de arquivo não suportado: {data_file}")
                return False
            
            # Verifica se temos dados para enviar
            if not data:
                logger.warning(f"Nenhum dado válido encontrado em {data_file}")
                return False
                
            # Adiciona metadados da empresa a cada documento
            for item in data:
                # Adiciona informações da empresa diretamente no documento
                item['company'] = self.company_name
                item['company_slug'] = self.company_slug
                item['timestamp'] = self.timestamp
                item['pipeline_run'] = self.timestamp
            
            # Prepara ações para bulk insert
            actions = []
            for item in data:
                action = {
                    "_index": full_index_name,
                    "_source": item
                }
                
                # Usa campo específico como ID se fornecido
                if id_field and id_field in item:
                    action["_id"] = item[id_field]
                else:
                    # Cria ID composto que inclui a empresa para evitar colisões
                    # entre documentos de empresas diferentes
                    if "_id" not in action and "id" in item:
                        action["_id"] = f"{self.company_slug}_{item['id']}"
                
                actions.append(action)
            
            # Adiciona logs detalhados
            logger.info(f"Preparando {len(actions)} documentos para envio ao índice {full_index_name}")
            
            # Envia em lotes
            if actions:
                try:
                    success, failed = helpers.bulk(self.es, actions, stats_only=True)
                    logger.info(f"✅ {success} documentos enviados para {full_index_name} ({failed} falhas)")
                    return True
                except Exception as e:
                    logger.error(f"❌ Erro no bulk insert para {full_index_name}: {e}")
                    # Tentar enviar documento por documento em caso de falha no bulk
                    logger.info("Tentando enviar documentos individualmente...")
                    individual_success = 0
                    for i, action in enumerate(actions):
                        try:
                            self.es.index(index=full_index_name, document=action["_source"], id=action.get("_id"))
                            individual_success += 1
                            # Log a cada 10 documentos
                            if individual_success % 10 == 0:
                                logger.info(f"Progresso: {individual_success}/{len(actions)} documentos enviados individualmente")
                        except Exception as e2:
                            logger.error(f"Falha ao indexar documento {i}: {e2}")
                    
                    if individual_success > 0:
                        logger.info(f"✅ {individual_success}/{len(actions)} documentos enviados individualmente")
                        return individual_success > 0
                    return False
            else:
                logger.warning(f"Nenhum documento para enviar ao índice {full_index_name}")
                return False
            
        except Exception as e: 
            logger.error(f"❌ Erro ao enviar dados para {full_index_name}: {e}")
            return False
    
    def run_tool(self, tool_name: str) -> bool:
        """Executa uma ferramenta específica do pipeline"""
        tool_config = self.config.get("tools", {}).get(tool_name)
        
        if not tool_config:
            logger.error(f"Ferramenta não configurada: {tool_name}")
            return False
        
        if not tool_config.get("enabled", False):
            logger.info(f"Ferramenta {tool_name} desabilitada na configuração")
            return True
        
        script_path = os.path.join(self.base_dir, tool_config.get("script", ""))
        if not os.path.exists(script_path):
            logger.error(f"Script não encontrado: {script_path}")
            return False
        
        # Diretório de saída específico para esta ferramenta
        tool_output_dir = os.path.join(self.output_dir, tool_name)
        os.makedirs(tool_output_dir, exist_ok=True)
        
        logger.info(f"🔄 Executando {tool_name}...")
        
        try:
            # Determina o comando com base na extensão do script
            if script_path.endswith('.py'):
                # Ativa o ambiente virtual do Telegram se necessário
                if tool_name == "telegram":
                    venv_activate = os.path.join(self.base_dir, "telegram_venv/bin/activate")
                    cmd = f"source {venv_activate} && python3 {script_path}"
                    use_shell = True
                else:
                    cmd = ["python3", script_path]
                    use_shell = False
            elif script_path.endswith('.sh'):
                cmd = ["bash", script_path]
                use_shell = False
            else:
                logger.error(f"Tipo de script não suportado: {script_path}")
                return False
            
            # Adiciona argumentos específicos por ferramenta
            if tool_name == "whois":
                output_file = os.path.join(tool_output_dir, "whois_results.json")
                if isinstance(cmd, list):
                    cmd.extend(["-l", self.temp_domains_file, "-o", output_file])
                else:
                    cmd += f" -l {self.temp_domains_file} -o {output_file}"
            
            elif tool_name == "dns":
                output_dir = os.path.join(tool_output_dir, "dns_analysis")
                if isinstance(cmd, list):
                    cmd.extend(["-f", self.temp_domains_file, "-d", output_dir])
                else:
                    cmd += f" -f {self.temp_domains_file} -d {output_dir}"
            
            elif tool_name == "coletor":
                # Copia o arquivo de domínios para o diretório do coletor
                coletor_domains = os.path.join(os.path.dirname(script_path), "dominios.txt")
                subprocess.run(["cp", self.temp_domains_file, coletor_domains])
                
                # Define diretório de saída
                if isinstance(cmd, list):
                    cmd.append(coletor_domains)
                    cmd.extend(["OUT_DIR=" + tool_output_dir])
                else:
                    cmd += f" {coletor_domains} OUT_DIR={tool_output_dir}"
            
            elif tool_name == "shodan":
                output_dir = tool_output_dir
                if isinstance(cmd, list):
                    cmd.extend([self.temp_domains_file, output_dir])
                else:
                    cmd += f" {self.temp_domains_file} {output_dir}"
            
            elif tool_name == "feed":
                # Para feeds, coletamos e enviamos diretamente para o ES
                feeds_file = os.path.join(os.path.dirname(script_path), "feeds.yaml")
                output_dir = os.path.join(tool_output_dir, "feeds")
                if isinstance(cmd, list):
                    cmd.extend(["collect-send", "--feeds-file", feeds_file, 
                               "--output-dir", output_dir, "--days", "7",
                               "--es-host", self.es_config["host"], 
                               "--es-port", str(self.es_config["port"]),
                               "--index", f"{self.index_prefix}_feed"])
                else:
                    cmd += f" collect-send --feeds-file {feeds_file} --output-dir {output_dir} --days 7 --es-host {self.es_config['host']} --es-port {self.es_config['port']} --index {self.index_prefix}_feed"
            
            elif tool_name == "telegram":
                output_dir = os.path.join(tool_output_dir, "downloads")
                if isinstance(cmd, list):
                    cmd.extend(["--limit", "10", "--ext", ".txt", "--output-dir", output_dir])
                else:
                    cmd += f" --limit 10 --ext .txt --output-dir {output_dir}"
            
            # Executa o comando
            logger.info(f"Executando: {cmd}")
            start_time = time.time()
            
            if use_shell:
                # Executa com shell e mostra output em tempo real
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                          stderr=subprocess.STDOUT, text=True, bufsize=1)
            else:
                # Executa sem shell e mostra output em tempo real
                if isinstance(cmd, list):
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1)
                else:
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            # Captura e exibe o output em tempo real
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                print(f"[{tool_name}] {line}", end='')  # Mostra na tela
                output_lines.append(line)
                
            # Aguarda o processo terminar e obtém o código de retorno
            process.stdout.close()
            return_code = process.wait()
            
            elapsed_time = time.time() - start_time
            
            # Verifica resultado
            if return_code == 0:
                logger.info(f"✅ {tool_name} executado com sucesso em {elapsed_time:.2f}s")
                
                # Encontra e envia resultados para o Elasticsearch
                self._process_tool_results(tool_name, tool_output_dir)
                
                return True
            else:
                logger.error(f"❌ {tool_name} falhou com código {return_code}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Erro ao executar {tool_name}: {e}")
            return False
    
    def _process_tool_results(self, tool_name: str, output_dir: str):
        """Processa resultados da ferramenta e envia para o Elasticsearch"""
        index_name = self.config.get("tools", {}).get(tool_name, {}).get("index", tool_name)
        
        # Garante que o índice existe
        self.create_index(index_name)
        
        # Processa resultados específicos por ferramenta
        if tool_name == "whois":
            whois_file = os.path.join(output_dir, "whois_results.json")
            if os.path.exists(whois_file):
                self.send_to_elasticsearch(index_name, whois_file)
        
        elif tool_name == "dns":
            dns_dir = os.path.join(output_dir, "dns_analysis")
            consolidated_file = None
            
            # Procura arquivo consolidado
            for file in os.listdir(dns_dir):
                if file.startswith("consolidated_") and file.endswith(".json"):
                    consolidated_file = os.path.join(dns_dir, file)
                    break
            
            if consolidated_file:
                self.send_to_elasticsearch(index_name, consolidated_file)
            else:
                # Processa arquivos individuais
                for file in os.listdir(dns_dir):
                    if file.endswith(".json") and not file.startswith("consolidated_"):
                        self.send_to_elasticsearch(index_name, os.path.join(dns_dir, file))
        
        elif tool_name == "coletor":
            # Processa resultados do coletor (diretório elk)
            # Primeiro verifica no diretório de saída específico
            elk_dir = os.path.join(output_dir, "elk")
            
            # Se não encontrar, procura no diretório padrão do projeto
            if not os.path.exists(elk_dir):
                logger.info(f"Diretório elk não encontrado em {elk_dir}, procurando em diretório alternativo...")
                elk_dir = os.path.join(self.base_dir, "out", "elk")
            
            if os.path.exists(elk_dir):
                logger.info(f"Processando arquivos do coletor em: {elk_dir}")
                for file in os.listdir(elk_dir):
                    file_path = os.path.join(elk_dir, file)
                    if file.endswith(".json") or file.endswith(".jsonl"):
                        # Verifica se o arquivo tem conteúdo
                        if os.path.getsize(file_path) > 0:
                            # Usa subíndices baseados no nome do arquivo
                            sub_index = os.path.splitext(file)[0]
                            logger.info(f"Enviando {file_path} para o índice {index_name}_{sub_index}")
                            success = self.send_to_elasticsearch(f"{index_name}_{sub_index}", file_path)
                            if success:
                                logger.info(f"✅ Arquivo {file} enviado com sucesso para {index_name}_{sub_index}")
                            else:
                                logger.error(f"❌ Falha ao enviar {file} para {index_name}_{sub_index}")
                        else:
                            logger.warning(f"Arquivo vazio ignorado: {file_path}")
            else:
                logger.error(f"❌ Nenhum diretório elk encontrado para o coletor")
        
        elif tool_name == "shodan":
            # Processa resultados do Shodan
            # Verifica múltiplos caminhos possíveis para os resultados do Shodan
            json_dirs = [
                os.path.join(output_dir, "shodan_results", "json"),  # Caminho original
                os.path.join(output_dir, "json"),                   # Caminho alternativo 1
                os.path.join(output_dir)                           # Caminho alternativo 2
            ]
            
            processed = False
            for json_dir in json_dirs:
                if os.path.exists(json_dir):
                    logger.info(f"Processando diretório Shodan: {json_dir}")
                    for file in os.listdir(json_dir):
                        if file.endswith(".json"):
                            file_path = os.path.join(json_dir, file)
                            logger.info(f"Processando arquivo Shodan: {file_path}")
                            success = self.send_to_elasticsearch(index_name, file_path)
                            if success:
                                processed = True
                                logger.info(f"✅ Arquivo {file} enviado com sucesso para {index_name}")
                            else:
                                logger.error(f"❌ Falha ao enviar {file} para {index_name}")
            
            if not processed:
                logger.error(f"❌ Nenhum arquivo JSON do Shodan encontrado nos diretórios esperados")
        
        elif tool_name == "telegram":
            # Para o Telegram, precisamos processar os arquivos baixados
            downloads_dir = os.path.join(output_dir, "downloads")
            if os.path.exists(downloads_dir):
                # Executa o script de importação para o ELK
                import_script = os.path.join(self.base_dir, "TELEGRAM/import_to_elk.py")
                if os.path.exists(import_script):
                    try:
                        # Ativa o ambiente virtual
                        venv_activate = os.path.join(self.base_dir, "telegram_venv/bin/activate") 
                        cmd = f"source {venv_activate} && python3 {import_script}"
                        cmd += f" --directory {downloads_dir}"
                        cmd += f" --host {self.es_config['host']}"
                        cmd += f" --port {self.es_config['port']}"
                        cmd += f" --index {self.index_prefix}_{index_name}"
                        cmd += f" --company \"{self.company_name}\""  # Adiciona a empresa como parâmetro
                        cmd += f" --company-slug \"{self.company_slug}\""  # Adiciona o slug da empresa
                        
                        logger.info(f"Executando importação Telegram: {cmd}")
                        # Executa com shell e mostra output em tempo real
                        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
                        
                        # Captura e exibe o output em tempo real
                        for line in iter(process.stdout.readline, ''):
                            if not line:
                                break
                            print(f"[telegram_import] {line}", end='')
                            
                        # Aguarda o processo terminar
                        process.stdout.close()
                        return_code = process.wait()
                        
                        if return_code == 0:
                            logger.info("✅ Importação Telegram concluída")
                        else:
                            logger.error(f"❌ Importação Telegram falhou com código {return_code}")
                    except Exception as e:
                        logger.error(f"❌ Erro na importação Telegram: {e}")
    
    def run_pipeline(self):
        """Executa o pipeline completo"""
        logger.info(f"🚀 Iniciando pipeline para {self.company_name}")
        
        # Conecta ao Elasticsearch
        if not self.connect_to_elasticsearch():
            logger.error("❌ Falha ao conectar ao Elasticsearch. Abortando pipeline.")
            return False
        
        # Cria índice para metadados
        self.create_index("metadata")
        
        # Envia metadados para o Elasticsearch
        metadata_file = os.path.join(self.output_dir, "metadata.json")
        self.send_to_elasticsearch("metadata", metadata_file)
        
        # Executa ferramentas na ordem especificada (sem feed e telegram)
        tools_order = ["whois", "dns", "coletor", "shodan"]
        
        for tool in tools_order:
            self.run_tool(tool)
        
        logger.info(f"✅ Pipeline concluído para {self.company_name}")
        logger.info(f"   Resultados em: {self.output_dir}")
        logger.info(f"   Índices Elasticsearch: {self.index_prefix}_*")
        logger.info(f"   Dados podem ser filtrados por company='{self.company_name}' ou company_slug='{self.company_slug}'")
        
        return True

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="ADINT Pipeline - Orquestrador de coleta e análise de inteligência")
    parser.add_argument("--company", required=True, help="Nome da empresa alvo")
    parser.add_argument("--company-slug", help="Slug/apelido da empresa (se não fornecido, será gerado a partir do nome)")
    parser.add_argument("--domains", required=True, help="Arquivo com lista de domínios (um por linha)")
    parser.add_argument("--notes", default="", help="Observações sobre a análise")
    parser.add_argument("--es-host", default="localhost", help="Host do Elasticsearch")
    parser.add_argument("--es-port", type=int, default=9200, help="Porta do Elasticsearch")
    parser.add_argument("--output-dir", default="pipeline_results", help="Diretório para armazenar resultados")
    parser.add_argument("--config", default="pipeline_config.yaml", help="Arquivo de configuração")
    
    args = parser.parse_args()
    
    # Verifica se o arquivo de domínios existe
    if not os.path.exists(args.domains):
        logger.error(f"Arquivo de domínios não encontrado: {args.domains}")
        sys.exit(1)
    
    # Determina o slug da empresa
    company_slug = args.company_slug if args.company_slug else None
    
    # Inicia o pipeline
    pipeline = ADINTPipeline(
        company_name=args.company,
        domains_file=args.domains,
        notes=args.notes,
        es_host=args.es_host,
        es_port=args.es_port,
        output_dir=args.output_dir,
        config_file=args.config,
        company_slug=company_slug
    )
    
    # Executa o pipeline
    success = pipeline.run_pipeline()
    
    # Retorna código de saída
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
