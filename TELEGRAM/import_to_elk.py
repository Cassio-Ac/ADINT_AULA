#!/usr/bin/env python3
"""
Script para importar dados de vazamentos para o Elasticsearch.
Lê arquivos da pasta downloads_omega_cloud e envia linhas que contêm ':' ou '|' para o ELK.
"""

import os
import sys
import glob
import uuid
from elasticsearch import Elasticsearch
from tqdm import tqdm
import logging
import re


# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("import_to_elk.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def normalizar_nome_arquivo(nome):
    # Converte para minúsculo
    nome = nome.lower()
    # Substitui espaços e caracteres especiais por underline
    nome = re.sub(r'[^a-z0-9._-]+', '_', nome)
    # Remove múltiplos underlines ou pontos repetidos
    nome = re.sub(r'[_]+', '_', nome)
    nome = re.sub(r'[.]+', '.', nome)
    # Remove underlines do início/fim
    nome = nome.strip('_')
    return nome

# Configuração do Elasticsearch
ES_HOST = "localhost"
ES_PORT = 9200
ES_INDEX = "vazamentos_dados"

def connect_to_elasticsearch():
    """Conecta ao Elasticsearch e retorna o cliente."""
    try:
        es = Elasticsearch([f"http://{ES_HOST}:{ES_PORT}"])
        if not es.ping():
            logger.error("Não foi possível conectar ao Elasticsearch")
            sys.exit(1)
        return es
    except Exception as e:
        logger.error(f"Erro ao conectar ao Elasticsearch: {e}")
        sys.exit(1)

def create_index(es):
    """Cria o índice se não existir."""
    try:
        if not es.indices.exists(index=ES_INDEX):
            mapping = {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "linha": {"type": "text"},
                        "arquivo_origem": {"type": "keyword"}
                    }
                }
            }
            es.indices.create(index=ES_INDEX, body=mapping)
            logger.info(f"Índice '{ES_INDEX}' criado com sucesso")
        else:
            logger.info(f"Índice '{ES_INDEX}' já existe")
    except Exception as e:
        logger.error(f"Erro ao criar índice: {e}")
        sys.exit(1)

def process_file(es, file_path):
    """Processa um arquivo e envia linhas relevantes para o Elasticsearch."""
    try:
        # Obtém o nome do arquivo sem o caminho completo
        arquivo_origem = os.path.basename(file_path)
        arquivo_origem = normalizar_nome_arquivo(arquivo_origem)
        
        # Conta o número de linhas para a barra de progresso
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for _ in f)
        
        # Processa o arquivo
        processed = 0
        inserted = 0
        bulk_data = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in tqdm(f, total=total_lines, desc=f"Processando {arquivo_origem}"):
                processed += 1
                
                # Filtra apenas linhas que contêm ':' ou '|'
                if ':' in line or '|' in line:
                    # Remove espaços em branco extras e quebras de linha
                    line = line.strip()
                    
                    # Cria documento para o Elasticsearch
                    doc = {
                        "id": str(uuid.uuid4()),
                        "linha": line,
                        "arquivo_origem": arquivo_origem
                    }
                    
                    # Adiciona à lista para inserção em lote
                    bulk_data.append({"index": {"_index": ES_INDEX}})
                    bulk_data.append(doc)
                    inserted += 1
                    
                    # Insere em lotes de 1000 documentos
                    if len(bulk_data) >= 2000:
                        es.bulk(index=ES_INDEX, body=bulk_data)
                        bulk_data = []
            
            # Insere o restante dos documentos
            if bulk_data:
                es.bulk(index=ES_INDEX, body=bulk_data)
        
        logger.info(f"Arquivo {arquivo_origem}: {processed} linhas processadas, {inserted} inseridas no Elasticsearch")
        return inserted
    
    except Exception as e:
        logger.error(f"Erro ao processar arquivo {file_path}: {e}")
        return 0

def main():
    """Função principal."""
    # Conecta ao Elasticsearch
    es = connect_to_elasticsearch()
    
    # Cria o índice
    create_index(es)
    
    # Obtém a lista de arquivos
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads_omega_cloud")
    files = glob.glob(os.path.join(data_dir, "*.txt"))
    
    if not files:
        logger.error(f"Nenhum arquivo encontrado em {data_dir}")
        sys.exit(1)
    
    logger.info(f"Encontrados {len(files)} arquivos para processar")
    
    # Processa cada arquivo
    total_inserted = 0
    for file_path in files:
        inserted = process_file(es, file_path)
        total_inserted += inserted
    
    logger.info(f"Processamento concluído. Total de {total_inserted} linhas inseridas no Elasticsearch")

if __name__ == "__main__":
    main()
