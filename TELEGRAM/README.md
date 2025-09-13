# Vazamentos para ELK - Documentação

Este projeto contém scripts para processar arquivos de vazamentos de dados e enviá-los para o Elasticsearch.

## Requisitos

- Python 3.x
- Elasticsearch
- Dependências Python: elasticsearch, tqdm

## Estrutura do Projeto

- `upload_to_elk.py`: Script principal para processar os arquivos e enviar para o Elasticsearch
- `run_upload.sh`: Script de conveniência para executar o upload
- `downloads_omega_cloud/`: Diretório contendo os arquivos de vazamentos
- `telegram_venv/`: Ambiente virtual Python com as dependências instaladas

## Como Usar

### Configuração

1. Certifique-se de que o Elasticsearch está rodando
2. Ajuste as configurações no script `run_upload.sh` se necessário:
   - `ELK_HOST`: Host do Elasticsearch (padrão: localhost)
   - `ELK_PORT`: Porta do Elasticsearch (padrão: 9200)
   - `ELK_USER`: Usuário do Elasticsearch (opcional)
   - `ELK_PASSWORD`: Senha do Elasticsearch (opcional)
   - `ELK_INDEX`: Nome do índice no Elasticsearch (padrão: vazamentos)
   - `BATCH_SIZE`: Tamanho do lote para upload (padrão: 1000)
   - `DIRECTORY`: Diretório com os arquivos (padrão: downloads_omega_cloud)

### Execução

```bash
./run_upload.sh
```

Ou execute o script Python diretamente:

```bash
source ../telegram_venv/bin/activate
python upload_to_elk.py --host localhost --port 9200 --index vazamentos
```

### Parâmetros do Script Python

```
usage: upload_to_elk.py [-h] [--host HOST] [--port PORT] [--user USER]
                        [--password PASSWORD] [--index INDEX] [--batch BATCH]
                        [--directory DIRECTORY]

Upload de dados para o Elasticsearch

options:
  -h, --help            show this help message and exit
  --host HOST           Host do Elasticsearch
  --port PORT           Porta do Elasticsearch
  --user USER           Usuário do Elasticsearch
  --password PASSWORD   Senha do Elasticsearch
  --index INDEX         Nome do índice no Elasticsearch
  --batch BATCH         Tamanho do lote para upload
  --directory DIRECTORY
                        Diretório com os arquivos
```

## Estrutura dos Dados no Elasticsearch

Cada documento no Elasticsearch terá a seguinte estrutura:

```json
{
  "id": "hash_md5_do_arquivo_e_linha",
  "linha": "conteúdo_da_linha_original",
  "arquivo_origem": "nome_do_arquivo"
}
```

O script filtra apenas linhas que contenham `:` ou `|`, que são as divisórias das colunas nos arquivos de vazamento.

## Logs

Os logs são salvos no arquivo `elk_upload.log` e também exibidos no console durante a execução.
