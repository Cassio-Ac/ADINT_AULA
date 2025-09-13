# Guia de Personalização do Pipeline de Análise de Superfície

Este guia fornece instruções para personalizar e estender o pipeline de análise de superfície de ataque.

## Índice

1. [Configuração Básica](#configuração-básica)
2. [Adição de Novas Ferramentas](#adição-de-novas-ferramentas)
3. [Personalização de Índices](#personalização-de-índices)
4. [Integração com Outras Fontes](#integração-com-outras-fontes)
5. [Automatização e Agendamento](#automatização-e-agendamento)

## Configuração Básica

### Arquivo de Configuração Principal

O arquivo `pipeline_config.yaml` é o ponto central de configuração do pipeline. Ele contém as seguintes seções principais:

```yaml
tools:
  # Configuração de ferramentas
  
elasticsearch:
  # Configuração do Elasticsearch
  
tool_settings:
  # Configurações específicas por ferramenta
```

### Habilitar/Desabilitar Ferramentas

Para habilitar ou desabilitar uma ferramenta, edite a propriedade `enabled` na seção correspondente:

```yaml
tools:
  whois:
    enabled: true  # Habilita a ferramenta WHOIS
    script: WHOIS/whois_universal.py
    index: whois
  
  telegram:
    enabled: false  # Desabilita a ferramenta Telegram
    script: TELEGRAM/download_Combo.py
    index: telegram
```

### Configurações Específicas por Ferramenta

A seção `tool_settings` permite configurar parâmetros específicos para cada ferramenta:

```yaml
tool_settings:
  coletor:
    threads: 20      # Número de threads para o coletor
    rate_limit: 50   # Limite de requisições por minuto
  
  shodan:
    max_results: 1000  # Número máximo de resultados do Shodan
  
  feed:
    days_to_collect: 7  # Número de dias para coletar feeds
```

## Adição de Novas Ferramentas

### Passo 1: Criar o Script da Ferramenta

Crie um novo script para a ferramenta em um diretório apropriado. O script deve:

1. Aceitar argumentos de linha de comando para entrada e saída
2. Processar os dados conforme necessário
3. Gerar saída em formato JSON

Exemplo de estrutura básica para um script Python:

```python
#!/usr/bin/env python3
import argparse
import json
import sys

def main():
    parser = argparse.ArgumentParser(description="Minha nova ferramenta")
    parser.add_argument("-l", "--list", help="Arquivo com lista de domínios")
    parser.add_argument("-o", "--output", help="Arquivo de saída JSON")
    args = parser.parse_args()
    
    # Processar os domínios
    results = process_domains(args.list)
    
    # Salvar resultados
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

def process_domains(domains_file):
    # Implementar o processamento aqui
    results = []
    with open(domains_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                # Processar o domínio
                result = {"domain": domain, "data": "exemplo"}
                results.append(result)
    return results

if __name__ == "__main__":
    main()
```

### Passo 2: Adicionar a Ferramenta à Configuração

Edite o arquivo `pipeline_config.yaml` para adicionar a nova ferramenta:

```yaml
tools:
  # ... ferramentas existentes ...
  
  minha_ferramenta:
    enabled: true
    script: MINHA_FERRAMENTA/minha_ferramenta.py
    index: minha_ferramenta
    description: "Minha nova ferramenta personalizada"
```

### Passo 3: Atualizar o Script Principal

Se necessário, modifique o script `adint_pipeline.py` para suportar a nova ferramenta. Você precisará adicionar um caso específico na função `run_tool`:

```python
# Adiciona argumentos específicos por ferramenta
if tool_name == "minha_ferramenta":
    output_file = os.path.join(tool_output_dir, "minha_ferramenta_results.json")
    if isinstance(cmd, list):
        cmd.extend(["-l", self.temp_domains_file, "-o", output_file])
    else:
        cmd += f" -l {self.temp_domains_file} -o {output_file}"
```

## Personalização de Índices

### Modificar Configurações de Índice

Para modificar as configurações padrão dos índices, edite a seção `elasticsearch.index_settings` no arquivo `pipeline_config.yaml`:

```yaml
elasticsearch:
  index_settings:
    number_of_shards: 1
    number_of_replicas: 0
    refresh_interval: "5s"
```

### Personalizar Mapeamento de Índice

Para personalizar o mapeamento de um índice específico, edite a seção `elasticsearch.template.mappings` no arquivo `pipeline_config.yaml`:

```yaml
elasticsearch:
  template:
    settings:
      index.mapping.total_fields.limit: 2000
    
    mappings:
      properties:
        # Mapeamento padrão para campos comuns
        "@timestamp":
          type: "date"
        
        # Campos personalizados para sua ferramenta
        meu_campo:
          type: "keyword"
```

### Adicionar Campos Calculados

Para adicionar campos calculados durante o processamento, modifique o método `process_results` no script `adint_pipeline.py`:

```python
def process_results(self, tool_name, results_file):
    """Processa os resultados de uma ferramenta e envia para o Elasticsearch"""
    # ... código existente ...
    
    # Adiciona campos calculados
    for doc in documents:
        # Adiciona metadados comuns
        doc["_analise_metadata"] = {
            "company": self.company_name,
            "timestamp": self.timestamp,
            "pipeline_run": self.timestamp
        }
        
        # Adiciona campos calculados específicos
        if tool_name == "minha_ferramenta":
            if "data" in doc:
                doc["data_length"] = len(doc["data"])
                doc["data_hash"] = hashlib.md5(doc["data"].encode()).hexdigest()
    
    # ... código existente ...
```

## Integração com Outras Fontes

### Integração com APIs Externas

Para integrar o pipeline com uma API externa, crie um novo script que:

1. Se conecta à API externa
2. Processa os dados recebidos
3. Gera saída em formato JSON

Exemplo de integração com uma API REST:

```python
#!/usr/bin/env python3
import argparse
import json
import requests
import sys

def main():
    parser = argparse.ArgumentParser(description="Integração com API Externa")
    parser.add_argument("-l", "--list", help="Arquivo com lista de domínios")
    parser.add_argument("-o", "--output", help="Arquivo de saída JSON")
    parser.add_argument("-k", "--api-key", help="Chave de API")
    args = parser.parse_args()
    
    # Processar os domínios
    results = query_api(args.list, args.api_key)
    
    # Salvar resultados
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

def query_api(domains_file, api_key):
    results = []
    with open(domains_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                # Consultar a API
                response = requests.get(
                    f"https://api.exemplo.com/v1/domain/{domain}",
                    headers={"Authorization": f"Bearer {api_key}"}
                )
                if response.status_code == 200:
                    data = response.json()
                    results.append({
                        "domain": domain,
                        "api_data": data
                    })
    return results

if __name__ == "__main__":
    main()
```

### Integração com Outras Ferramentas de Segurança

Para integrar com outras ferramentas de segurança, você pode:

1. Criar um script wrapper que execute a ferramenta
2. Processar a saída da ferramenta para formato JSON
3. Adicionar a ferramenta à configuração do pipeline

Exemplo de wrapper para uma ferramenta de linha de comando:

```python
#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser(description="Wrapper para Ferramenta Externa")
    parser.add_argument("-l", "--list", help="Arquivo com lista de domínios")
    parser.add_argument("-o", "--output", help="Arquivo de saída JSON")
    args = parser.parse_args()
    
    # Processar os domínios
    results = run_external_tool(args.list)
    
    # Salvar resultados
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

def run_external_tool(domains_file):
    results = []
    with open(domains_file) as f:
        for line in f:
            domain = line.strip()
            if domain:
                # Executar a ferramenta externa
                cmd = ["ferramenta_externa", "--target", domain, "--format", "json"]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode == 0:
                    try:
                        data = json.loads(proc.stdout)
                        results.append({
                            "domain": domain,
                            "tool_data": data
                        })
                    except json.JSONDecodeError:
                        print(f"Erro ao processar saída para {domain}", file=sys.stderr)
    return results

if __name__ == "__main__":
    main()
```

## Automatização e Agendamento

### Criação de Script de Agendamento

Para automatizar a execução do pipeline, você pode criar um script de agendamento:

```bash
#!/bin/bash
# Script para execução agendada do pipeline

# Configurações
COMPANY="Minha Empresa"
DOMAINS_FILE="/caminho/para/dominios.txt"
NOTES="Execução agendada $(date +'%Y-%m-%d')"
OUTPUT_DIR="/caminho/para/resultados/$(date +'%Y%m%d')"
LOG_FILE="/caminho/para/logs/pipeline_$(date +'%Y%m%d_%H%M%S').log"

# Cria diretório de saída
mkdir -p "$OUTPUT_DIR"

# Executa o pipeline
cd /caminho/para/adint-pipeline
./run_pipeline.sh -c "$COMPANY" -d "$DOMAINS_FILE" -n "$NOTES" -o "$OUTPUT_DIR" > "$LOG_FILE" 2>&1

# Verifica resultado
if [ $? -eq 0 ]; then
    echo "Pipeline concluído com sucesso em $(date +'%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    # Opcional: enviar notificação de sucesso
    # mail -s "Pipeline concluído com sucesso" usuario@exemplo.com < "$LOG_FILE"
else
    echo "Pipeline falhou em $(date +'%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    # Opcional: enviar notificação de falha
    # mail -s "Pipeline falhou" usuario@exemplo.com < "$LOG_FILE"
fi
```

### Configuração de Cron Job

Para agendar a execução regular do pipeline, adicione uma entrada ao crontab:

```bash
# Editar crontab
crontab -e
```

Adicione uma linha como esta para executar o pipeline semanalmente (domingo às 2h da manhã):

```
0 2 * * 0 /caminho/para/script_agendamento.sh
```

### Integração com Sistemas de CI/CD

Para integrar com sistemas de CI/CD como Jenkins, GitLab CI ou GitHub Actions, crie um arquivo de configuração apropriado.

Exemplo para GitHub Actions:

```yaml
name: ADINT Pipeline

on:
  schedule:
    - cron: '0 2 * * 0'  # Executa todo domingo às 2h da manhã
  workflow_dispatch:     # Permite execução manual

jobs:
  run-pipeline:
    runs-on: ubuntu-latest
    
    services:
      elasticsearch:
        image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
        env:
          discovery.type: single-node
          xpack.security.enabled: false
        ports:
          - 9200:9200
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      
      - name: Run pipeline
        run: |
          ./run_pipeline.sh -c "Minha Empresa" -d dominios.txt -n "Execução automatizada GitHub Actions"
      
      - name: Archive results
        uses: actions/upload-artifact@v2
        with:
          name: pipeline-results
          path: pipeline_results/
```

### Monitoramento e Alertas

Para monitorar a execução do pipeline e receber alertas, você pode:

1. Configurar alertas no Elasticsearch/Kibana
2. Integrar com sistemas de monitoramento como Prometheus/Grafana
3. Enviar notificações por email, Slack, etc.

Exemplo de script para enviar notificação por Slack:

```python
#!/usr/bin/env python3
import argparse
import json
import requests
import sys

def main():
    parser = argparse.ArgumentParser(description="Notificação para Slack")
    parser.add_argument("-w", "--webhook", required=True, help="URL do webhook do Slack")
    parser.add_argument("-c", "--company", required=True, help="Nome da empresa")
    parser.add_argument("-s", "--status", required=True, choices=["success", "failure"], help="Status da execução")
    args = parser.parse_args()
    
    # Constrói a mensagem
    if args.status == "success":
        color = "#36a64f"  # Verde
        title = f"✅ Pipeline concluído com sucesso para {args.company}"
    else:
        color = "#ff0000"  # Vermelho
        title = f"❌ Pipeline falhou para {args.company}"
    
    # Envia a notificação
    payload = {
        "attachments": [
            {
                "color": color,
                "title": title,
                "text": f"Execução em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "fields": [
                    {
                        "title": "Empresa",
                        "value": args.company,
                        "short": True
                    },
                    {
                        "title": "Status",
                        "value": args.status.capitalize(),
                        "short": True
                    }
                ]
            }
        ]
    }
    
    response = requests.post(args.webhook, json=payload)
    if response.status_code != 200:
        print(f"Erro ao enviar notificação: {response.status_code} {response.text}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```
