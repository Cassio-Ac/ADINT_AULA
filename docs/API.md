# Documentação da API do Pipeline de Análise de Superfície

Este documento descreve a API do pipeline de análise de superfície de ataque, incluindo os principais módulos, classes e funções.

## Visão Geral da API

O pipeline de análise de superfície é implementado como um conjunto de módulos Python que interagem entre si para coletar, processar e analisar informações de segurança. O script principal `adint_pipeline.py` contém a classe `AdintPipeline`, que orquestra todo o processo.

## Classe Principal: AdintPipeline

### Inicialização

```python
class AdintPipeline:
    def __init__(self, company_name, domains_file, notes=None, es_host="localhost", 
                 es_port=9200, output_dir="pipeline_results", config_file="pipeline_config.yaml"):
        """
        Inicializa o pipeline de análise de superfície.
        
        Args:
            company_name (str): Nome da empresa alvo
            domains_file (str): Caminho para o arquivo com lista de domínios
            notes (str, opcional): Observações sobre a análise
            es_host (str, opcional): Host do Elasticsearch
            es_port (int, opcional): Porta do Elasticsearch
            output_dir (str, opcional): Diretório para armazenar resultados
            config_file (str, opcional): Caminho para o arquivo de configuração
        """
```

### Métodos Principais

#### Configuração

```python
def _load_config(self, config_file):
    """
    Carrega a configuração do pipeline a partir de um arquivo YAML.
    
    Args:
        config_file (str): Caminho para o arquivo de configuração
        
    Returns:
        dict: Configuração carregada
    """
```

#### Execução de Ferramentas

```python
def run_tool(self, tool_name):
    """
    Executa uma ferramenta específica do pipeline.
    
    Args:
        tool_name (str): Nome da ferramenta a ser executada
        
    Returns:
        bool: True se a execução foi bem-sucedida, False caso contrário
    """
```

#### Processamento de Resultados

```python
def process_results(self, tool_name, results_file):
    """
    Processa os resultados de uma ferramenta e envia para o Elasticsearch.
    
    Args:
        tool_name (str): Nome da ferramenta
        results_file (str): Caminho para o arquivo de resultados
        
    Returns:
        tuple: (documentos processados, documentos com erro)
    """
```

#### Execução do Pipeline

```python
def run_pipeline(self):
    """
    Executa o pipeline completo.
    
    Returns:
        bool: True se a execução foi bem-sucedida, False caso contrário
    """
```

## Fluxo de Execução

O fluxo de execução do pipeline segue estas etapas:

1. **Inicialização**:
   - Carrega a configuração
   - Prepara o ambiente (diretórios, arquivos temporários)
   - Configura o Elasticsearch

2. **Preparação**:
   - Cria índices no Elasticsearch
   - Armazena metadados da execução

3. **Execução de Ferramentas**:
   - Para cada ferramenta habilitada:
     - Executa a ferramenta com os parâmetros apropriados
     - Processa os resultados
     - Envia para o Elasticsearch

4. **Finalização**:
   - Limpa arquivos temporários
   - Registra o fim da execução

## Interação com Ferramentas

### Execução de Ferramentas

O método `run_tool` executa uma ferramenta específica do pipeline:

```python
def run_tool(self, tool_name):
    # Obtém configuração da ferramenta
    tool_config = self.config.get("tools", {}).get(tool_name)
    
    # Verifica se a ferramenta está habilitada
    if not tool_config.get("enabled", False):
        return True
    
    # Obtém o caminho do script
    script_path = os.path.join(self.base_dir, tool_config.get("script", ""))
    
    # Determina o comando com base na extensão do script
    if script_path.endswith('.py'):
        cmd = ["python3", script_path]
    elif script_path.endswith('.sh'):
        cmd = ["bash", script_path]
    
    # Adiciona argumentos específicos por ferramenta
    # ...
    
    # Executa o comando
    proc = subprocess.Popen(cmd, ...)
    
    # Processa a saída
    # ...
    
    # Processa os resultados
    if os.path.exists(output_file):
        self.process_results(tool_name, output_file)
    
    return True
```

### Processamento de Resultados

O método `process_results` processa os resultados de uma ferramenta e envia para o Elasticsearch:

```python
def process_results(self, tool_name, results_file):
    # Carrega os resultados do arquivo
    with open(results_file, "r") as f:
        data = json.load(f)
    
    # Determina o índice
    index_name = f"{self.index_prefix}_{tool_config.get('index', tool_name)}"
    
    # Prepara os documentos
    documents = []
    if isinstance(data, list):
        documents = data
    elif isinstance(data, dict):
        # Caso especial para cada ferramenta
        # ...
    
    # Adiciona metadados
    for doc in documents:
        doc["_analise_metadata"] = {
            "company": self.company_name,
            "timestamp": self.timestamp,
            "pipeline_run": self.timestamp
        }
    
    # Envia para o Elasticsearch
    success, failed = self._bulk_index(index_name, documents)
    
    return success, failed
```

## Interação com Elasticsearch

### Criação de Índices

O método `_create_index` cria um índice no Elasticsearch com as configurações apropriadas:

```python
def _create_index(self, index_name, mappings=None):
    """
    Cria um índice no Elasticsearch se ele não existir.
    
    Args:
        index_name (str): Nome do índice
        mappings (dict, opcional): Mapeamento personalizado
        
    Returns:
        bool: True se o índice foi criado ou já existia, False caso contrário
    """
    # Verifica se o índice já existe
    if self.es.indices.exists(index=index_name):
        return True
    
    # Prepara as configurações do índice
    settings = self.config.get("elasticsearch", {}).get("index_settings", {})
    
    # Prepara o mapeamento
    index_mappings = mappings or {}
    if not mappings:
        # Usa o mapeamento padrão do template
        template_mappings = self.config.get("elasticsearch", {}).get("template", {}).get("mappings", {})
        if template_mappings:
            index_mappings = template_mappings
    
    # Cria o índice
    try:
        self.es.indices.create(
            index=index_name,
            body={
                "settings": settings,
                "mappings": index_mappings
            }
        )
        return True
    except Exception as e:
        logger.error(f"Erro ao criar índice {index_name}: {e}")
        return False
```

### Indexação em Lote

O método `_bulk_index` envia documentos para o Elasticsearch em lote:

```python
def _bulk_index(self, index_name, documents):
    """
    Envia documentos para o Elasticsearch em lote.
    
    Args:
        index_name (str): Nome do índice
        documents (list): Lista de documentos a serem indexados
        
    Returns:
        tuple: (documentos indexados com sucesso, documentos com erro)
    """
    if not documents:
        return 0, 0
    
    # Prepara o lote
    actions = []
    for doc in documents:
        action = {
            "_index": index_name,
            "_source": doc
        }
        actions.append(action)
    
    # Envia o lote
    try:
        success, failed = helpers.bulk(
            self.es,
            actions,
            stats_only=True
        )
        return success, failed
    except Exception as e:
        logger.error(f"Erro ao indexar documentos em {index_name}: {e}")
        return 0, len(documents)
```

## Personalização da API

### Adição de Novas Ferramentas

Para adicionar uma nova ferramenta ao pipeline, você precisa:

1. Criar o script da ferramenta
2. Adicionar a ferramenta à configuração
3. Adicionar um caso específico no método `run_tool`
4. Adicionar um caso específico no método `process_results` (se necessário)

### Extensão da Classe Principal

Para estender a classe `AdintPipeline`, você pode:

1. Criar uma subclasse que herda de `AdintPipeline`
2. Sobrescrever os métodos que deseja personalizar
3. Adicionar novos métodos conforme necessário

Exemplo:

```python
class CustomAdintPipeline(AdintPipeline):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Inicialização personalizada
    
    def run_tool(self, tool_name):
        # Lógica personalizada para ferramentas específicas
        if tool_name == "minha_ferramenta_personalizada":
            # Lógica específica
            return True
        
        # Caso contrário, usa a implementação padrão
        return super().run_tool(tool_name)
    
    def custom_method(self):
        # Novo método personalizado
        pass
```

## Exemplos de Uso

### Uso Básico

```python
from adint_pipeline import AdintPipeline

# Inicializa o pipeline
pipeline = AdintPipeline(
    company_name="Minha Empresa",
    domains_file="dominios.txt",
    notes="Análise de segurança"
)

# Executa o pipeline completo
success = pipeline.run_pipeline()

if success:
    print("Pipeline concluído com sucesso!")
else:
    print("Pipeline falhou.")
```

### Execução de Ferramentas Específicas

```python
from adint_pipeline import AdintPipeline

# Inicializa o pipeline
pipeline = AdintPipeline(
    company_name="Minha Empresa",
    domains_file="dominios.txt"
)

# Executa apenas ferramentas específicas
pipeline.run_tool("whois")
pipeline.run_tool("dns")
```

### Processamento Manual de Resultados

```python
from adint_pipeline import AdintPipeline

# Inicializa o pipeline
pipeline = AdintPipeline(
    company_name="Minha Empresa",
    domains_file="dominios.txt"
)

# Processa resultados manualmente
success, failed = pipeline.process_results("whois", "resultados_whois.json")
print(f"Documentos indexados: {success}, Falhas: {failed}")
```
