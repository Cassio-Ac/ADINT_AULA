# Guia de Troubleshooting do Pipeline de Análise de Superfície

Este guia fornece soluções para problemas comuns que podem ocorrer durante a execução do pipeline de análise de superfície de ataque.

## Índice

1. [Problemas de Conexão](#problemas-de-conexão)
2. [Problemas com Ferramentas](#problemas-com-ferramentas)
3. [Problemas com Elasticsearch](#problemas-com-elasticsearch)
4. [Problemas com Dados](#problemas-com-dados)
5. [Problemas com o Telegram](#problemas-com-o-telegram)
6. [Logs e Diagnóstico](#logs-e-diagnóstico)

## Problemas de Conexão

### Erro de Conexão com Elasticsearch

**Sintoma**: Mensagem de erro indicando falha na conexão com o Elasticsearch.

```
ConnectionError: Cannot connect to host localhost:9200
```

**Possíveis Causas**:
1. Elasticsearch não está em execução
2. Host ou porta incorretos
3. Firewall bloqueando a conexão
4. Configurações de segurança do Elasticsearch

**Soluções**:

1. **Verificar se o Elasticsearch está em execução**:
   ```bash
   curl http://localhost:9200
   ```
   
   Se não estiver em execução, inicie-o:
   ```bash
   # Se instalado localmente
   sudo systemctl start elasticsearch
   
   # Se usando Docker
   docker start elasticsearch
   ```

2. **Verificar host e porta**:
   Edite o comando para especificar o host e porta corretos:
   ```bash
   ./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt -h elasticsearch.local -p 9200
   ```

3. **Verificar firewall**:
   ```bash
   # Ubuntu/Debian
   sudo ufw status
   
   # CentOS/RHEL
   sudo firewall-cmd --list-all
   ```
   
   Se necessário, abra a porta:
   ```bash
   # Ubuntu/Debian
   sudo ufw allow 9200/tcp
   
   # CentOS/RHEL
   sudo firewall-cmd --permanent --add-port=9200/tcp
   sudo firewall-cmd --reload
   ```

4. **Verificar configurações de segurança**:
   Se o Elasticsearch estiver configurado com autenticação, você precisará fornecer credenciais. Edite o arquivo `pipeline_config.yaml`:
   ```yaml
   elasticsearch:
     auth:
       username: "elastic"
       password: "sua_senha"
   ```

### Erro de Conexão com API Externa

**Sintoma**: Mensagem de erro indicando falha na conexão com uma API externa (Shodan, etc.).

**Possíveis Causas**:
1. Problemas de rede
2. API key inválida ou expirada
3. Limite de requisições excedido

**Soluções**:

1. **Verificar conectividade**:
   ```bash
   ping api.shodan.io
   ```

2. **Verificar API key**:
   ```bash
   shodan info
   ```
   
   Se necessário, configure novamente:
   ```bash
   shodan init YOUR_API_KEY
   ```

3. **Verificar limites de requisições**:
   Muitas APIs têm limites de requisições. Verifique sua conta e, se necessário, reduza a frequência de consultas ou atualize para um plano com limites maiores.

## Problemas com Ferramentas

### Ferramenta não Encontrada

**Sintoma**: Mensagem de erro indicando que uma ferramenta não foi encontrada.

```
Script não encontrado: /caminho/para/ferramenta.py
```

**Possíveis Causas**:
1. Caminho incorreto no arquivo de configuração
2. Ferramenta não instalada
3. Permissões incorretas

**Soluções**:

1. **Verificar caminho no arquivo de configuração**:
   Edite o arquivo `pipeline_config.yaml` e verifique se o caminho está correto:
   ```yaml
   tools:
     ferramenta:
       script: CAMINHO/CORRETO/ferramenta.py
   ```

2. **Instalar a ferramenta**:
   Siga as instruções de instalação na documentação da ferramenta.

3. **Verificar permissões**:
   ```bash
   chmod +x CAMINHO/PARA/ferramenta.py
   ```

### Erro na Execução de uma Ferramenta

**Sintoma**: Uma ferramenta é executada, mas falha com um erro.

**Possíveis Causas**:
1. Dependências ausentes
2. Configuração incorreta
3. Erro no script

**Soluções**:

1. **Verificar dependências**:
   ```bash
   # Para scripts Python
   pip install -r requirements.txt
   
   # Para scripts shell
   ldd $(which comando)
   ```

2. **Verificar configuração**:
   Verifique se todas as configurações necessárias estão corretas.

3. **Executar a ferramenta manualmente**:
   Execute a ferramenta manualmente para identificar o problema:
   ```bash
   python3 FERRAMENTA/ferramenta.py -l dominios.txt -o saida.json
   ```

### Ferramenta Muito Lenta

**Sintoma**: Uma ferramenta está demorando muito para ser executada.

**Possíveis Causas**:
1. Muitos domínios para processar
2. Configuração inadequada
3. Limitações de recursos

**Soluções**:

1. **Reduzir o número de domínios**:
   Use um arquivo de domínios menor para teste.

2. **Ajustar configurações**:
   Edite o arquivo `pipeline_config.yaml` para ajustar configurações específicas da ferramenta:
   ```yaml
   tool_settings:
     ferramenta:
       threads: 10  # Reduzir número de threads
       timeout: 5   # Reduzir timeout
   ```

3. **Aumentar recursos**:
   Se possível, aumente a memória ou CPU disponíveis para a execução.

## Problemas com Elasticsearch

### Índice não Criado

**Sintoma**: O índice não é criado no Elasticsearch.

**Possíveis Causas**:
1. Erro na criação do índice
2. Permissões insuficientes
3. Configuração incorreta

**Soluções**:

1. **Verificar logs**:
   Verifique os logs do pipeline para identificar erros na criação do índice.

2. **Verificar permissões**:
   Certifique-se de que o usuário tem permissões para criar índices:
   ```bash
   curl -X GET "localhost:9200/_security/user/current" -u "username:password"
   ```

3. **Criar o índice manualmente**:
   ```bash
   curl -X PUT "localhost:9200/analise_superficie_empresa_indice" -H 'Content-Type: application/json' -d'
   {
     "settings": {
       "number_of_shards": 1,
       "number_of_replicas": 0
     }
   }'
   ```

### Erro de Mapeamento

**Sintoma**: Erro ao indexar documentos devido a problemas de mapeamento.

```
mapper_parsing_exception: failed to parse field [campo] of type [tipo]
```

**Possíveis Causas**:
1. Tipo de campo incompatível
2. Mapeamento dinâmico inadequado
3. Campo com múltiplos tipos

**Soluções**:

1. **Verificar o mapeamento atual**:
   ```bash
   curl -X GET "localhost:9200/analise_superficie_empresa_indice/_mapping"
   ```

2. **Atualizar o mapeamento**:
   ```bash
   curl -X PUT "localhost:9200/analise_superficie_empresa_indice/_mapping" -H 'Content-Type: application/json' -d'
   {
     "properties": {
       "campo_problematico": {
         "type": "text",
         "fields": {
           "keyword": {
             "type": "keyword",
             "ignore_above": 256
           }
         }
       }
     }
   }'
   ```

3. **Recriar o índice**:
   Se o mapeamento não puder ser atualizado, recrie o índice:
   ```bash
   # Criar novo índice com mapeamento correto
   curl -X PUT "localhost:9200/analise_superficie_empresa_indice_new" -H 'Content-Type: application/json' -d'
   {
     "mappings": {
       "properties": {
         "campo_problematico": {
           "type": "text"
         }
       }
     }
   }'
   
   # Reindexar dados
   curl -X POST "localhost:9200/_reindex" -H 'Content-Type: application/json' -d'
   {
     "source": {
       "index": "analise_superficie_empresa_indice"
     },
     "dest": {
       "index": "analise_superficie_empresa_indice_new"
     }
   }'
   
   # Excluir índice antigo
   curl -X DELETE "localhost:9200/analise_superficie_empresa_indice"
   
   # Criar alias
   curl -X POST "localhost:9200/_aliases" -H 'Content-Type: application/json' -d'
   {
     "actions": [
       {
         "add": {
           "index": "analise_superficie_empresa_indice_new",
           "alias": "analise_superficie_empresa_indice"
         }
       }
     ]
   }'
   ```

### Erro de Bulk Indexing

**Sintoma**: Erro ao indexar documentos em lote.

```
bulk_reject_message: rejected execution of bulk
```

**Possíveis Causas**:
1. Lote muito grande
2. Recursos insuficientes no Elasticsearch
3. Timeout durante a indexação

**Soluções**:

1. **Reduzir o tamanho do lote**:
   Edite o arquivo `pipeline_config.yaml` para reduzir o tamanho do lote:
   ```yaml
   elasticsearch:
     bulk_size: 500  # Reduzir de 1000 para 500
   ```

2. **Aumentar recursos do Elasticsearch**:
   ```bash
   # Editar configuração do Elasticsearch
   sudo nano /etc/elasticsearch/elasticsearch.yml
   
   # Adicionar/modificar configurações
   thread_pool.write.queue_size: 1000
   ```

3. **Aumentar timeout**:
   Edite o arquivo `pipeline_config.yaml` para aumentar o timeout:
   ```yaml
   elasticsearch:
     timeout: 60  # Aumentar de 30 para 60 segundos
   ```

## Problemas com Dados

### Dados Ausentes

**Sintoma**: Alguns dados esperados não estão presentes nos resultados.

**Possíveis Causas**:
1. Falha na coleta de dados
2. Filtros aplicados incorretamente
3. Dados não disponíveis na fonte

**Soluções**:

1. **Verificar logs**:
   Verifique os logs do pipeline para identificar falhas na coleta de dados.

2. **Verificar filtros**:
   Certifique-se de que não há filtros inadvertidamente excluindo dados:
   ```bash
   # Verificar configuração
   cat pipeline_config.yaml
   
   # Verificar arquivo de domínios
   cat dominios.txt
   ```

3. **Verificar disponibilidade dos dados**:
   Tente coletar os dados manualmente para confirmar que estão disponíveis na fonte.

### Dados Duplicados

**Sintoma**: Alguns dados aparecem duplicados nos resultados.

**Possíveis Causas**:
1. Múltiplas execuções do pipeline
2. Falha na detecção de duplicatas
3. Configuração incorreta

**Soluções**:

1. **Verificar índices existentes**:
   ```bash
   curl -X GET "localhost:9200/_cat/indices/analise_superficie_*"
   ```

2. **Remover duplicatas**:
   ```bash
   # Usar um script de deduplicação
   python3 deduplicate.py --index analise_superficie_empresa_indice --field id
   ```

3. **Adicionar verificação de duplicatas**:
   Edite o arquivo `pipeline_config.yaml` para adicionar verificação de duplicatas:
   ```yaml
   elasticsearch:
     deduplication:
       enabled: true
       fields: ["domain", "ip"]
   ```

### Dados Incorretos

**Sintoma**: Alguns dados nos resultados estão incorretos.

**Possíveis Causas**:
1. Erro na coleta de dados
2. Erro no processamento de dados
3. Dados incorretos na fonte

**Soluções**:

1. **Verificar fonte de dados**:
   Confirme que os dados estão corretos na fonte.

2. **Verificar processamento**:
   Verifique se há erros no processamento dos dados:
   ```bash
   # Executar ferramenta manualmente
   python3 FERRAMENTA/ferramenta.py -l dominios.txt -o saida.json
   
   # Verificar resultado
   cat saida.json
   ```

3. **Corrigir dados**:
   Se necessário, corrija os dados manualmente:
   ```bash
   curl -X POST "localhost:9200/analise_superficie_empresa_indice/_update_by_query" -H 'Content-Type: application/json' -d'
   {
     "script": {
       "source": "ctx._source.campo_incorreto = params.valor_correto",
       "params": {
         "valor_correto": "valor_correto"
       }
     },
     "query": {
       "term": {
         "id": "documento_id"
       }
     }
   }'
   ```

## Problemas com o Telegram

### Erro de Autenticação

**Sintoma**: Erro ao autenticar com a API do Telegram.

```
AuthorizationError: You're not authorized to use this API
```

**Possíveis Causas**:
1. API ID ou hash incorretos
2. Sessão expirada
3. Conta limitada pelo Telegram

**Soluções**:

1. **Verificar API ID e hash**:
   Edite o arquivo de configuração do Telegram e verifique se os valores estão corretos.

2. **Reautenticar**:
   Execute o script de autenticação novamente:
   ```bash
   python3 TELEGRAM/auth.py
   ```

3. **Criar nova aplicação**:
   Se a conta estiver limitada, crie uma nova aplicação em https://my.telegram.org/apps.

### Erro ao Baixar Arquivos

**Sintoma**: Erro ao baixar arquivos do Telegram.

```
FloodWaitError: A wait of X seconds is required
```

**Possíveis Causas**:
1. Limite de requisições excedido
2. Arquivos muito grandes
3. Problemas de permissão

**Soluções**:

1. **Aguardar o tempo indicado**:
   O Telegram impõe limites de requisições. Aguarde o tempo indicado e tente novamente.

2. **Reduzir o número de downloads**:
   Edite o arquivo `pipeline_config.yaml` para reduzir o número de downloads:
   ```yaml
   tool_settings:
     telegram:
       max_files: 5  # Reduzir de 10 para 5
   ```

3. **Verificar permissões**:
   Certifique-se de que sua conta tem permissão para baixar arquivos do canal.

### Erro ao Processar Arquivos

**Sintoma**: Erro ao processar arquivos baixados do Telegram.

**Possíveis Causas**:
1. Arquivo corrompido
2. Formato não suportado
3. Arquivo muito grande

**Soluções**:

1. **Verificar integridade do arquivo**:
   ```bash
   file ARQUIVO
   ```

2. **Verificar formato**:
   Certifique-se de que o formato do arquivo é suportado pelo processador.

3. **Processar manualmente**:
   Tente processar o arquivo manualmente:
   ```bash
   python3 TELEGRAM/process_file.py --file ARQUIVO --output saida.json
   ```

## Logs e Diagnóstico

### Ativar Logs Detalhados

Para ativar logs detalhados, use a opção `--verbose`:

```bash
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt --verbose
```

Ou edite o arquivo `pipeline_config.yaml`:

```yaml
logging:
  level: DEBUG
  file: pipeline.log
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

### Verificar Logs

Os logs do pipeline são armazenados no arquivo `adint_pipeline.log`. Você pode verificá-los com:

```bash
# Ver logs completos
cat adint_pipeline.log

# Ver apenas erros
grep ERROR adint_pipeline.log

# Ver logs de uma ferramenta específica
grep "FERRAMENTA" adint_pipeline.log
```

### Diagnóstico do Elasticsearch

Para diagnosticar problemas no Elasticsearch:

```bash
# Verificar saúde do cluster
curl -X GET "localhost:9200/_cluster/health?pretty"

# Verificar alocação de shards
curl -X GET "localhost:9200/_cat/shards?v"

# Verificar uso de disco
curl -X GET "localhost:9200/_cat/allocation?v"

# Verificar índices
curl -X GET "localhost:9200/_cat/indices?v"

# Verificar nós
curl -X GET "localhost:9200/_cat/nodes?v"
```

### Diagnóstico de Rede

Para diagnosticar problemas de rede:

```bash
# Verificar conectividade
ping host

# Verificar portas abertas
nc -zv host porta

# Verificar rota
traceroute host

# Verificar DNS
dig dominio
```

### Diagnóstico de Recursos

Para diagnosticar problemas de recursos:

```bash
# Verificar uso de CPU
top

# Verificar uso de memória
free -h

# Verificar uso de disco
df -h

# Verificar processos
ps aux | grep python
```

### Reiniciar Serviços

Se necessário, reinicie os serviços:

```bash
# Reiniciar Elasticsearch
sudo systemctl restart elasticsearch

# Reiniciar Kibana
sudo systemctl restart kibana

# Reiniciar Docker (se usando containers)
docker restart elasticsearch kibana
```

### Limpar Dados

Para limpar dados e começar do zero:

```bash
# Excluir índices
curl -X DELETE "localhost:9200/analise_superficie_empresa_*"

# Limpar diretório de resultados
rm -rf pipeline_results/*

# Limpar arquivos temporários
rm -rf temp/*
```
