#!/usr/bin/env python3
"""
ADINT Pipeline — orquestrador da coleta de superfície de ataque
===============================================================

O QUE ELE FAZ (e o que ele NÃO faz)
-----------------------------------
Este script é o maestro, não o músico. Ele não consulta WHOIS, DNS nem Shodan:

  1. lê o `pipeline_config.yaml` — quais etapas existem, quais estão
     habilitadas, qual script cada uma roda e em qual índice o resultado cai;
  2. executa cada etapa habilitada, em ordem, como um subprocesso;
  3. lê o JSON/JSONL que a etapa deixou em disco, acrescenta a identificação da
     empresa + o carimbo da execução, e indexa no Elasticsearch.

Quem coleta de verdade são os scripts de `WHOIS/`, `DNS/`, `COLETOR/`,
`SHODAN/`, `FEED/` e `TELEGRAM/`. Todos rodam sozinhos, sem o orquestrador —
é assim que se aprende o que cada um faz (README, "Uma etapa por vez").

USO
---
    cd <caminho-do-projeto>        # o cd importa: veja "ONDE RODAR"

    python3 adint_pipeline.py --company "Minha Empresa" --company-slug minhaempresa \
        --domains dominios.txt --es-host localhost --es-port 9200 \
        --output-dir pipeline_results --config pipeline_config.yaml

Flags (todas definidas no `argparse` em `main()`):
    --company       obrigatória   nome da empresa alvo, como aparecerá nos relatórios
    --company-slug  opcional      apelido curto; se omitido é gerado do nome (`_slugify`)
    --domains       obrigatória   arquivo texto, um domínio por linha
    --notes         opcional      observação livre, vai junto nos metadados
    --es-host       localhost     host do Elasticsearch
    --es-port       9200          porta do Elasticsearch
    --output-dir    pipeline_results   onde os arquivos brutos ficam
    --config        pipeline_config.yaml   qual configuração usar

ONDE RODAR: de dentro da pasta do projeto, com o Python do venv
---------------------------------------------------------------
    cd <caminho-do-projeto>
    ./.venv/bin/python3 adint_pipeline.py ...

Duas coisas dependem do diretório atual, e as duas falham silenciosamente fora
da pasta do projeto:

  * **As chaves de API.** O orquestrador não carrega o `.env`; cada script
    filho chama `load_dotenv()` por conta própria, e essa busca começa no
    diretório atual — que o filho herda deste processo. Rodando de fora, o
    `.env` não é encontrado, `SHODAN_API_KEY` vem vazia e a etapa do Shodan
    termina "com sucesso" e resultado vazio. (Os caminhos dos scripts no
    `pipeline_config.yaml` NÃO sofrem disso: são resolvidos contra a pasta
    deste arquivo, via `self.base_dir`.)
  * **Os caminhos que você digita.** `--domains` é aberto como você escreveu,
    relativo ao diretório atual. O log `adint_pipeline.log` também é criado no
    diretório atual.

E **use o Python do venv**: o pipeline repassa o *mesmo* interpretador para
cada etapa (`sys.executable`, veja `run_tool`). Chamar com o Python do sistema
faz todas as etapas herdarem um ambiente sem `elasticsearch`, `whois` nem
`shodan` — o erro aparece lá na frente, numa etapa qualquer.

COMO OS DADOS FICAM NO ELASTICSEARCH
------------------------------------
Índices **gerais por tipo de dado**, com o prefixo `analise_superficie_`:

    analise_superficie_metadata          quem é a empresa e quais domínios
    analise_superficie_whois             um documento por domínio
    analise_superficie_dns               um documento por execução (domínios como chaves)
    analise_superficie_shodan            um documento por IP/host
    analise_superficie_coletor_httpx     endpoints web vivos
    analise_superficie_coletor_naabu     portas abertas
    analise_superficie_coletor_nuclei    achados do nuclei
    analise_superficie_coletor_certs|san certificados e nomes alternativos
    analise_superficie_feed              notícias dos feeds RSS

**Os dados de todas as empresas convivem nos mesmos índices.** Não existe um
índice por cliente. O que separa é o campo `company_slug`, gravado em cada
documento por `send_to_elasticsearch`. Para filtrar uma empresa, use o subcampo
exato:

    # certo  — `company_slug.keyword` é `keyword`: casa o valor inteiro
    GET analise_superficie_shodan/_search
    { "query": { "term": { "company_slug.keyword": "minhaempresa" } } }

Pedir `company_slug` (sem o sufixo) num `term` compara contra o texto
*analisado*, e aí um slug com maiúscula ou hífen devolve **zero resultados com
HTTP 200** — sucesso vazio, não erro. Esse é o tropeço nº 1 de quem começa.

`pipeline_run` E `timestamp`: POR QUE IMPORTAM
----------------------------------------------
Cada execução ganha um carimbo (`self.timestamp`, formato `20250219_143012`) e
ele é gravado em TODO documento daquela rodada, em dois campos: `timestamp`
(data) e `pipeline_run` (keyword, o identificador da rodada).

Como os índices são gerais e **acumulativos**, rodar o pipeline duas vezes
deixa os dois conjuntos de documentos lado a lado. Consequência prática:

  * uma agregação sem filtro por `pipeline_run` **soma rodadas diferentes** —
    você lê "46 endpoints" quando a rodada atual tem 40, e os outros 6 são
    fantasmas de semana passada;
  * um `"size": 1` sem `sort` por `timestamp` devolve um documento *qualquer*
    (num filtro `term` todos empatam em relevância) — pode ser o mais antigo.

Ou seja: **sem filtrar por execução você lê dado velho achando que é novo**, e
nada no retorno avisa. O servidor MCP (`mcp_exposure_poc.py`) trata isso em
`latest_pipeline_run()`.

ONDE FICA A SAÍDA DE CADA ETAPA
-------------------------------
Tudo em disco, antes de ir para o Elasticsearch — é o que permite conferir o
dado bruto quando o relatório parece estranho:

    <output-dir>/<company_slug>/
        metadata.json               → analise_superficie_metadata
        temp/domains.txt            cópia normalizada da lista de domínios
        whois/whois_results.json    → analise_superficie_whois
        dns/dns_analysis/consolidated_*.json → analise_superficie_dns
        coletor/elk/*.json(l)       → analise_superficie_coletor_<nome-do-arquivo>
        shodan/**/*.json            → analise_superficie_shodan
        feed/feeds/                 (o FEED/ indexa sozinho, não passa por aqui)

Quem faz essa ponte é `_process_tool_results()`: para cada etapa ele sabe onde
procurar o arquivo e chama `send_to_elasticsearch()`, que carrega o JSON,
injeta `company` / `company_slug` / `timestamp` / `pipeline_run` em cada item e
envia em lote (`helpers.bulk`). Um item do JSON = um documento no índice.

LIGAR, DESLIGAR E ACRESCENTAR ETAPAS
------------------------------------
No `pipeline_config.yaml`, cada etapa é uma entrada em `tools:`:

    tools:
      shodan:
        enabled: true                              # false = etapa pulada
        script: SHODAN/unified_shodan_scanner.py   # relativo à pasta do projeto
        index: shodan                              # vira analise_superficie_shodan

`enabled: false` faz `run_tool()` registrar "desabilitada" e seguir adiante
(retorna sucesso: desligar uma etapa não derruba o pipeline).

**Atenção:** mudar o YAML não é suficiente para incluir uma etapa nova na
execução completa. A ordem das etapas está na lista `tools_order`, dentro de
`run_pipeline()`. Para acrescentar uma ferramenta são três passos:

  1. criar a entrada em `tools:` no `pipeline_config.yaml` (enabled/script/index);
  2. em `run_tool()`, acrescentar um `elif tool_name == "..."` montando os
     argumentos de linha de comando que o SEU script espera;
  3. em `_process_tool_results()`, dizer onde o script escreveu a saída;
     e incluir o nome em `tools_order`, em `run_pipeline()`, na posição certa.
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
        # Caminho RELATIVO: o log é criado no diretório atual, não na pasta do
        # projeto. Rodando de outro lugar, é lá que ele aparece.
        logging.FileHandler("adint_pipeline.log"),
        logging.StreamHandler()   # e também na tela, ao vivo
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
        # Prefira passar --company-slug explicitamente e reusar SEMPRE o mesmo
        # valor para a mesma empresa: é a chave que liga as execuções entre si
        # e entre os índices. Um slug gerado automaticamente muda quando o nome
        # muda ("Minha Empresa" → minha_empresa; "Minha Empresa LTDA" →
        # minha_empresa_ltda), e aí a segunda rodada vira "outra empresa" sem
        # ninguém perceber.
        self.company_slug = company_slug if company_slug else self._slugify(company_name)
        self.domains_file = domains_file
        self.notes = notes
        # Carimbo ÚNICO desta execução. É calculado uma vez, aqui, e gravado
        # igual em todo documento da rodada (como `timestamp` e `pipeline_run`).
        # É ele que permite depois perguntar "só o que foi coletado agora" num
        # índice que acumula todas as rodadas de todas as empresas.
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Pasta onde ESTE arquivo mora. Serve de âncora para os scripts das
        # etapas e para a saída — e é por isso que os caminhos relativos do
        # pipeline_config.yaml funcionam mesmo se o diretório atual for outro.
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        # Saída separada por empresa:
        #   <projeto>/<output-dir>/<company_slug>/<etapa>/
        # No disco a separação é por pasta; no Elasticsearch é por campo
        # (company_slug). São dois modelos diferentes para a mesma coisa.
        self.output_dir = os.path.join(self.base_dir, output_dir, self.company_slug)
        os.makedirs(self.output_dir, exist_ok=True)

        # Diretório temporário para arquivos de domínios
        self.temp_dir = os.path.join(self.output_dir, "temp")
        os.makedirs(self.temp_dir, exist_ok=True)

        # Cópia NORMALIZADA da lista de domínios (sem linhas em branco, sem
        # espaços nas pontas). Todas as etapas recebem este arquivo, não o seu
        # original: uma linha vazia no `dominios.txt` faria a ferramenta
        # consultar "" e devolver lixo.
        self.temp_domains_file = os.path.join(self.temp_dir, "domains.txt")
        self._copy_domains_file()
        
        # Configuração do Elasticsearch
        self.es_config = {
            "host": es_host,
            "port": es_port,
            "timeout": 60
        }
        self.es = None
        
        # Prefixo para índices do Elasticsearch.
        # Os índices são GERAIS por tipo de dado (analise_superficie_whois,
        # _dns, _shodan...) e NÃO contêm o nome da empresa: todas as empresas
        # dividem os mesmos índices. A separação é lógica, pelo campo
        # `company_slug` injetado em cada documento — não física.
        self.index_prefix = "analise_superficie"
        
        # Carrega configuração
        self.config = self._load_config(config_file)
        
        # Lê os domínios do arquivo
        domains = self._read_domains_from_file(domains_file)
        
        # O DOCUMENTO DE METADADOS — o pivô da análise.
        # Guarda a LISTA de domínios, não o caminho do arquivo: quem consulta
        # depois (o servidor MCP, uma LLM, você no Kibana) não tem acesso ao
        # seu disco. Este documento é o único lugar onde "empresa X persegue
        # estes domínios" fica registrado; todo o resto é fato solto sobre
        # domínios e IPs.
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
        """Carrega o pipeline_config.yaml — o painel de controle das etapas.

        É este arquivo que decide o que roda: para cada etapa, `enabled`
        (liga/desliga), `script` (qual programa) e `index` (onde o resultado
        vai parar). Mexer aqui não requer mexer no código.
        """
        # Resolvido contra a pasta do projeto, não contra o diretório atual.
        config_path = os.path.join(self.base_dir, config_file)

        # Se o arquivo não existir, cria um com configuração padrão
        # (o dicionário abaixo é a referência do formato esperado — use-o como
        # modelo ao acrescentar uma ferramenta nova)
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
            # request_timeout funciona no cliente 8.x e 9.x (a 9.x removeu o antigo timeout=)
            self.es = Elasticsearch([f"http://{self.es_config['host']}:{self.es_config['port']}"],
                                   request_timeout=self.es_config['timeout'])
            
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
        """Cria o índice no Elasticsearch se ainda não existir.

        Criar o índice ANTES de indexar é o que garante o mapeamento certo. Se o
        primeiro documento chegar num índice inexistente, o Elasticsearch
        adivinha os tipos (dynamic mapping) — e tipo adivinhado errado não se
        corrige depois: só reindexando.
        """
        if not self.es:
            logger.error("Elasticsearch não conectado")
            return False

        # Índice geral, sem o nome da empresa: `analise_superficie_<tipo>`.
        # Quem separa as empresas é o campo company_slug, não o índice.
        full_index_name = f"{self.index_prefix}_{index_name}"

        try:
            if not self.es.indices.exists(index=full_index_name):
                settings = self.config.get("elasticsearch", {}).get("index_settings", {})
                self.es.indices.create(
                    index=full_index_name,
                    body={
                        "settings": settings,
                        # Mapeamento dos 4 campos que ESTE pipeline injeta em
                        # todo documento. É o contrato que o servidor MCP
                        # (mcp_exposure_poc.py) consulta depois.
                        "mappings": {
                            "properties": {
                                "company": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {"type": "keyword", "ignore_above": 256}
                                    }
                                },
                                # text + subcampo .keyword: o `text` serve para
                                # busca por palavra ("minha empresa" acha
                                # "Minha Empresa LTDA"); o `.keyword` guarda o
                                # valor INTEIRO, sem análise, e é o único que
                                # serve para filtro exato e agregação.
                                # Na prática: para filtrar a empresa use
                                # `company_slug.keyword`. Um `term` em
                                # `company_slug` (sem sufixo) devolve zero
                                # resultados e HTTP 200 quando o slug tem
                                # maiúscula ou hífen — falha sem erro.
                                "company_slug": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {"type": "keyword", "ignore_above": 256}
                                    }
                                },
                                # keyword direto: é um identificador opaco de
                                # execução, nunca se busca "parte" dele.
                                "pipeline_run": {
                                    "type": "keyword"
                                },
                                # date com formatos alternativos (`||`): aceita
                                # o `20250219_143012` que este pipeline gera E
                                # os ISO que as ferramentas trazem. Ser `date`
                                # é o que permite `sort` por recência — num
                                # campo `text` o sort falha.
                                "timestamp": {
                                    "type": "date",
                                    "format": "yyyy-MM-dd'T'HH:mm:ss||yyyy-MM-dd||yyyyMMdd_HHmmss||epoch_millis"
                                }
                            },
                            # Os documentos das ferramentas têm campos
                            # imprevisíveis (cada TLD de WHOIS, cada template de
                            # nuclei). Este template diz: toda string nova vira
                            # text + .keyword, para o aluno poder agregar
                            # qualquer campo sem precisar remapear o índice.
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
        """Lê um arquivo de saída de etapa e indexa cada item como um documento.

        É aqui que o arquivo em disco vira dado consultável. O caminho é:

            arquivo .json/.jsonl  →  lista de itens  →  + metadados da empresa
                                  →  helpers.bulk    →  analise_superficie_<index_name>

        UM ITEM DO JSON = UM DOCUMENTO NO ÍNDICE. Se o arquivo é um objeto único
        (o caso do `metadata.json` e do DNS consolidado), ele é embrulhado numa
        lista de um elemento e vira um documento só.

        Aceita `.json` e `.jsonl`; um `.json` que falha no parse é tentado como
        JSONL antes de desistir, porque várias ferramentas de rede escrevem uma
        linha por achado e chamam o arquivo de `.json`.
        """
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
                
            # ESTE É O CORAÇÃO DO MODELO DE DADOS.
            # As ferramentas não sabem de qual empresa estão falando nem quando
            # rodaram — elas só devolvem fatos sobre domínios e IPs. É este
            # laço que torna cada achado rastreável, acrescentando 4 campos:
            #
            #   company       nome legível, para o relatório
            #   company_slug  a chave de filtro (use company_slug.keyword)
            #   timestamp     quando (date, permite ordenar por recência)
            #   pipeline_run  QUAL execução (keyword, permite isolar a rodada)
            #
            # Sem `pipeline_run`, uma contagem no índice soma todas as rodadas
            # já feitas e você reporta número velho como se fosse de agora.
            # Observe que `timestamp` é SOBRESCRITO: se a ferramenta já trouxe
            # um campo com esse nome (a data de um certificado, por exemplo),
            # ele é perdido — o carimbo do pipeline tem precedência.
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
                    # (sem o slug, duas empresas com um item de `id` igual
                    # sobrescreveriam uma à outra no mesmo índice geral).
                    #
                    # ATENÇÃO ao efeito colateral: _id fixo significa que
                    # reexecutar o pipeline SOBRESCREVE o documento anterior
                    # em vez de criar um novo. Para itens com `id`, o índice
                    # guarda só a última rodada; para os demais (sem `id`), o
                    # Elasticsearch gera um _id aleatório e cada rodada
                    # ACUMULA um documento novo. Os dois comportamentos
                    # convivem no mesmo índice — é por isso que filtrar por
                    # `pipeline_run` é obrigatório para contar qualquer coisa.
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
        """Executa UMA etapa do pipeline como subprocesso e indexa o resultado.

        Cada etapa é um programa independente, com flags próprias. Este método
        é o tradutor: pega o nome da etapa, descobre no YAML qual script rodar,
        monta a linha de comando que AQUELE script espera (o bloco de
        `elif tool_name == ...` abaixo) e acompanha a saída ao vivo.

        Para acrescentar uma ferramenta nova ao pipeline, é aqui que se escreve
        o `elif` com os argumentos dela — e em `_process_tool_results()` onde
        ela escreveu a saída.
        """
        tool_config = self.config.get("tools", {}).get(tool_name)

        if not tool_config:
            logger.error(f"Ferramenta não configurada: {tool_name}")
            return False

        # `enabled: false` no pipeline_config.yaml = etapa pulada.
        # Retorna True de propósito: desligar uma etapa é uma escolha, não uma
        # falha, e não deve interromper o resto da execução.
        if not tool_config.get("enabled", False):
            logger.info(f"Ferramenta {tool_name} desabilitada na configuração")
            return True

        # O caminho do script é resolvido contra a pasta DESTE arquivo
        # (`self.base_dir`), não contra o diretório atual. Por isso o
        # `pipeline_config.yaml` pode usar caminho relativo
        # (`WHOIS/whois_universal.py`) e continuar válido.
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
                    # sys.executable = o MESMO interpretador que está rodando este pipeline.
                    # Não use "python3" solto: ele resolve pelo PATH e cai no Python do
                    # sistema (/usr/bin/python3), que não tem whois, elasticsearch, shodan
                    # nem telethon — o sintoma é ModuleNotFoundError numa etapa qualquer.
                    # Assim o script roda em qualquer máquina: quem escolhe o interpretador
                    # é quem chamou o pipeline, não o PATH.
                    #
                    # A CONSEQUÊNCIA PARA VOCÊ: o ambiente é herdado, não
                    # consertado. Se você chamar o pipeline com o Python do
                    # sistema, TODAS as etapas rodam nele — e todas quebram com
                    # ModuleNotFoundError, uma a uma, mesmo com o venv instalado
                    # e funcionando ao lado. A escolha do interpretador se faz
                    # na primeira palavra do comando e vale para a execução
                    # inteira:
                    #
                    #     ./.venv/bin/python3 adint_pipeline.py ...   # certo
                    #     source .venv/bin/activate; python3 ...      # certo
                    #     python3 adint_pipeline.py ...               # roleta do PATH
                    #
                    # Para conferir em qual Python você está, antes de rodar:
                    #     python3 -c "import sys; print(sys.executable)"
                    cmd = [sys.executable, script_path]
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
                
                # Define o diretório de saída via variável de ambiente OUT_DIR.
                # coletor.sh lê OUT_DIR do ambiente (OUT="${OUT_DIR:-out}"), NÃO como
                # argumento posicional — passá-lo como argumento não tinha efeito e os
                # resultados caíam em ./out. O subprocesso herda este os.environ.
                os.environ["OUT_DIR"] = tool_output_dir
                if isinstance(cmd, list):
                    cmd.append(coletor_domains)
                else:
                    cmd += f" {coletor_domains}"
            
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
        """Encontra o arquivo de saída da etapa e manda para o Elasticsearch.

        A PONTE entre disco e índice. Cada ferramenta escreve num lugar e num
        formato próprios, então não há regra geral: há um bloco por etapa
        dizendo onde olhar. É a razão de o passo 3 existir ao se acrescentar
        uma ferramenta nova — sem ele a etapa roda, grava em disco e o dado
        nunca chega ao Elasticsearch.

        Chamado só quando a etapa termina com código 0 (ver `run_tool`).
        """
        # O índice vem do YAML (`index: shodan`), com o nome da etapa como
        # padrão. O prefixo `analise_superficie_` é acrescentado adiante.
        index_name = self.config.get("tools", {}).get(tool_name, {}).get("index", tool_name)

        # Cria o índice com o mapeamento certo ANTES do primeiro documento
        # (ver create_index: tipo adivinhado não se corrige sem reindexar).
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
                            # O coletor.sh roda cinco ferramentas e escreve um
                            # arquivo por ferramenta (httpx.json, naabu.json,
                            # nuclei.json...). Cada um vira um ÍNDICE PRÓPRIO,
                            # nomeado a partir do arquivo:
                            #   elk/httpx.json → analise_superficie_coletor_httpx
                            # Misturar portas abertas com achados de nuclei no
                            # mesmo índice daria um mapeamento confuso.
                            # Observe que estes subíndices NÃO passam por
                            # create_index() com o mapeamento acima — são
                            # criados pelo mapeamento dinâmico do próprio
                            # Elasticsearch no primeiro documento.
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
        """Executa o pipeline completo, na ordem."""
        logger.info(f"🚀 Iniciando pipeline para {self.company_name}")

        # Conecta ao Elasticsearch ANTES de coletar qualquer coisa: não faz
        # sentido gastar consulta de API e scan de rede se não há onde guardar.
        if not self.connect_to_elasticsearch():
            logger.error("❌ Falha ao conectar ao Elasticsearch. Abortando pipeline.")
            return False

        # O índice `metadata` é o PIVÔ de tudo: é nele que se descobre quais
        # empresas existem e quais domínios pertencem a cada uma. O servidor
        # MCP começa toda consulta por aqui. Por isso ele é escrito primeiro,
        # antes de qualquer coleta — se o pipeline morrer no meio, pelo menos
        # se sabe o que ele estava tentando analisar.
        self.create_index("metadata")

        metadata_file = os.path.join(self.output_dir, "metadata.json")
        self.send_to_elasticsearch("metadata", metadata_file)

        # A ORDEM DAS ETAPAS, e a lista de quem participa da execução completa.
        # A ordem não é arbitrária: WHOIS e DNS são passivos e baratos, e o
        # que eles descobrem contextualiza o resto; `coletor` é a etapa ATIVA
        # (manda pacote para o alvo — só com autorização, ver o README); e
        # `shodan` fecha com a visão externa dos IPs.
        #
        # `feed` e `telegram` ficam fora de propósito: o FEED/ indexa sozinho e
        # não é específico da empresa, e o TELEGRAM/ exige sessão autenticada.
        # Rode-os à mão quando quiser (ver README, "Uma etapa por vez").
        #
        # ⚠️ Esta lista é a palavra final sobre o que roda. Pôr
        # `enabled: true` no pipeline_config.yaml para uma etapa que NÃO está
        # aqui não tem efeito algum — é preciso acrescentar o nome a esta
        # lista. O inverso vale: estar aqui com `enabled: false` no YAML faz a
        # etapa ser pulada por `run_tool()`.
        tools_order = ["whois", "dns", "coletor", "shodan"]

        # Sem interromper em caso de falha: uma etapa que quebra (binário
        # ausente, API sem chave) não deve cancelar as outras. Confira o log
        # no fim — "pipeline concluído" NÃO significa "tudo coletado".
        for tool in tools_order:
            self.run_tool(tool)

        logger.info(f"✅ Pipeline concluído para {self.company_name}")
        logger.info(f"   Resultados em: {self.output_dir}")
        logger.info(f"   Índices Elasticsearch: {self.index_prefix}_*")
        logger.info(f"   Dados podem ser filtrados por company='{self.company_name}' ou company_slug='{self.company_slug}'")
        
        return True

def main():
    """Ponto de entrada: lê as flags, monta o pipeline e executa.

    Exemplo completo (rode de dentro da pasta do projeto, com o Python do venv):

        ./.venv/bin/python3 adint_pipeline.py \\
            --company "Minha Empresa" --company-slug minhaempresa \\
            --domains dominios.txt --es-host localhost --es-port 9200 \\
            --output-dir pipeline_results --config pipeline_config.yaml
    """
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
    
    # `--domains` é resolvido contra o DIRETÓRIO ATUAL (diferente do --config e
    # do --output-dir, que seguem a pasta do projeto). Se este erro aparecer
    # com o arquivo existindo, você está rodando de outro diretório.
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
