#!/bin/bash
# Script para executar o pipeline ADINT com parâmetros simplificados

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Função de ajuda
show_help() {
  echo -e "${BLUE}ADINT Pipeline - Orquestrador de coleta e análise de inteligência${RESET}"
  echo ""
  echo "Uso:"
  echo "  $0 [opções]"
  echo ""
  echo "Opções:"
  echo "  -c, --company NOME     Nome da empresa alvo (obrigatório)"
  echo "  -s, --company-slug SLUG Slug/apelido da empresa (opcional)"
  echo "  -d, --domains ARQUIVO  Arquivo com lista de domínios (obrigatório)"
  echo "  -n, --notes TEXTO      Observações sobre a análise"
  echo "  -h, --host HOST        Host do Elasticsearch (padrão: localhost)"
  echo "  -p, --port PORTA       Porta do Elasticsearch (padrão: 9200)"
  echo "  -o, --output DIR       Diretório para armazenar resultados (padrão: pipeline_results)"
  echo "  --help                 Mostra esta mensagem de ajuda"
  echo ""
  echo "Exemplos:"
  echo "  $0 -c \"Adsumus Intelligence\" -s \"adint\" -d dominios.txt -n \"Análise de segurança\""
  echo "  $0 --company \"Empresa XYZ\" --company-slug \"xyz\" --domains dominios.txt --host elastic.local --port 9200"
}

# Verifica se o Python 3 está instalado
check_python() {
  if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Erro: Python 3 não encontrado. Por favor, instale o Python 3.${RESET}"
    exit 1
  fi
}

# Verifica se o Elasticsearch está acessível
check_elasticsearch() {
  local host=$1
  local port=$2
  
  echo -e "${YELLOW}Verificando conexão com Elasticsearch em $host:$port...${RESET}"
  
  if ! curl -s "http://$host:$port" > /dev/null; then
    echo -e "${RED}Aviso: Não foi possível conectar ao Elasticsearch em $host:$port${RESET}"
    echo -e "${YELLOW}Deseja continuar mesmo assim? (s/n)${RESET}"
    read -r response
    if [[ "$response" != "s" && "$response" != "S" ]]; then
      echo -e "${RED}Abortando.${RESET}"
      exit 1
    fi
  else
    echo -e "${GREEN}Elasticsearch está acessível!${RESET}"
  fi
}

# Verifica dependências
check_dependencies() {
  local missing=0
  
  echo -e "${YELLOW}Verificando dependências...${RESET}"
  
  # Verifica Python e módulos
  check_python
  
  # Lista de módulos Python necessários
  modules=("elasticsearch" "yaml")
  
  for module in "${modules[@]}"; do
    if ! python3 -c "import $module" &> /dev/null; then
      echo -e "${RED}Módulo Python '$module' não encontrado. Instale com: pip install $module${RESET}"
      missing=1
    fi
  done
  
  # Verifica ferramentas externas
  tools=("dig" "jq" "curl")
  
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
      echo -e "${RED}Ferramenta '$tool' não encontrada. Por favor, instale-a.${RESET}"
      missing=1
    fi
  done
  
  if [ $missing -eq 1 ]; then
    echo -e "${RED}Dependências ausentes. Por favor, instale-as e tente novamente.${RESET}"
    exit 1
  fi
  
  echo -e "${GREEN}Todas as dependências estão instaladas!${RESET}"
}

# Valores padrão
ES_HOST="localhost"
ES_PORT="9200"
OUTPUT_DIR="pipeline_results"
NOTES=""
COMPANY_SLUG=""

# Processa argumentos
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--company)
      COMPANY="$2"
      shift 2
      ;;
    -s|--company-slug)
      COMPANY_SLUG="$2"
      shift 2
      ;;
    -d|--domains)
      DOMAINS="$2"
      shift 2
      ;;
    -n|--notes)
      NOTES="$2"
      shift 2
      ;;
    -h|--host)
      ES_HOST="$2"
      shift 2
      ;;
    -p|--port)
      ES_PORT="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      echo -e "${RED}Erro: Opção desconhecida: $1${RESET}"
      show_help
      exit 1
      ;;
  esac
done

# Verifica argumentos obrigatórios
if [ -z "$COMPANY" ] || [ -z "$DOMAINS" ]; then
  echo -e "${RED}Erro: Nome da empresa e arquivo de domínios são obrigatórios.${RESET}"
  show_help
  exit 1
fi

# Verifica se o arquivo de domínios existe
if [ ! -f "$DOMAINS" ]; then
  echo -e "${RED}Erro: Arquivo de domínios não encontrado: $DOMAINS${RESET}"
  exit 1
fi

# Verifica dependências
check_dependencies

# Verifica conexão com Elasticsearch
check_elasticsearch "$ES_HOST" "$ES_PORT"

# Executa o pipeline
echo -e "${BLUE}Iniciando pipeline ADINT para $COMPANY...${RESET}"
if [ -n "$COMPANY_SLUG" ]; then
  echo -e "${YELLOW}Slug da empresa: $COMPANY_SLUG${RESET}"
fi
echo -e "${YELLOW}Usando domínios de: $DOMAINS${RESET}"
echo -e "${YELLOW}Elasticsearch: $ES_HOST:$ES_PORT${RESET}"
echo -e "${YELLOW}Resultados serão salvos em: $OUTPUT_DIR${RESET}"

# Comando para executar o pipeline
CMD="python3 adint_pipeline.py \
  --company \"$COMPANY\" \
  --domains \"$DOMAINS\" \
  --notes \"$NOTES\" \
  --es-host \"$ES_HOST\" \
  --es-port \"$ES_PORT\" \
  --output-dir \"$OUTPUT_DIR\""

# Adiciona company-slug se fornecido
if [ -n "$COMPANY_SLUG" ]; then
  CMD="$CMD --company-slug \"$COMPANY_SLUG\""
fi

echo -e "${BLUE}Executando: $CMD${RESET}"
eval $CMD

# Verifica resultado
if [ $? -eq 0 ]; then
  echo -e "${GREEN}Pipeline concluído com sucesso!${RESET}"
  echo -e "${GREEN}Resultados disponíveis em: $OUTPUT_DIR${RESET}"
  # Se tiver company_slug, usa ele, senão gera a partir do nome da empresa
  if [ -n "$COMPANY_SLUG" ]; then
    echo -e "${GREEN}Índices no Elasticsearch: analise_superficie_${COMPANY_SLUG}_*${RESET}"
  else
    echo -e "${GREEN}Índices no Elasticsearch: analise_superficie_$(echo "$COMPANY" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g')_*${RESET}"
  fi
else
  echo -e "${RED}Pipeline falhou. Verifique os logs para mais detalhes.${RESET}"
  exit 1
fi
