#!/bin/bash
# Script de configuração inicial para o pipeline de análise de superfície

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

echo -e "${BLUE}Configurando ambiente para o pipeline de análise de superfície...${RESET}"

# Verifica se o Python 3 está instalado
if ! command -v python3 &> /dev/null; then
  echo -e "${RED}Erro: Python 3 não encontrado. Por favor, instale o Python 3.${RESET}"
  exit 1
fi

# Instala dependências Python principais
echo -e "${YELLOW}Instalando dependências Python principais...${RESET}"
pip3 install -r requirements.txt

# Verifica ferramentas externas
tools=("dig" "jq" "curl")
missing=0

echo -e "${YELLOW}Verificando ferramentas externas...${RESET}"
for tool in "${tools[@]}"; do
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${RED}Ferramenta '$tool' não encontrada. Por favor, instale-a.${RESET}"
    missing=1
  fi
done

if [ $missing -eq 1 ]; then
  echo -e "${YELLOW}Algumas ferramentas externas estão faltando. Instale-as antes de executar o pipeline.${RESET}"
fi

# Configuração do ambiente virtual para o Telegram (opcional)
echo -e "${YELLOW}Deseja configurar o ambiente para a coleta do Telegram? (s/n)${RESET}"
read -r setup_telegram

if [[ "$setup_telegram" == "s" || "$setup_telegram" == "S" ]]; then
  echo -e "${YELLOW}Configurando ambiente virtual para o Telegram...${RESET}"
  
  # Cria ambiente virtual
  python3 -m venv telegram_venv
  
  # Ativa o ambiente virtual
  source telegram_venv/bin/activate
  
  # Instala dependências
  pip install -r TELEGRAM/requirements.txt
  
  # Desativa o ambiente virtual
  deactivate
  
  echo -e "${GREEN}Ambiente Telegram configurado!${RESET}"
  echo -e "${YELLOW}Para usar a ferramenta Telegram, habilite-a no arquivo pipeline_config.yaml${RESET}"
fi

echo -e "${GREEN}Configuração concluída!${RESET}"
echo -e "${BLUE}Para executar o pipeline, use: ./run_pipeline.sh -c \"Nome da Empresa\" -d dominios.txt${RESET}"
