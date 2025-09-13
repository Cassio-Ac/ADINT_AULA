# Pipeline de Análise de Superfície de Ataque

Este repositório contém um pipeline automatizado para análise de superfície de ataque, que combina várias ferramentas de código aberto para coletar, processar e analisar informações de segurança sobre domínios e infraestrutura de uma organização.

## 🚀 Início Rápido

```bash
# Instalar dependências
./setup.sh

# Executar o pipeline
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt
```

## 📋 Visão Geral

O pipeline de análise de superfície de ataque é uma solução integrada que:

- Automatiza a coleta de informações sobre domínios e infraestrutura
- Identifica vulnerabilidades e problemas de configuração
- Centraliza os resultados no Elasticsearch para análise
- Facilita a visualização e geração de relatórios

## 🧰 Ferramentas Integradas

- **WHOIS**: Consulta informações de registro de domínios
- **DNS**: Analisa configurações DNS e atribui pontuação de segurança
- **COLETOR**: Executa subfinder, httpx, naabu, tlsx e nuclei
- **SHODAN**: Consulta informações no Shodan para domínios e IPs
- **FEED**: Coleta feeds RSS de segurança relevantes
- **TELEGRAM**: Coleta dados de vazamentos do Telegram (opcional, requer configuração)

## 📊 Índices do Elasticsearch

Os resultados são armazenados em índices do Elasticsearch com o prefixo `analise_superficie_*`:

- `analise_superficie_metadata`: Metadados da execução
- `analise_superficie_whois`: Resultados WHOIS
- `analise_superficie_dns`: Análise de segurança DNS
- `analise_superficie_coletor_*`: Resultados do coletor (httpx, naabu, tlsx, nuclei)
- `analise_superficie_shodan`: Dados do Shodan
- `analise_superficie_feed`: Feeds RSS relevantes
- `analise_superficie_telegram`: Dados de vazamentos (opcional)

## 📘 Documentação

Para documentação detalhada, consulte:

- [Documentação Completa](docs/README.md)
- [Guia de Instalação](docs/INSTALLATION.md)
- [Guia de API](docs/API.md)
- [Guia do Kibana](docs/KIBANA.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🛠️ Configuração

O comportamento do pipeline pode ser personalizado editando o arquivo `pipeline_config.yaml`:

```yaml
tools:
  whois:
    enabled: true
    script: WHOIS/whois_universal.py
    index: whois
  
  # ... outras ferramentas ...

elasticsearch:
  index_settings:
    number_of_shards: 1
    number_of_replicas: 0
```

## 📝 Requisitos

- Python 3.8+
- Elasticsearch 7.x+
- Docker (opcional, para algumas ferramentas)
- API Shodan (para consultas Shodan)
- API Telegram (opcional, para coleta de vazamentos)

## 🤝 Contribuição

Contribuições são bem-vindas! Por favor, leia o [guia de contribuição](docs/CONTRIBUTING.md) antes de enviar pull requests.

## 📄 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.
