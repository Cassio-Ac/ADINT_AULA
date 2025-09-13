# Pipeline de Análise de Superfície de Ataque

![Logo](https://img.shields.io/badge/ADINT-Pipeline-blue)
![Version](https://img.shields.io/badge/version-1.0.0-green)
![Python](https://img.shields.io/badge/python-3.6+-yellow)
![Elasticsearch](https://img.shields.io/badge/elasticsearch-7.x-orange)

Bem-vindo à documentação do Pipeline de Análise de Superfície de Ataque, uma solução integrada para coletar, processar e analisar informações de segurança sobre domínios e infraestrutura de uma organização.

## 📚 Documentação

- [README](../README.md) - Visão geral do projeto
- [Visão Geral](README.md) - Documentação detalhada do pipeline
- [Esquema de Dados](SCHEMA.md) - Descrição dos esquemas de dados
- [Instalação](INSTALLATION.md) - Guia de instalação
- [Visualização no Kibana](KIBANA.md) - Guia para visualização dos dados
- [Personalização](CUSTOMIZATION.md) - Guia de personalização
- [API](API.md) - Documentação da API
- [Ferramentas](TOOLS.md) - Documentação detalhada das ferramentas
- [Troubleshooting](TROUBLESHOOTING.md) - Guia de solução de problemas

## 📊 Amostras de Dados

Explore amostras de dados coletados pelo pipeline:

- [Metadados](samples/metadata_sample.json)
- [WHOIS](samples/whois_sample.json)
- [DNS](samples/dns_sample.json)
- [COLETOR - HTTPX](samples/coletor_httpx_sample.json)
- [COLETOR - Naabu](samples/coletor_naabu_sample.json)
- [COLETOR - TLSX](samples/coletor_tlsx_sample.json)
- [COLETOR - Nuclei](samples/coletor_nuclei_sample.json)
- [Shodan](samples/shodan_sample.json)
- [Feed](samples/feed_sample.json)
- [Telegram](samples/telegram_sample.json)

## 🚀 Início Rápido

```bash
# Instalar dependências
./setup.sh

# Executar o pipeline
./run_pipeline.sh -c "Nome da Empresa" -d dominios.txt
```

## 📋 Recursos

- Coleta automatizada de informações sobre domínios e infraestrutura
- Análise de segurança DNS com pontuação e recomendações
- Detecção de serviços expostos e vulnerabilidades
- Monitoramento de feeds RSS de segurança
- Coleta opcional de dados de vazamentos do Telegram
- Visualização integrada no Kibana

## 🔧 Ferramentas Integradas

- **WHOIS**: Consulta informações de registro de domínios
- **DNS**: Analisa configurações DNS e atribui pontuação de segurança
- **COLETOR**: Executa subfinder, httpx, naabu, tlsx e nuclei
- **SHODAN**: Consulta informações no Shodan para domínios e IPs
- **FEED**: Coleta feeds RSS de segurança relevantes
- **TELEGRAM**: Coleta dados de vazamentos do Telegram (opcional)

## 📈 Índices no Elasticsearch

- `analise_superficie_[empresa]_metadata`: Metadados da execução
- `analise_superficie_[empresa]_whois`: Resultados WHOIS
- `analise_superficie_[empresa]_dns`: Análise DNS
- `analise_superficie_[empresa]_coletor_*`: Resultados do COLETOR
- `analise_superficie_[empresa]_shodan`: Resultados Shodan
- `analise_superficie_[empresa]_feed`: Feeds RSS
- `analise_superficie_[empresa]_telegram`: Dados de vazamentos

## 🤝 Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests.

## 📄 Licença

Este projeto é distribuído sob a licença MIT.
