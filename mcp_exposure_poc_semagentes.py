#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP Server - Análise de Superfície de Ataque (FUNCIONAL)
Baseado no script complete_working_report.py que já está funcionando

Requisitos:
  pip install mcp requests python-dateutil

Uso:
  python mcp_surface_analysis.py

Ferramentas disponíveis:
  - surface_report: Gera relatório completo em markdown
  - surface_report_json: Gera relatório em JSON
  - check_leaks: Verifica apenas vazamentos
  - get_company_info: Pega informações da empresa
  - shodan_summary: Resumo de exposição externa
"""
import asyncio
import json
import logging
import os
import sys
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import Counter

import requests
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

# Configuração de logging para stderr (MCP usa stdout)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-surface-analysis")

# Configurações do Elasticsearch
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
HEADERS = {"Content-Type": "application/json"}
TIMEOUT = 30

# Inicializar MCP Server
mcp = FastMCP("surface-analysis")

# ============================================================================
# FUNÇÕES AUXILIARES (baseadas no script funcional)
# ============================================================================

def search_es(index: str, query: Dict[str, Any]) -> Dict[str, Any]:
    """Busca no Elasticsearch"""
    try:
        url = f"{ES_URL}/{index}/_search"
        response = requests.post(url, headers=HEADERS, json=query, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Erro ao buscar {index}: {e}")
        return {"hits": {"hits": []}}

def count_es(index: str, query: Dict[str, Any]) -> int:
    """Conta documentos no Elasticsearch"""
    try:
        url = f"{ES_URL}/{index}/_count"
        response = requests.post(url, headers=HEADERS, json=query, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json().get("count", 0)
    except Exception as e:
        logger.error(f"Erro ao contar {index}: {e}")
        return 0

def nslookup_domain(domain: str) -> List[str]:
    """Resolve domínio para IPs"""
    ips = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        ips.extend(ip_list)
    except Exception:
        pass
    
    valid_ips = []
    for ip in ips:
        try:
            socket.inet_aton(ip)
            if ip not in valid_ips:
                valid_ips.append(ip)
        except:
            pass
    
    return valid_ips

# ============================================================================
# FUNÇÕES DE COLETA DE DADOS (baseadas no script funcional)
# ============================================================================

def get_company_metadata(company_name: Optional[str] = None) -> Dict[str, Any]:
    """Busca metadados da empresa"""
    index = "analise_superficie_metadata"
    
    if company_name:
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"company": company_name}},
                        {"term": {"company_slug.keyword": company_name.lower()}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 1
        }
    else:
        query = {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1
        }
    
    result = search_es(index, query)
    hits = result.get("hits", {}).get("hits", [])
    
    if hits:
        data = hits[0]["_source"]
        return {
            "name": data.get("company", "Empresa Desconhecida"),
            "slug": data.get("company_slug", "unknown"),
            "domains": data.get("domains", []),
            "timestamp": data.get("timestamp"),
            "pipeline_run": data.get("pipeline_run")
        }
    
    return {}

def resolve_domain_ips(domains: List[str]) -> tuple[Dict[str, List[str]], List[str]]:
    """Resolve domínios para IPs"""
    domain_ips = {}
    all_ips = set()
    
    for domain in domains:
        ips = nslookup_domain(domain)
        if ips:
            domain_ips[domain] = ips
            all_ips.update(ips)
    
    # Subdomínios comuns
    common_subdomains = ['mail', 'www', 'cpanel', 'webdisk', 'autodiscover', 'webmail', 'ftp']
    
    for domain in domains:
        for subdomain in common_subdomains:
            full_subdomain = f"{subdomain}.{domain}"
            ips = nslookup_domain(full_subdomain)
            if ips:
                domain_ips[full_subdomain] = ips
                all_ips.update(ips)
    
    return domain_ips, list(all_ips)

def analyze_dns_security(company_slug: str, domains: List[str]) -> List[Dict[str, Any]]:
    """Analisa segurança DNS"""
    index = "analise_superficie_dns"
    
    query = {
        "query": {"term": {"company_slug": company_slug}},
        "size": 1
    }
    
    result = search_es(index, query)
    hits = result.get("hits", {}).get("hits", [])
    
    dns_results = []
    if hits:
        source = hits[0]["_source"]
        for domain in domains:
            if domain in source and isinstance(source[domain], dict):
                domain_data = source[domain]
                security_scores = domain_data.get("security_scores", [])
                
                if security_scores:
                    earned = sum(s.get("earned_points", 0) for s in security_scores)
                    maximum = sum(s.get("max_points", 0) for s in security_scores)
                    percentage = round((earned / maximum) * 100, 2) if maximum > 0 else 0
                    
                    if percentage >= 90: grade = "A"
                    elif percentage >= 80: grade = "B"
                    elif percentage >= 70: grade = "C"
                    elif percentage >= 60: grade = "D"
                    else: grade = "F"
                else:
                    percentage = 0
                    grade = "F"
                
                dns_results.append({
                    "domain": domain,
                    "grade": grade,
                    "percentage": percentage,
                    "recommendations": domain_data.get("recommendations", [])[:3]
                })
    
    return dns_results

def get_shodan_exposure(all_ips: List[str], company_slug: str) -> Dict[str, Any]:
    """Analisa exposição externa via Shodan"""
    index = "analise_superficie_shodan"
    
    should_queries = [{"term": {"company_slug": company_slug}}]
    for ip in all_ips:
        should_queries.append({"term": {"ip": ip}})
    
    query = {
        "query": {
            "bool": {
                "should": should_queries,
                "minimum_should_match": 1
            }
        },
        "size": 50
    }
    
    result = search_es(index, query)
    hits = result.get("hits", {}).get("hits", [])
    
    assets = []
    total_vulns = total_ports = 0
    countries = set()
    organizations = set()
    
    for hit in hits:
        source = hit["_source"]
        vulns = source.get("vulnerabilities", [])
        ports = source.get("ports", [])
        asset_ip = source.get("ip")
        
        if asset_ip in all_ips or source.get("company_slug") == company_slug:
            assets.append({
                "ip": asset_ip,
                "hostnames": source.get("hostnames", []),
                "country": source.get("country"),
                "organization": source.get("organization"),
                "open_ports": len(ports),
                "vulnerabilities": len(vulns),
                "top_vulns": vulns[:10]
            })
            
            total_vulns += len(vulns)
            total_ports += len(ports)
            if source.get("country"): countries.add(source.get("country"))
            if source.get("organization"): organizations.add(source.get("organization"))
    
    return {
        "assets": assets,
        "summary": {
            "total_assets": len(assets),
            "total_ports": total_ports,
            "total_vulnerabilities": total_vulns,
            "countries": list(countries),
            "organizations": list(organizations)
        }
    }

def get_web_surface(company_slug: str) -> Dict[str, Any]:
    """Analisa superfície web"""
    index = "analise_superficie_coletor_httpx"
    
    query = {
        "query": {
            "bool": {
                "must": [{"term": {"company_slug.keyword": company_slug}}]
            }
        },
        "size": 100
    }
    
    result = search_es(index, query)
    hits = result.get("hits", {}).get("hits", [])
    
    endpoints = []
    status_counts = Counter()
    
    for hit in hits:
        source = hit["_source"]
        status = source.get("status_code")
        status_counts[status] += 1
        
        endpoints.append({
            "url": source.get("url"),
            "status": status,
            "title": source.get("title", "").strip()[:80],
            "server": source.get("webserver", "Unknown")
        })
    
    return {
        "endpoints": endpoints,
        "total_endpoints": len(endpoints),
        "status_distribution": dict(status_counts)
    }

def check_data_leaks(domains: List[str]) -> Dict[str, Any]:
    """Verifica vazamentos usando a query que FUNCIONA"""
    index = "vazamentos_dados"
    
    if not domains:
        return {"total": 0, "samples": [], "by_domain": {}}
    
    total_leaks = 0
    all_samples = []
    by_domain = {}
    
    for domain in domains:
        # QUERY QUE FUNCIONA - testada
        query_body = {
            "query": {
                "wildcard": {
                    "linha": f"*{domain}*"
                }
            }
        }
        
        sample_query = {
            "query": {
                "wildcard": {
                    "linha": f"*{domain}*"
                }
            },
            "size": 10,
            "_source": ["linha", "arquivo_origem", "id"]
        }
        
        result = search_es(index, sample_query)
        hits = result.get("hits", {}).get("hits", [])
        
        # Filtra apenas emails válidos do domínio
        valid_hits = []
        for hit in hits:
            source = hit["_source"]
            linha = source.get("linha", "")
            
            if f"@{domain}" in linha:
                valid_hits.append(hit)
        
        actual_count = len(valid_hits)
        by_domain[domain] = actual_count
        total_leaks += actual_count
        
        for hit in valid_hits:
            source = hit["_source"]
            linha = source.get("linha", "")
            
            # Mascarar senha
            if ":" in linha:
                email, senha = linha.split(":", 1)
                if len(senha) > 6:
                    senha_masked = senha[:3] + "*" * (len(senha) - 6) + senha[-3:]
                else:
                    senha_masked = "*" * len(senha)
                linha_masked = f"{email}:{senha_masked}"
            else:
                linha_masked = linha
            
            all_samples.append({
                "linha": linha_masked,
                "arquivo": source.get("arquivo_origem", "N/A"),
                "domain": domain
            })
    
    return {
        "total": total_leaks,
        "samples": all_samples[:15],
        "by_domain": by_domain
    }

# ============================================================================
# FERRAMENTAS MCP
# ============================================================================

@mcp.tool()
def ping() -> str:
    """Health check do servidor MCP"""
    return "pong - MCP Surface Analysis Server is running"

@mcp.tool()
def get_company_info(company_name: str = "") -> Dict[str, Any]:
    """
    Busca informações da empresa nos metadados
    
    Args:
        company_name: Nome da empresa (opcional, se vazio pega a primeira)
    
    Returns:
        Dict com informações da empresa: name, slug, domains, timestamp
    """
    if not company_name.strip():
        company_name = None
    
    return get_company_metadata(company_name)

@mcp.tool() 
def check_leaks(company_name: str = "") -> Dict[str, Any]:
    """
    Verifica vazamentos de dados para uma empresa
    
    Args:
        company_name: Nome da empresa
    
    Returns:
        Dict com total de vazamentos, amostras e breakdown por domínio
    """
    company_info = get_company_metadata(company_name if company_name.strip() else None)
    if not company_info:
        return {"error": "Empresa não encontrada"}
    
    domains = company_info.get("domains", [])
    return check_data_leaks(domains)

@mcp.tool()
def shodan_summary(company_name: str = "") -> Dict[str, Any]:
    """
    Resumo de exposição externa via Shodan
    
    Args:
        company_name: Nome da empresa
    
    Returns:
        Dict com assets externos, vulnerabilidades, países, organizações
    """
    company_info = get_company_metadata(company_name if company_name.strip() else None)
    if not company_info:
        return {"error": "Empresa não encontrada"}
    
    domains = company_info.get("domains", [])
    company_slug = company_info.get("slug", "")
    
    domain_ips, all_ips = resolve_domain_ips(domains)
    return get_shodan_exposure(all_ips, company_slug)

@mcp.tool()
def surface_report_json(company_name: str = "") -> Dict[str, Any]:
    """
    Gera relatório completo de superfície em formato JSON
    
    Args:
        company_name: Nome da empresa
    
    Returns:
        Dict completo com todas as análises
    """
    company_info = get_company_metadata(company_name if company_name.strip() else None)
    if not company_info:
        return {"error": "Empresa não encontrada"}
    
    company_name = company_info["name"]
    company_slug = company_info["slug"]
    domains = company_info["domains"]
    
    # Resolve IPs
    domain_ips, all_ips = resolve_domain_ips(domains)
    
    # Coleta análises
    dns_analysis = analyze_dns_security(company_slug, domains)
    shodan_data = get_shodan_exposure(all_ips, company_slug)
    web_surface = get_web_surface(company_slug)
    leak_data = check_data_leaks(domains)
    
    # Calcula status crítico
    critical_issues = 0
    if leak_data['total'] > 0:
        critical_issues += 1
    if shodan_data['summary']['total_vulnerabilities'] > 50:
        critical_issues += 1
    
    if leak_data['total'] > 0:
        status = "CRÍTICO"
    elif critical_issues >= 2:
        status = "ATENÇÃO"
    else:
        status = "BOM"
    
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "company": {
            "name": company_name,
            "slug": company_slug,
            "domains": domains,
            "domain_ips": domain_ips,
            "total_ips": len(all_ips)
        },
        "status": status,
        "summary": {
            "domains_analyzed": len(domains),
            "unique_ips": len(all_ips),
            "external_assets": shodan_data['summary']['total_assets'],
            "web_endpoints": web_surface['total_endpoints'],
            "vulnerabilities": shodan_data['summary']['total_vulnerabilities'],
            "credentials_leaked": leak_data['total']
        },
        "dns_security": dns_analysis,
        "external_exposure": shodan_data,
        "web_surface": web_surface,
        "data_leaks": leak_data
    }

@mcp.tool()
def surface_report(company_name: str = "") -> str:
    """
    Gera relatório completo de superfície em formato Markdown
    
    Args:
        company_name: Nome da empresa
    
    Returns:
        String em formato Markdown com o relatório completo
    """
    # Pega dados JSON
    data = surface_report_json(company_name)
    
    if "error" in data:
        return f"❌ Erro: {data['error']}"
    
    # Gera markdown
    company = data["company"]
    summary = data["summary"] 
    status = data["status"]
    leaks = data["data_leaks"]
    shodan = data["external_exposure"]
    web = data["web_surface"]
    dns = data["dns_security"]
    
    md = []
    
    # Header
    md.append(f"# 🔍 Relatório de Análise de Superfície - {company['name']}")
    md.append("")
    md.append(f"**Data**: {data['generated_at'][:19]} UTC")
    md.append(f"**Domínios**: {', '.join(company['domains'])}")
    md.append(f"**IPs Resolvidos**: {company['total_ips']}")
    md.append("")
    
    # Status
    if status == "CRÍTICO":
        emoji = "🔴"
    elif status == "ATENÇÃO":
        emoji = "⚠️"
    else:
        emoji = "✅"
    
    md.append(f"## {emoji} Status: **{status}**")
    md.append("")
    
    # Resumo
    md.append("## 📋 Resumo Executivo")
    md.append("")
    md.append(f"- 🌐 **Domínios**: {summary['domains_analyzed']}")
    md.append(f"- 🖥️ **IPs únicos**: {summary['unique_ips']}")
    md.append(f"- 🔍 **Ativos externos**: {summary['external_assets']}")
    md.append(f"- 🌍 **Endpoints web**: {summary['web_endpoints']}")
    md.append(f"- ⚠️ **Vulnerabilidades**: {summary['vulnerabilities']}")
    md.append(f"- 💀 **Credenciais vazadas**: {summary['credentials_leaked']}")
    md.append("")
    
    # DNS
    if dns:
        md.append("## 🌐 Segurança DNS")
        md.append("")
        for item in dns:
            grade = item['grade']
            emoji = "✅" if grade in ['A', 'B'] else "⚠️" if grade == 'C' else "❌"
            md.append(f"### {emoji} {item['domain']} - Grade {grade} ({item['percentage']}%)")
            if item.get('recommendations'):
                md.append("**Recomendações:**")
                for rec in item['recommendations'][:2]:
                    md.append(f"- {rec.get('priority', '🟡')} **{rec.get('category')}**: {rec.get('recommendation', '')[:100]}...")
            md.append("")
    
    # Exposição Externa
    if shodan['summary']['total_assets'] > 0:
        md.append("## 🔍 Exposição Externa")
        md.append("")
        md.append(f"- **Ativos**: {shodan['summary']['total_assets']}")
        md.append(f"- **Vulnerabilidades**: {shodan['summary']['total_vulnerabilities']}")
        md.append(f"- **Países**: {', '.join(shodan['summary'].get('countries', []))}")
        md.append("")
        
        # Assets críticos
        critical = [a for a in shodan['assets'] if a['vulnerabilities'] > 10]
        if critical:
            md.append("### 🔴 Ativos Críticos")
            for asset in critical[:3]:
                md.append(f"- **{asset['ip']}**: {asset['vulnerabilities']} vulns, {asset['open_ports']} portas")
        md.append("")
    
    # Web
    if web['total_endpoints'] > 0:
        md.append("## 🌍 Superfície Web")
        md.append("")
        md.append(f"**Total**: {web['total_endpoints']} endpoints")
        md.append("")
        for status_code, count in sorted(web['status_distribution'].items()):
            emoji = "✅" if status_code == 200 else "🔒" if status_code in [401, 403] else "❌"
            md.append(f"- {emoji} **{status_code}**: {count} endpoints")
        md.append("")
    
    # Vazamentos - MAIS IMPORTANTE
    if leaks['total'] > 0:
        md.append("## 💀 Vazamentos de Dados")
        md.append("")
        md.append(f"🚨 **CRÍTICO**: {leaks['total']} credenciais encontradas!")
        md.append("")
        
        # Por domínio
        for domain, count in leaks['by_domain'].items():
            if count > 0:
                md.append(f"- 🔴 **{domain}**: {count} credenciais")
        md.append("")
        
        # Amostras
        if leaks['samples']:
            md.append("### 🔍 Amostras (Senhas Mascaradas)")
            md.append("")
            for sample in leaks['samples'][:5]:
                md.append(f"- `{sample['linha']}`")
                md.append(f"  - Arquivo: {sample['arquivo']}")
            md.append("")
            
            md.append("### 🚨 AÇÃO IMEDIATA NECESSÁRIA")
            md.append("- 🔴 Alterar **TODAS** as senhas expostas")
            md.append("- 🔴 Implementar 2FA em contas críticas")
            md.append("- 🟠 Auditar logs de acesso")
    else:
        md.append("## 💀 Vazamentos de Dados")
        md.append("")
        md.append("✅ Nenhuma credencial vazada encontrada")
    
    md.append("")
    md.append("---")
    md.append(f"*Relatório gerado via MCP Surface Analysis Server*")
    
    return "\n".join(md)

# ============================================================================
# MAIN - Servidor MCP
# ============================================================================

if __name__ == "__main__":
    # Teste de conectividade
    try:
        response = requests.get(f"{ES_URL}/", timeout=10)
        response.raise_for_status()
        logger.info(f"✅ Conectado ao Elasticsearch: {ES_URL}")
    except Exception as e:
        logger.error(f"❌ Erro de conexão com ES: {e}")
        sys.exit(1)
    
    logger.info("🚀 Iniciando MCP Surface Analysis Server...")
    logger.info("🛠️ Ferramentas disponíveis:")
    logger.info("  - ping: Health check")
    logger.info("  - get_company_info: Info da empresa")
    logger.info("  - check_leaks: Verifica vazamentos")
    logger.info("  - shodan_summary: Exposição externa")
    logger.info("  - surface_report: Relatório completo MD")
    logger.info("  - surface_report_json: Relatório completo JSON")
    
    # Roda servidor MCP via stdio
    mcp.run(transport="stdio")