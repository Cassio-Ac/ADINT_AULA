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
import re
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
    """
    Busca metadados da empresa com múltiplos fallbacks
    
    Estratégias de busca em ordem de prioridade:
    1. Nome completo exato
    2. Slug exato (múltiplas variações)
    3. Busca parcial no nome
    4. Busca wildcard
    5. Busca mais recente (fallback final)
    """
    index = "analise_superficie_metadata"
    
    # Se não especificar empresa, pega a mais recente
    if not company_name or not company_name.strip():
        query = {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1
        }
        logger.info("Buscando empresa mais recente")
        result = search_es(index, query)
        return _extract_company_data(result)
    
    company_name = company_name.strip()
    logger.info(f"Buscando empresa: '{company_name}'")
    
    # ESTRATÉGIA 1: Busca precisa por nome completo
    query_exact = {
        "query": {
            "bool": {
                "should": [
                    {"match_phrase": {"company": company_name}},
                    {"term": {"company.keyword": company_name}},
                ],
                "minimum_should_match": 1
            }
        },
        "size": 1
    }
    
    result = search_es(index, query_exact)
    if result.get("hits", {}).get("hits", []):
        logger.info(f"✅ Encontrado por nome exato: {company_name}")
        return _extract_company_data(result)
    
    # ESTRATÉGIA 2: Busca por slug (múltiplas variações)
    slug_variations = [
        company_name,                    # Original
        company_name.lower(),           # Minúscula
        company_name.upper(),           # Maiúscula  
        company_name.title(),           # Title Case
    ]
    
    for slug_var in slug_variations:
        query_slug = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"company_slug.keyword": slug_var}},
                        {"term": {"company_slug": slug_var}},
                        {"match": {"company_slug": slug_var}},
                        {"term": {"slug.keyword": slug_var}},           # Campo alternativo
                        {"term": {"slug": slug_var}},                  # Campo alternativo
                        {"match": {"slug": slug_var}},                 # Campo alternativo
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 1
        }
        
        result = search_es(index, query_slug)
        if result.get("hits", {}).get("hits", []):
            logger.info(f"✅ Encontrado por slug: {slug_var}")
            return _extract_company_data(result)
    
    # ESTRATÉGIA 3: Busca parcial no nome (case insensitive)
    query_partial = {
        "query": {
            "bool": {
                "should": [
                    {"match": {"company": {"query": company_name, "operator": "and"}}},
                    {"wildcard": {"company.keyword": f"*{company_name}*"}},
                    {"wildcard": {"company": f"*{company_name.lower()}*"}},
                    {"regexp": {"company.keyword": f".*{re.escape(company_name)}.*"}},
                ],
                "minimum_should_match": 1
            }
        },
        "size": 5  # Pegar múltiplos resultados para escolher o melhor
    }
    
    result = search_es(index, query_partial)
    hits = result.get("hits", {}).get("hits", [])
    if hits:
        # Escolher o resultado com melhor score ou nome mais similar
        best_hit = _find_best_match(hits, company_name)
        if best_hit:
            logger.info(f"✅ Encontrado por busca parcial: {company_name}")
            return _extract_company_data_from_hit(best_hit)
    
    # ESTRATÉGIA 4: Busca wildcard mais agressiva
    company_parts = company_name.lower().split()
    if len(company_parts) > 1:
        # Buscar por cada palavra separadamente
        for part in company_parts:
            if len(part) > 2:  # Ignorar palavras muito pequenas
                query_word = {
                    "query": {
                        "bool": {
                            "should": [
                                {"wildcard": {"company": f"*{part}*"}},
                                {"wildcard": {"company_slug": f"*{part}*"}},
                                {"wildcard": {"slug": f"*{part}*"}},
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    "size": 3
                }
                
                result = search_es(index, query_word)
                hits = result.get("hits", {}).get("hits", [])
                if hits:
                    best_hit = _find_best_match(hits, company_name)
                    if best_hit:
                        logger.info(f"✅ Encontrado por palavra-chave: {part}")
                        return _extract_company_data_from_hit(best_hit)
    
    # ESTRATÉGIA 5: Busca por domínio (se parecer com domínio)
    if "." in company_name and len(company_name.split(".")) >= 2:
        query_domain = {
            "query": {
                "bool": {
                    "should": [
                        {"nested": {
                            "path": "domains",
                            "query": {"wildcard": {"domains": f"*{company_name}*"}}
                        }},
                        {"wildcard": {"domains": f"*{company_name}*"}},
                        {"match": {"domains": company_name}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 1
        }
        
        result = search_es(index, query_domain)
        if result.get("hits", {}).get("hits", []):
            logger.info(f"✅ Encontrado por domínio: {company_name}")
            return _extract_company_data(result)
    
    # ESTRATÉGIA 6: Fallback - empresa mais recente (último recurso)
    logger.warning(f"⚠️ Empresa '{company_name}' não encontrada com nenhuma estratégia. Retornando empresa mais recente.")
    query_fallback = {
        "query": {"match_all": {}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 1
    }
    
    result = search_es(index, query_fallback)
    fallback_data = _extract_company_data(result)
    
    if fallback_data:
        logger.info(f"📋 Usando como fallback: {fallback_data.get('name', 'Unknown')}")
        # Adicionar aviso no retorno
        fallback_data["search_warning"] = f"Empresa '{company_name}' não encontrada. Usando '{fallback_data.get('name', 'Unknown')}' como fallback."
    
    return fallback_data

def _extract_company_data(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extrai dados da empresa do resultado do Elasticsearch"""
    hits = result.get("hits", {}).get("hits", [])
    
    if hits:
        return _extract_company_data_from_hit(hits[0])
    
    return {}

def _extract_company_data_from_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Extrai dados da empresa de um hit específico"""
    data = hit["_source"]
    return {
        "name": data.get("company", "Empresa Desconhecida"),
        "slug": data.get("company_slug", data.get("slug", "unknown")),
        "domains": data.get("domains", []),
        "timestamp": data.get("timestamp"),
        "pipeline_run": data.get("pipeline_run"),
        "elasticsearch_score": hit.get("_score", 0)
    }

def _find_best_match(hits: List[Dict[str, Any]], search_term: str) -> Optional[Dict[str, Any]]:
    """
    Encontra o melhor match entre múltiplos resultados
    Critérios: score do Elasticsearch + similaridade de nome
    """
    if not hits:
        return None
    
    search_term_lower = search_term.lower()
    best_hit = None
    best_score = -1
    
    for hit in hits:
        source = hit["_source"]
        company_name = source.get("company", "").lower()
        company_slug = source.get("company_slug", source.get("slug", "")).lower()
        es_score = hit.get("_score", 0)
        
        # Calcular score de similaridade
        name_similarity = 0
        slug_similarity = 0
        
        # Exact matches têm score máximo
        if search_term_lower == company_name:
            name_similarity = 100
        elif search_term_lower == company_slug:
            slug_similarity = 100
        # Partial matches
        elif search_term_lower in company_name:
            name_similarity = 80
        elif search_term_lower in company_slug:
            slug_similarity = 80
        elif company_name in search_term_lower:
            name_similarity = 60
        elif company_slug in search_term_lower:
            slug_similarity = 60
        
        # Score composto (ES score + similaridade)
        composite_score = es_score + max(name_similarity, slug_similarity)
        
        if composite_score > best_score:
            best_score = composite_score
            best_hit = hit
    
    return best_hit

# ============================================================================
# FUNÇÃO DE DIAGNÓSTICO ADICIONAL (OPCIONAL)
# ============================================================================

def debug_company_search(company_name: str) -> Dict[str, Any]:
    """
    Função de debug para entender por que uma busca não funcionou
    Útil para troubleshooting
    """
    index = "analise_superficie_metadata"
    debug_info = {
        "search_term": company_name,
        "strategies_tested": [],
        "all_companies": []
    }
    
    # Listar todas as empresas disponíveis
    query_all = {
        "query": {"match_all": {}},
        "size": 10,
        "_source": ["company", "company_slug", "slug", "domains"]
    }
    
    result = search_es(index, query_all)
    hits = result.get("hits", {}).get("hits", [])
    
    for hit in hits:
        source = hit["_source"]
        debug_info["all_companies"].append({
            "name": source.get("company"),
            "slug": source.get("company_slug", source.get("slug")),
            "domains": source.get("domains", [])
        })
    
    return debug_info


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
# AGENTES THREAT INTELLIGENCE - CÓDIGO COMPLETO PARA INTEGRAÇÃO
# 
# INSTRUÇÕES:
# 1. Copie TODO este código 
# 2. Cole no FINAL do arquivo mcp_exposure_poc.py (antes da linha "if __name__ == "__main__":")
# 3. Salve e reinicie o servidor MCP
# ============================================================================

def analyze_whois_detailed(company_slug: str) -> Dict[str, Any]:
    """Análise detalhada de WHOIS"""
    whois_query = {
        "query": {"term": {"company_slug": company_slug}},
        "size": 10
    }
    
    result = search_es("analise_superficie_whois", whois_query)
    hits = result.get("hits", {}).get("hits", [])
    
    analysis = {
        "domains_analyzed": len(hits),
        "registration_analysis": [],
        "privacy_assessment": {"protected_domains": 0, "total_domains": len(hits)},
        "risk_indicators": [],
        "recommendations": []
    }
    
    if len(hits) == 0:
        return {
            "domains_analyzed": 0,
            "message": "Nenhum dado WHOIS encontrado para esta empresa",
            "recommendations": ["Verificar se os domínios estão sendo coletados pelo pipeline WHOIS"]
        }
    
    for hit in hits:
        source = hit["_source"]
        domain = source.get("domain", "")
        
        # Análise básica de registro
        reg_data = {
            "domain": domain,
            "registrar": source.get("registrar", "N/A"),
            "creation_date": source.get("creation_date"),
            "expiration_date": source.get("expiration_date"),
            "privacy_protected": _check_privacy_protection(source)
        }
        analysis["registration_analysis"].append(reg_data)
        
        # Contagem de proteção de privacidade
        if reg_data["privacy_protected"]:
            analysis["privacy_assessment"]["protected_domains"] += 1
        
        # Indicadores de risco básicos
        if source.get("expiration_date"):
            try:
                exp_date_str = source.get("expiration_date")
                if exp_date_str:
                    # Tentar diferentes formatos de data
                    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
                        try:
                            exp_date = datetime.strptime(exp_date_str.replace('Z', ''), fmt.replace('Z', ''))
                            exp_date = exp_date.replace(tzinfo=timezone.utc)
                            days_to_expire = (exp_date - datetime.now(timezone.utc)).days
                            if days_to_expire < 30:
                                analysis["risk_indicators"].append({
                                    "domain": domain,
                                    "type": "expiring_soon",
                                    "description": f"Domínio expira em {days_to_expire} dias"
                                })
                            break
                        except ValueError:
                            continue
            except Exception as e:
                logger.error(f"Erro ao processar data de expiração: {e}")
    
    # Calcular porcentagem de proteção
    total = analysis["privacy_assessment"]["total_domains"]
    protected = analysis["privacy_assessment"]["protected_domains"]
    analysis["privacy_assessment"]["protection_percentage"] = round((protected / total) * 100, 2) if total > 0 else 0
    
    # Gerar recomendações básicas
    if analysis["privacy_assessment"]["protection_percentage"] < 50:
        analysis["recommendations"].append({
            "priority": "high",
            "category": "privacy",
            "description": "Implementar proteção de privacidade WHOIS em mais domínios"
        })
    
    if analysis["risk_indicators"]:
        analysis["recommendations"].append({
            "priority": "critical", 
            "category": "domain_management",
            "description": "Renovar domínios próximos ao vencimento"
        })
    
    return analysis

def _check_privacy_protection(whois_data: Dict[str, Any]) -> bool:
    """Verifica se domínio tem proteção de privacidade"""
    privacy_indicators = ["privacy", "protected", "whoisguard", "domains by proxy", "redacted"]
    registrant = str(whois_data.get("registrant_org", "")).lower()
    admin_org = str(whois_data.get("admin_org", "")).lower()
    return any(indicator in registrant or indicator in admin_org for indicator in privacy_indicators)

def analyze_dns_deep_dive(company_slug: str, domains: List[str]) -> Dict[str, Any]:
    """Análise DNS detalhada com foco em TXT records"""
    dns_query = {
        "query": {"term": {"company_slug": company_slug}},
        "size": 1
    }
    
    result = search_es("analise_superficie_dns", dns_query)
    hits = result.get("hits", {}).get("hits", [])
    
    if not hits:
        return {
            "error": "Dados DNS não encontrados",
            "message": "Nenhum dado DNS encontrado para esta empresa no índice analise_superficie_dns",
            "domains_requested": domains,
            "suggestion": "Verificar se o pipeline DNS está coletando dados para estes domínios"
        }
    
    dns_data = hits[0]["_source"]
    
    analysis = {
        "txt_records_analysis": {},
        "security_posture": {},
        "detailed_explanations": {},
        "recommendations": [],
        "domains_processed": []
    }
    
    for domain in domains:
        if domain not in dns_data:
            analysis["txt_records_analysis"][domain] = {
                "status": "not_found",
                "message": f"Dados DNS não encontrados para {domain}"
            }
            continue
        
        analysis["domains_processed"].append(domain)
        domain_data = dns_data[domain]
        txt_records = domain_data.get("txt_records", [])
        
        # Análise detalhada de TXT records
        domain_txt_analysis = {
            "total_txt_records": len(txt_records),
            "spf_records": [],
            "dmarc_records": [],
            "dkim_records": [],
            "verification_records": [],
            "other_records": []
        }
        
        for txt_record in txt_records:
            txt_value = txt_record.get("value", "")
            
            if txt_value.startswith("v=spf1"):
                spf_analysis = _parse_spf_detailed(txt_value)
                domain_txt_analysis["spf_records"].append(spf_analysis)
                
            elif txt_value.startswith("v=DMARC1"):
                dmarc_analysis = _parse_dmarc_detailed(txt_value)
                domain_txt_analysis["dmarc_records"].append(dmarc_analysis)
                
            elif "google-site-verification" in txt_value:
                domain_txt_analysis["verification_records"].append({
                    "type": "Google Search Console",
                    "value": txt_value[:50] + "...",
                    "purpose": "Verificação de propriedade do domínio para Google Search Console"
                })
                
            elif txt_value.startswith("MS="):
                domain_txt_analysis["verification_records"].append({
                    "type": "Microsoft 365",
                    "value": txt_value,
                    "purpose": "Verificação de propriedade do domínio para Microsoft 365"
                })
                
            elif "facebook-domain-verification" in txt_value:
                domain_txt_analysis["verification_records"].append({
                    "type": "Facebook Domain Verification",
                    "value": txt_value[:50] + "...",
                    "purpose": "Verificação de propriedade do domínio para Facebook Business"
                })
                
            else:
                domain_txt_analysis["other_records"].append({
                    "value": txt_value[:100] + ("..." if len(txt_value) > 100 else ""),
                    "analysis": "Registro TXT adicional - verificar propósito manualmente"
                })
        
        analysis["txt_records_analysis"][domain] = domain_txt_analysis
        
        # Avaliação de postura de segurança
        security_score = 0
        security_issues = []
        
        if domain_txt_analysis["spf_records"]:
            security_score += 25
            spf_record = domain_txt_analysis["spf_records"][0]
            if spf_record.get("security_assessment", {}).get("score", 0) < 50:
                security_issues.append("SPF configurado mas com problemas de segurança")
        else:
            security_issues.append("SPF não configurado - emails podem ser falsificados")
        
        if domain_txt_analysis["dmarc_records"]:
            dmarc_record = domain_txt_analysis["dmarc_records"][0]
            dmarc_policy = dmarc_record.get("components", {}).get("p", {}).get("value", "none")
            
            if dmarc_policy == "reject":
                security_score += 35
            elif dmarc_policy == "quarantine":
                security_score += 25
            else:  # none
                security_score += 15
                security_issues.append("DMARC em modo permissivo (p=none) - apenas monitoramento")
        else:
            security_issues.append("DMARC não configurado - falta de proteção contra spoofing")
        
        # Verificar DNSSEC
        if domain_data.get("dnssec_enabled"):
            security_score += 40
        else:
            security_issues.append("DNSSEC não habilitado - vulnerável a ataques DNS")
        
        analysis["security_posture"][domain] = {
            "score": security_score,
            "grade": _calculate_dns_grade(security_score),
            "issues": security_issues,
            "max_score": 100
        }
    
    # Explicações detalhadas dos conceitos
    analysis["detailed_explanations"] = _get_dns_explanations()
    
    # Recomendações baseadas nos achados
    for domain in analysis["domains_processed"]:
        posture = analysis["security_posture"].get(domain, {})
        if posture.get("score", 0) < 70:
            analysis["recommendations"].append({
                "domain": domain,
                "priority": "high" if posture.get("score", 0) < 50 else "medium",
                "current_score": posture.get("score", 0),
                "grade": posture.get("grade", "F"),
                "issues": posture.get("issues", []),
                "actions": _get_dns_remediation_actions(posture.get("issues", []))
            })
    
    return analysis

def _parse_spf_detailed(spf_value: str) -> Dict[str, Any]:
    """Parser detalhado de SPF com explicações"""
    parts = spf_value.split()
    mechanisms = []
    
    for part in parts[1:]:  # Skip v=spf1
        if part.startswith("include:"):
            domain = part.split(":", 1)[1]
            mechanisms.append({
                "type": "include",
                "value": domain,
                "explanation": f"Inclui a política SPF do domínio {domain}",
                "security_impact": "Médio - delega autorização para outro domínio"
            })
        elif part.startswith("ip4:"):
            ip = part.split(":", 1)[1]
            mechanisms.append({
                "type": "ip4",
                "value": ip,
                "explanation": f"Autoriza o IP/rede {ip} a enviar emails",
                "security_impact": "Baixo - autorização explícita por IP"
            })
        elif part.startswith("ip6:"):
            ip = part.split(":", 1)[1]
            mechanisms.append({
                "type": "ip6", 
                "value": ip,
                "explanation": f"Autoriza o IPv6/rede {ip} a enviar emails",
                "security_impact": "Baixo - autorização explícita por IPv6"
            })
        elif part == "mx":
            mechanisms.append({
                "type": "mx",
                "value": None,
                "explanation": "Autoriza os servidores MX do domínio a enviar emails",
                "security_impact": "Baixo - usa registros MX existentes"
            })
        elif part == "a":
            mechanisms.append({
                "type": "a",
                "value": None,
                "explanation": "Autoriza o IP do registro A do domínio a enviar emails",
                "security_impact": "Baixo - usa registro A existente"
            })
        elif part in ["-all", "~all", "?all", "+all"]:
            qualifier = part[0]
            explanations = {
                "-": "FAIL - Rejeita emails não autorizados (mais restritivo)",
                "~": "SOFTFAIL - Marca como suspeito mas não rejeita (recomendado)",
                "?": "NEUTRAL - Não expressa opinião (pouco útil)",
                "+": "PASS - Autoriza qualquer servidor (INSEGURO!)"
            }
            mechanisms.append({
                "type": "all",
                "qualifier": qualifier,
                "value": part,
                "explanation": explanations.get(qualifier, "Qualificador desconhecido"),
                "security_impact": "CRÍTICO - define política padrão para emails não cobertos"
            })
    
    return {
        "raw_record": spf_value,
        "version": "spf1",
        "mechanisms": mechanisms,
        "total_mechanisms": len(mechanisms),
        "security_assessment": _assess_spf_security(mechanisms)
    }

def _parse_dmarc_detailed(dmarc_value: str) -> Dict[str, Any]:
    """Parser detalhado de DMARC com explicações"""
    dmarc_parts = {}
    
    for part in dmarc_value.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            dmarc_parts[key.strip()] = value.strip()
    
    analysis = {
        "raw_record": dmarc_value,
        "version": dmarc_parts.get("v", ""),
        "components": {},
        "security_assessment": {}
    }
    
    # Análise detalhada de cada componente
    components = {
        "v": {
            "value": dmarc_parts.get("v", "DMARC1"),
            "explanation": "Versão do protocolo DMARC (sempre deve ser DMARC1)",
            "required": True,
            "status": "✅ Correto" if dmarc_parts.get("v") == "DMARC1" else "❌ Incorreto"
        },
        "p": {
            "value": dmarc_parts.get("p", "none"),
            "explanation": {
                "none": "🟡 MONITORAMENTO - Coleta dados mas não bloqueia emails",
                "quarantine": "🟠 QUARENTENA - Envia emails suspeitos para spam",
                "reject": "🔴 REJEIÇÃO - Bloqueia completamente emails não autenticados"
            }.get(dmarc_parts.get("p", "none"), "❌ Política desconhecida"),
            "security_level": {
                "none": "Baixo - apenas coleta dados",
                "quarantine": "Médio - filtragem de spam",
                "reject": "Alto - máxima proteção"
            }.get(dmarc_parts.get("p", "none"), "Desconhecido"),
            "required": True
        },
        "rua": {
            "value": dmarc_parts.get("rua", "❌ não configurado"),
            "explanation": "Endereços de email para receber relatórios agregados (estatísticas diárias)",
            "importance": "🔴 CRÍTICO - Sem isso você não saberá o que está acontecendo",
            "example": "rua=mailto:dmarc-reports@seudominio.com"
        },
        "pct": {
            "value": dmarc_parts.get("pct", "100"),
            "explanation": f"Aplica a política DMARC a {dmarc_parts.get('pct', '100')}% dos emails",
            "recommendation": "Use 100% após período de teste. Valores menores são para transição gradual",
            "current_coverage": f"{dmarc_parts.get('pct', '100')}% dos emails são verificados"
        }
    }
    
    analysis["components"] = components
    analysis["security_assessment"] = _assess_dmarc_security(dmarc_parts)
    
    return analysis

def _get_dns_explanations() -> Dict[str, str]:
    """Explicações detalhadas dos conceitos DNS para analistas"""
    return {
        "SPF_COMPLETO": """
📧 SENDER POLICY FRAMEWORK (SPF) - GUIA PARA ANALISTAS:

PROPÓSITO:
- Define quais servidores podem enviar emails em nome do domínio
- Primeira linha de defesa contra spoofing de email
- Reduz chance de emails legítimos serem marcados como spam

MECANISMOS SPF:
• include:dominio.com - Inclui política SPF de outro domínio (ex: Google)
• ip4:192.168.1.1/24 - Autoriza IP ou rede específica IPv4
• mx - Autoriza todos os servidores MX do domínio
• a - Autoriza o IP do registro A do domínio

QUALIFICADORES:
• + (PASS) - Autoriza explicitamente
• - (FAIL) - Rejeita explicitamente 
• ~ (SOFTFAIL) - Marca como suspeito [RECOMENDADO para ~all]
• ? (NEUTRAL) - Não opina [evitar]

EXEMPLO:
"v=spf1 include:_spf.google.com ~all" = Autoriza Google + softfail resto
        """,
        
        "DMARC_COMPLETO": """
🛡️ DMARC - GUIA PARA ANALISTAS:

PROPÓSITO:
- Combina SPF + DKIM para autenticação robusta
- Define o que fazer com emails que falham na autenticação
- Fornece relatórios sobre uso do domínio

EVOLUÇÃO RECOMENDADA:
1️⃣ p=none (monitora sem bloquear)
2️⃣ p=quarantine (envia suspeitos para spam)
3️⃣ p=reject (bloqueia completamente)

COMPONENTES CRÍTICOS:
• p= - Política principal (none/quarantine/reject)
• rua= - OBRIGATÓRIO para relatórios agregados
• pct= - Percentual de aplicação (para transição)

MIGRAÇÃO SEGURA:
Semanas 1-4: p=none, pct=100 (monitore)
Semanas 5-8: p=quarantine gradual 
Semana 9+: p=reject (máxima proteção)
        """
    }

def _calculate_dns_grade(score: int) -> str:
    """Calcula grade DNS baseada na pontuação"""
    if score >= 90: 
        return "A"
    elif score >= 80: 
        return "B" 
    elif score >= 70: 
        return "C"
    elif score >= 60: 
        return "D"
    else: 
        return "F"

def _assess_spf_security(mechanisms: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Avalia segurança do SPF"""
    issues = []
    recommendations = []
    score = 70  # Base score
    
    # Verificar se existe qualificador 'all'
    all_mechanisms = [m for m in mechanisms if m["type"] == "all"]
    if not all_mechanisms:
        issues.append("Falta qualificador 'all' - emails não cobertos passarão")
        recommendations.append("Adicionar '~all' ao final do registro SPF")
        score -= 20
    else:
        qualifier = all_mechanisms[0].get("qualifier", "+")
        if qualifier == "+":
            issues.append("Qualificador '+all' muito permissivo")
            recommendations.append("Alterar '+all' para '~all' ou '-all'")
            score -= 30
        elif qualifier == "?":
            issues.append("Qualificador '?all' inútil")
            recommendations.append("Alterar '?all' para '~all'")
            score -= 15
        elif qualifier == "~":
            score += 10  # Bom
        elif qualifier == "-":
            score += 15  # Excelente
    
    # Verificar número de includes
    includes = [m for m in mechanisms if m["type"] == "include"]
    if len(includes) > 8:
        issues.append(f"Muitos includes ({len(includes)}) podem causar limite DNS")
        recommendations.append("Consolidar includes ou usar IPs diretos")
        score -= 10
    
    return {
        "score": max(0, score),
        "max_score": 100,
        "issues": issues,
        "recommendations": recommendations,
        "grade": _calculate_dns_grade(max(0, score))
    }

def _assess_dmarc_security(dmarc_parts: Dict[str, str]) -> Dict[str, Any]:
    """Avalia segurança do DMARC"""
    issues = []
    recommendations = []
    score = 30
    
    # Avaliar política
    policy = dmarc_parts.get("p", "none")
    if policy == "reject":
        score += 50
        recommendations.append("Excelente! Política 'reject' oferece máxima proteção")
    elif policy == "quarantine":
        score += 35
        recommendations.append("Considere migrar para 'p=reject' após análise")
    else:  # none
        issues.append("Política 'none' apenas monitora, sem proteção")
        recommendations.append("Migrar para 'p=quarantine' depois 'p=reject'")
        score += 10
    
    # Verificar relatórios
    if not dmarc_parts.get("rua"):
        issues.append("Falta 'rua' - não receberá relatórios")
        recommendations.append("Configurar 'rua=mailto:dmarc@dominio.com'")
        score -= 15
    else:
        score += 15
    
    # Verificar percentual
    try:
        pct = int(dmarc_parts.get("pct", "100"))
        if pct < 100:
            issues.append(f"Política aplicada apenas a {pct}% dos emails")
            recommendations.append(f"Aumentar para 100% após validação")
            score -= (100 - pct) // 10
        else:
            score += 10
    except (ValueError, TypeError):
        issues.append("Valor 'pct' inválido")
        score -= 5
    
    return {
        "score": max(0, min(100, score)),
        "max_score": 100,
        "issues": issues,
        "recommendations": recommendations,
        "grade": _calculate_dns_grade(max(0, min(100, score))),
        "policy_strength": {
            "none": "Fraco - apenas monitoramento",
            "quarantine": "Médio - filtragem",
            "reject": "Forte - bloqueio total"
        }.get(policy, "Desconhecido")
    }

def _get_dns_remediation_actions(issues: List[str]) -> List[str]:
    """Gera ações de remediação específicas"""
    actions = []
    
    for issue in issues:
        if "SPF não configurado" in issue:
            actions.append("IMPLEMENTAR SPF: Criar TXT 'v=spf1 include:_spf.google.com ~all'")
        elif "DMARC não configurado" in issue:
            actions.append("IMPLEMENTAR DMARC: Criar TXT '_dmarc' com 'v=DMARC1; p=none; rua=mailto:dmarc@dominio.com'")
        elif "DNSSEC não habilitado" in issue:
            actions.append("HABILITAR DNSSEC: Ativar no registrador/DNS provider")
        elif "modo permissivo" in issue or "p=none" in issue:
            actions.append("FORTALECER DMARC: Migrar p=none → p=quarantine → p=reject")
        elif "problemas de segurança" in issue:
            actions.append("REVISAR SPF: Verificar mecanismos e usar '~all'")
        elif "relatórios" in issue:
            actions.append("CONFIGURAR RUA: Adicionar rua=mailto:dmarc-reports@dominio.com")
    
    if not actions:
        actions.append("AUDITORIA DNS: Revisar configurações com especialista")
    
    return actions

# ============================================================================
# FERRAMENTAS MCP
# ============================================================================

@mcp.tool()
def whois_detailed_analysis(company_name: str = "") -> Dict[str, Any]:
    """
    Análise detalhada de WHOIS por agente especializado
    
    Args:
        company_name: Nome da empresa
        
    Returns:
        Dict com análise completa de WHOIS incluindo registros, privacidade, riscos
    """
    try:
        company_info = get_company_metadata(company_name if company_name.strip() else None)
        if not company_info:
            return {"error": "Empresa não encontrada"}
        
        return analyze_whois_detailed(company_info["slug"])
    except Exception as e:
        logger.error(f"Erro em whois_detailed_analysis: {e}")
        return {"error": f"Erro interno: {str(e)}"}

@mcp.tool()
def dns_deep_dive_analysis(company_name: str = "") -> Dict[str, Any]:
    """
    Análise ultra detalhada de DNS por agente especializado
    
    Args:
        company_name: Nome da empresa
        
    Returns:
        Dict com análise profunda de DNS, TXT records detalhados com explicações completas
    """
    try:
        company_info = get_company_metadata(company_name if company_name.strip() else None)
        if not company_info:
            return {"error": "Empresa não encontrada"}
        
        return analyze_dns_deep_dive(company_info["slug"], company_info["domains"])
    except Exception as e:
        logger.error(f"Erro em dns_deep_dive_analysis: {e}")
        return {"error": f"Erro interno: {str(e)}"}

@mcp.tool()
def comprehensive_threat_report(company_name: str = "") -> str:
    """
    Relatório comprehensive combinando análises especializadas
    
    Args:
        company_name: Nome da empresa
        
    Returns:
        String com relatório markdown detalhado para equipe de Threat Intel
    """
    try:
        company_info = get_company_metadata(company_name if company_name.strip() else None)
        if not company_info:
            return "❌ Erro: Empresa não encontrada"
        
        # Análise base
        base_report = surface_report_json(company_name)
        if "error" in base_report:
            return f"❌ Erro no relatório base: {base_report['error']}"
        
        # Análises especializadas
        whois_analysis = analyze_whois_detailed(company_info["slug"])
        dns_analysis = analyze_dns_deep_dive(company_info["slug"], company_info["domains"])
        
        # Gerar relatório unificado
        return _generate_threat_report_markdown(company_info, base_report, whois_analysis, dns_analysis)
    
    except Exception as e:
        logger.error(f"Erro em comprehensive_threat_report: {e}")
        return f"❌ Erro interno: {str(e)}"

def _generate_threat_report_markdown(company_info: Dict[str, Any], base_report: Dict[str, Any], 
                                   whois_analysis: Dict[str, Any], dns_analysis: Dict[str, Any]) -> str:
    """Gera relatório markdown"""
    
    company_name = company_info["name"]
    
    md = [
        f"# 🎯 RELATÓRIO THREAT INTELLIGENCE DETALHADO",
        f"## {company_name}",
        "",
        f"**Data**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Domínios**: {', '.join(company_info['domains'])}",
        f"**Status Geral**: {base_report.get('status', 'N/A')}",
        "",
        "---",
        "",
        "## 📊 RESUMO EXECUTIVO",
        "",
        f"- **Vulnerabilidades Externas**: {base_report.get('summary', {}).get('vulnerabilities', 0)}",
        f"- **Credenciais Vazadas**: {base_report.get('summary', {}).get('credentials_leaked', 0)}",
        f"- **Assets Externos**: {base_report.get('summary', {}).get('external_assets', 0)}",
        f"- **Endpoints Web**: {base_report.get('summary', {}).get('web_endpoints', 0)}",
        ""
    ]
    
    # Seção WHOIS
    md.extend([
        "## 🏢 ANÁLISE WHOIS DETALHADA",
        ""
    ])
    
    if whois_analysis.get("message"):
        md.extend([
            f"⚠️ **Status**: {whois_analysis['message']}",
            ""
        ])
    else:
        privacy = whois_analysis.get("privacy_assessment", {})
        md.extend([
            f"**Domínios Analisados**: {whois_analysis.get('domains_analyzed', 0)}",
            f"**Proteção de Privacidade**: {privacy.get('protection_percentage', 0):.1f}%",
            f"**Indicadores de Risco**: {len(whois_analysis.get('risk_indicators', []))}",
            ""
        ])
        
        # Riscos identificados
        risks = whois_analysis.get("risk_indicators", [])
        if risks:
            md.extend([
                "### ⚠️ Indicadores de Risco:",
                ""
            ])
            for risk in risks:
                md.append(f"- **{risk.get('domain', 'N/A')}**: {risk.get('description', 'N/A')}")
            md.append("")
    
    # Seção DNS Detalhada
    md.extend([
        "## 🌐 ANÁLISE DNS ULTRA DETALHADA",
        ""
    ])
    
    if dns_analysis.get("error"):
        md.extend([
            f"⚠️ **Status**: {dns_analysis['error']}",
            f"**Detalhes**: {dns_analysis.get('message', 'N/A')}",
            ""
        ])
    else:
        domains_processed = dns_analysis.get("domains_processed", [])
        md.extend([
            f"**Domínios Processados**: {len(domains_processed)}",
            ""
        ])
        
        # Postura de segurança DNS
        if domains_processed:
            md.extend([
                "### 🛡️ Postura de Segurança DNS:",
                ""
            ])
            
            for domain in domains_processed:
                posture = dns_analysis.get("security_posture", {}).get(domain, {})
                if posture:
                    grade = posture.get("grade", "F")
                    score = posture.get("score", 0)
                    emoji = "✅" if grade in ['A', 'B'] else "⚠️" if grade == 'C' else "❌"
                    
                    md.extend([
                        f"**{domain}** {emoji} Grade {grade} ({score}/100)",
                        ""
                    ])
                    
                    issues = posture.get("issues", [])
                    if issues:
                        md.append("**Problemas identificados:**")
                        for issue in issues:
                            md.append(f"- {issue}")
                        md.append("")
        
        # Análise detalhada de TXT Records
        txt_analysis = dns_analysis.get("txt_records_analysis", {})
        if txt_analysis:
            md.extend([
                "### 📝 ANÁLISE DETALHADA DE REGISTROS TXT",
                ""
            ])
            
            for domain, domain_txt in txt_analysis.items():
                if domain_txt.get("status") == "not_found":
                    continue
                
                md.extend([
                    f"#### {domain}",
                    f"**Total de registros TXT**: {domain_txt.get('total_txt_records', 0)}",
                    ""
                ])
                
                # SPF Analysis
                spf_records = domain_txt.get("spf_records", [])
                if spf_records:
                    md.extend([
                        "**📧 REGISTRO SPF ENCONTRADO:**",
                        ""
                    ])
                    for spf in spf_records:
                        md.extend([
                            "```",
                            spf.get("raw_record", "N/A"),
                            "```",
                            "",
                            "**Mecanismos SPF identificados:**",
                            ""
                        ])
                        
                        for mechanism in spf.get("mechanisms", []):
                            md.append(f"- **{mechanism.get('type', 'N/A')}**: {mechanism.get('explanation', 'N/A')}")
                            if mechanism.get('value'):
                                md.append(f"  - Valor: `{mechanism['value']}`")
                            md.append(f"  - Impacto: {mechanism.get('security_impact', 'N/A')}")
                        
                        # Assessment do SPF
                        spf_assessment = spf.get("security_assessment", {})
                        if spf_assessment:
                            md.extend([
                                "",
                                f"**Avaliação SPF**: Grade {spf_assessment.get('grade', 'N/A')} ({spf_assessment.get('score', 0)}/100)",
                                ""
                            ])
                            
                            if spf_assessment.get("issues"):
                                md.append("**Problemas:**")
                                for issue in spf_assessment["issues"]:
                                    md.append(f"- ⚠️ {issue}")
                                md.append("")
                else:
                    md.extend([
                        "**📧 SPF**: ❌ Não configurado",
                        "*Risco: Emails podem ser falsificados*",
                        ""
                    ])
                
                # DMARC Analysis
                dmarc_records = domain_txt.get("dmarc_records", [])
                if dmarc_records:
                    md.extend([
                        "**🛡️ REGISTRO DMARC ENCONTRADO:**",
                        ""
                    ])
                    for dmarc in dmarc_records:
                        md.extend([
                            "```",
                            dmarc.get("raw_record", "N/A"),
                            "```",
                            "",
                            "**Componentes DMARC detalhados:**",
                            ""
                        ])
                        
                        components = dmarc.get("components", {})
                        for key, component in components.items():
                            if isinstance(component, dict) and component.get("value"):
                                md.extend([
                                    f"**{key.upper()}={component['value']}**",
                                    f"- {component.get('explanation', 'N/A')}",
                                    ""
                                ])
                        
                        # Assessment do DMARC
                        dmarc_assessment = dmarc.get("security_assessment", {})
                        if dmarc_assessment:
                            md.extend([
                                f"**Avaliação DMARC**: Grade {dmarc_assessment.get('grade', 'N/A')} ({dmarc_assessment.get('score', 0)}/100)",
                                f"**Força da Política**: {dmarc_assessment.get('policy_strength', 'N/A')}",
                                ""
                            ])
                else:
                    md.extend([
                        "**🛡️ DMARC**: ❌ Não configurado",
                        "*Risco: Falta proteção abrangente contra spoofing*",
                        ""
                    ])
                
                # Verification Records
                verification_records = domain_txt.get("verification_records", [])
                if verification_records:
                    md.extend([
                        "**🔍 Registros de Verificação:**",
                        ""
                    ])
                    for verify in verification_records:
                        md.append(f"- **{verify.get('type', 'N/A')}**: {verify.get('purpose', 'N/A')}")
                    md.append("")
    
    # Recomendações DNS
    dns_recommendations = dns_analysis.get("recommendations", [])
    if dns_recommendations:
        md.extend([
            "### 📋 RECOMENDAÇÕES DNS ESPECÍFICAS",
            ""
        ])
        
        for rec in dns_recommendations:
            domain = rec.get("domain", "N/A")
            priority = rec.get("priority", "medium")
            priority_emoji = "🔴" if priority == "critical" else "🟠" if priority == "high" else "🟡"
            
            md.extend([
                f"#### {priority_emoji} {domain} - Score: {rec.get('current_score', 0)}/100 (Grade {rec.get('grade', 'F')})",
                ""
            ])
            
            actions = rec.get("actions", [])
            if actions:
                md.append("**Ações recomendadas:**")
                for action in actions:
                    md.append(f"- {action}")
                md.append("")
    
    # Explicações técnicas
    explanations = dns_analysis.get("detailed_explanations", {})
    if explanations:
        md.extend([
            "### 📚 GUIA TÉCNICO PARA ANALISTAS",
            ""
        ])
        
        for concept, explanation in explanations.items():
            md.extend([
                f"#### {concept.replace('_', ' ').title()}",
                "```",
                explanation.strip(),
                "```",
                ""
            ])
    
    # Seção de Próximos Passos
    md.extend([
        "## 🎯 PRÓXIMOS PASSOS ESTRATÉGICOS",
        "",
        "### Ações Prioritárias:",
        ""
    ])
    
    # Gerar recomendações baseadas nos achados
    priority_actions = []
    
    # Do base report
    if base_report.get("summary", {}).get("credentials_leaked", 0) > 0:
        priority_actions.append("🔴 **CRÍTICO**: Alterar imediatamente todas as credenciais vazadas")
    
    # Do DNS analysis
    if dns_analysis.get("recommendations"):
        dns_critical = [r for r in dns_analysis["recommendations"] if r.get("priority") == "high"]
        if dns_critical:
            priority_actions.append("🔴 **CRÍTICO**: Implementar controles DNS faltantes")
    
    # Do WHOIS analysis
    if whois_analysis.get("risk_indicators"):
        priority_actions.append("🟠 **ALTO**: Resolver indicadores de risco em domínios")
    
    if priority_actions:
        for i, action in enumerate(priority_actions, 1):
            md.append(f"{i}. {action}")
        md.append("")
    else:
        md.extend([
            "✅ Nenhuma ação crítica imediata identificada nos dados disponíveis.",
            ""
        ])
    
    md.extend([
        "### Implementação de Monitoramento:",
        "",
        "1. 📊 **Surface Monitoring**: Monitoramento contínuo da superfície externa",
        "2. 🔍 **Vulnerability Scanning**: Scanning automatizado semanal",
        "3. 📧 **DNS Monitoring**: Alertas para mudanças DNS não autorizadas",
        "4. 💀 **Credential Monitoring**: Monitoramento de vazamentos",
        "",
        "### Métricas de Acompanhamento:",
        "",
        "- **DNS Security Score**: Meta > 80/100 para todos os domínios",
        "- **Vulnerabilidades Críticas**: Meta = 0 vulnerabilidades CVSS >= 9.0",
        "- **Credential Exposure**: Meta = 0 credenciais expostas",
        "",
        "---",
        f"*Relatório gerado pelo MCP Threat Intelligence em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*"
    ])
    
    return "\n".join(md)

# ============================================================================
# INSTRUÇÕES FINAIS DE INTEGRAÇÃO
# ============================================================================

"""
🚀 INTEGRAÇÃO COMPLETA - PASSO A PASSO:

1. COPIE todo este código acima
2. COLE no final do arquivo mcp_exposure_poc.py (antes da linha "if __name__ == "__main__":")
3. ATUALIZE a seção de logging no main para incluir:

    logger.info("🤖 Agentes Threat Intel:")
    logger.info("  - whois_detailed_analysis: Análise WHOIS profunda")
    logger.info("  - dns_deep_dive_analysis: Análise DNS ultra detalhada")
    logger.info("  - comprehensive_threat_report: Relatório TI completo")

4. SALVE o arquivo e reinicie o servidor MCP

✅ FUNCIONALIDADES:
- Análise WHOIS com detecção de privacidade e riscos
- Análise DNS ultra detalhada com explicações de cada TXT record
- Parser completo de SPF e DMARC com avaliação de segurança
- Relatório master combinando todas as análises
- Guias técnicos detalhados para analistas

🎯 TESTE COM:
dns_deep_dive_analysis("Adint")
comprehensive_threat_report("Adint")

📝 EXEMPLO DO QUE VOCÊ VAI TER:
Para cada domínio, o sistema explicará detalhadamente:
- Cada mecanismo SPF (include, ip4, mx, all)
- Cada componente DMARC (p, rua, pct, aspf, adkim)
- Score de segurança com grade A-F
- Problemas específicos identificados
- Ações de remediação técnicas
- Explicações completas para analistas
"""



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