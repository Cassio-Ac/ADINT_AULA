#!/usr/bin/env python3
"""
DNS Security Analyzer
Analisa configurações DNS e atribui pontuação de segurança
"""

import dns.resolver
import dns.query
import dns.name
import dns.dnssec
import dns.message
import dns.flags
import socket
import whois
import json
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import argparse
import re
from dataclasses import dataclass, asdict
import subprocess

@dataclass
class SecurityScore:
    """Classe para armazenar pontuações de segurança"""
    category: str
    description: str
    max_points: int
    earned_points: int
    details: str
    severity: str  # 'critical', 'high', 'medium', 'low'

class DNSSecurityAnalyzer:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.results = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "dns_records": {},
            "security_scores": [],
            "total_score": 0,
            "max_possible_score": 0,
            "grade": "",
            "recommendations": []
        }
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
        
    def analyze(self) -> Dict:
        """Executa análise completa do domínio"""
        print(f"\n🔍 Iniciando análise de segurança DNS para: {self.domain}")
        print("=" * 60)
        
        # Coleta registros DNS
        self._collect_dns_records()
        
        # Análises de segurança
        self._check_dnssec()
        self._analyze_spf()
        self._analyze_dmarc()
        self._analyze_dkim()
        self._check_caa()
        self._analyze_mx_records()
        self._analyze_nameservers()
        self._check_dane()
        self._analyze_txt_records()
        self._check_ipv6_support()
        
        # Calcula pontuação final
        self._calculate_final_score()
        
        # Gera recomendações
        self._generate_recommendations()
        
        return self.results
    
    def _collect_dns_records(self):
        """Coleta todos os registros DNS disponíveis"""
        record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CAA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                self.results["dns_records"][record_type] = [
                    answer.to_text() for answer in answers
                ]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                self.results["dns_records"][record_type] = []
    
    def _add_score(self, category: str, description: str, max_points: int, 
                   earned_points: int, details: str, severity: str = "medium"):
        """Adiciona uma pontuação de segurança"""
        score = SecurityScore(
            category=category,
            description=description,
            max_points=max_points,
            earned_points=earned_points,
            details=details,
            severity=severity
        )
        self.results["security_scores"].append(asdict(score))
        print(f"  [{category}] {earned_points}/{max_points} pontos - {details}")
    
    def _check_dnssec(self):
        """Verifica configuração DNSSEC"""
        print("\n🔐 Verificando DNSSEC...")
        try:
            # Verifica DNSKEY
            response = self.resolver.resolve(self.domain, 'DNSKEY', raise_on_no_answer=False)
            if response.rrset is not None:
                # Verifica assinatura
                try:
                    query = dns.message.make_query(self.domain, 'A', want_dnssec=True)
                    response = dns.query.udp(query, '8.8.8.8')
                    
                    if response.flags & dns.flags.AD:
                        self._add_score(
                            "DNSSEC", "Validação DNSSEC", 20, 20,
                            "✅ DNSSEC totalmente configurado e validado", "critical"
                        )
                    else:
                        self._add_score(
                            "DNSSEC", "Validação DNSSEC", 20, 10,
                            "⚠️ DNSSEC configurado mas não validado", "critical"
                        )
                except:
                    self._add_score(
                        "DNSSEC", "Validação DNSSEC", 20, 5,
                        "⚠️ DNSSEC parcialmente configurado", "critical"
                    )
            else:
                self._add_score(
                    "DNSSEC", "Validação DNSSEC", 20, 0,
                    "❌ DNSSEC não habilitado", "critical"
                )
        except Exception as e:
            self._add_score(
                "DNSSEC", "Validação DNSSEC", 20, 0,
                f"❌ Erro ao verificar DNSSEC: {str(e)}", "critical"
            )
    
    def _analyze_spf(self):
        """Analisa registro SPF"""
        print("\n📧 Analisando SPF...")
        txt_records = self.results["dns_records"].get("TXT", [])
        spf_records = [r for r in txt_records if 'v=spf1' in r.lower()]
        
        if not spf_records:
            self._add_score(
                "SPF", "Registro SPF", 15, 0,
                "❌ Nenhum registro SPF encontrado", "high"
            )
            return
        
        if len(spf_records) > 1:
            self._add_score(
                "SPF", "Registro SPF", 15, 5,
                "⚠️ Múltiplos registros SPF encontrados (deve haver apenas um)", "high"
            )
            return
        
        spf = spf_records[0].lower()
        points = 15
        details = []
        
        # Verifica terminadores
        if '-all' in spf:
            details.append("✅ Usa -all (fail)")
        elif '~all' in spf:
            points -= 3
            details.append("⚠️ Usa ~all (softfail)")
        elif '?all' in spf:
            points -= 5
            details.append("⚠️ Usa ?all (neutral)")
        elif '+all' in spf:
            points -= 10
            details.append("❌ Usa +all (permite todos)")
        else:
            points -= 5
            details.append("⚠️ Sem qualificador all")
        
        # Verifica complexidade
        if spf.count('include:') > 5:
            points -= 2
            details.append("⚠️ Muitos includes (>5)")
        
        # Verifica lookups DNS
        if spf.count('a:') + spf.count('mx:') + spf.count('include:') > 10:
            points -= 3
            details.append("⚠️ Muitos lookups DNS (limite: 10)")
        
        self._add_score(
            "SPF", "Registro SPF", 15, max(0, points),
            f"SPF configurado: {', '.join(details)}", "high"
        )
    
    def _analyze_dmarc(self):
        """Analisa registro DMARC"""
        print("\n🛡️ Analisando DMARC...")
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [a.to_text() for a in answers if 'v=DMARC1' in a.to_text()]
            
            if not dmarc_records:
                self._add_score(
                    "DMARC", "Registro DMARC", 15, 0,
                    "❌ Nenhum registro DMARC encontrado", "high"
                )
                return
            
            dmarc = dmarc_records[0].lower()
            points = 15
            details = []
            
            # Verifica política
            if 'p=reject' in dmarc:
                details.append("✅ Política reject")
            elif 'p=quarantine' in dmarc:
                points -= 3
                details.append("⚠️ Política quarantine")
            elif 'p=none' in dmarc:
                points -= 7
                details.append("❌ Política none")
            
            # Verifica subdomínios
            if 'sp=reject' in dmarc or 'sp=quarantine' in dmarc:
                details.append("✅ Política para subdomínios")
            else:
                points -= 2
                details.append("⚠️ Sem política para subdomínios")
            
            # Verifica reporting
            if 'rua=' in dmarc:
                details.append("✅ Relatórios agregados configurados")
            else:
                points -= 1
                details.append("⚠️ Sem relatórios agregados")
            
            if 'ruf=' in dmarc:
                details.append("✅ Relatórios forenses configurados")
            
            # Verifica porcentagem
            pct_match = re.search(r'pct=(\d+)', dmarc)
            if pct_match and int(pct_match.group(1)) < 100:
                points -= 2
                details.append(f"⚠️ Aplicação parcial: {pct_match.group(1)}%")
            
            self._add_score(
                "DMARC", "Registro DMARC", 15, max(0, points),
                f"DMARC configurado: {', '.join(details)}", "high"
            )
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._add_score(
                "DMARC", "Registro DMARC", 15, 0,
                "❌ Nenhum registro DMARC encontrado", "high"
            )
        except Exception as e:
            self._add_score(
                "DMARC", "Registro DMARC", 15, 0,
                f"❌ Erro ao verificar DMARC: {str(e)}", "high"
            )
    
    def _analyze_dkim(self):
        """Verifica seletores DKIM comuns"""
        print("\n🔑 Verificando DKIM...")
        common_selectors = ['default', 'google', 'dkim', 'k1', 'k2', 
                           'selector1', 'selector2', 's1', 's2']
        found_selectors = []
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                if answers:
                    found_selectors.append(selector)
            except:
                continue
        
        if found_selectors:
            self._add_score(
                "DKIM", "Seletores DKIM", 10, 10,
                f"✅ DKIM configurado (seletores: {', '.join(found_selectors)})", "high"
            )
        else:
            self._add_score(
                "DKIM", "Seletores DKIM", 10, 0,
                "⚠️ Nenhum seletor DKIM comum encontrado", "high"
            )
    
    def _check_caa(self):
        """Verifica registros CAA"""
        print("\n🔒 Verificando CAA...")
        caa_records = self.results["dns_records"].get("CAA", [])
        
        if not caa_records:
            self._add_score(
                "CAA", "Registros CAA", 10, 0,
                "❌ Nenhum registro CAA encontrado", "medium"
            )
            return
        
        points = 10
        details = []
        
        # Verifica políticas
        has_issue = any('issue' in r for r in caa_records)
        has_issuewild = any('issuewild' in r for r in caa_records)
        has_iodef = any('iodef' in r for r in caa_records)
        
        if has_issue:
            details.append("✅ Política 'issue' definida")
        else:
            points -= 3
            details.append("⚠️ Sem política 'issue'")
        
        if has_issuewild:
            details.append("✅ Política 'issuewild' definida")
        else:
            points -= 2
            details.append("⚠️ Sem política 'issuewild'")
        
        if has_iodef:
            details.append("✅ Relatórios 'iodef' configurados")
        
        self._add_score(
            "CAA", "Registros CAA", 10, max(0, points),
            f"CAA configurado: {', '.join(details)}", "medium"
        )
    
    def _analyze_mx_records(self):
        """Analisa registros MX"""
        print("\n📨 Analisando registros MX...")
        mx_records = self.results["dns_records"].get("MX", [])
        
        if not mx_records:
            self._add_score(
                "MX", "Registros MX", 10, 0,
                "⚠️ Nenhum registro MX encontrado", "medium"
            )
            return
        
        points = 10
        details = []
        
        # Verifica redundância
        if len(mx_records) > 1:
            details.append(f"✅ {len(mx_records)} servidores MX (redundância)")
        else:
            points -= 3
            details.append("⚠️ Apenas 1 servidor MX (sem redundância)")
        
        # Verifica prioridades
        priorities = []
        for mx in mx_records:
            parts = mx.split()
            if parts:
                priorities.append(int(parts[0]))
        
        if len(set(priorities)) > 1:
            details.append("✅ Múltiplas prioridades configuradas")
        elif len(mx_records) > 1:
            points -= 2
            details.append("⚠️ Mesma prioridade para todos os MX")
        
        # Verifica se aponta para IP direto (não recomendado)
        for mx in mx_records:
            mx_host = mx.split()[-1]
            if re.match(r'\d+\.\d+\.\d+\.\d+', mx_host):
                points -= 5
                details.append(f"❌ MX aponta para IP direto: {mx_host}")
                break
        
        self._add_score(
            "MX", "Registros MX", 10, max(0, points),
            f"MX configurado: {', '.join(details)}", "medium"
        )
    
    def _analyze_nameservers(self):
        """Analisa servidores de nome"""
        print("\n🌐 Analisando nameservers...")
        ns_records = self.results["dns_records"].get("NS", [])
        
        if len(ns_records) < 2:
            self._add_score(
                "NS", "Nameservers", 10, 0,
                f"❌ Apenas {len(ns_records)} nameserver(s) (mínimo recomendado: 2)", "high"
            )
            return
        
        points = 10
        details = []
        
        if len(ns_records) >= 2:
            details.append(f"✅ {len(ns_records)} nameservers configurados")
        
        # Verifica diversidade de provedores
        providers = set()
        for ns in ns_records:
            domain_parts = ns.split('.')
            if len(domain_parts) >= 2:
                providers.add('.'.join(domain_parts[-2:]))
        
        if len(providers) > 1:
            details.append(f"✅ Múltiplos provedores DNS ({len(providers)})")
        else:
            points -= 3
            details.append("⚠️ Todos os NS no mesmo provedor")
        
        # Verifica se tem NS com IPv6
        has_ipv6 = False
        for ns in ns_records:
            try:
                ns_clean = ns.rstrip('.')
                aaaa = self.resolver.resolve(ns_clean, 'AAAA')
                if aaaa:
                    has_ipv6 = True
                    break
            except:
                continue
        
        if has_ipv6:
            details.append("✅ Suporte IPv6 nos nameservers")
        else:
            points -= 2
            details.append("⚠️ Sem suporte IPv6 nos nameservers")
        
        self._add_score(
            "NS", "Nameservers", 10, max(0, points),
            f"NS configurado: {', '.join(details)}", "high"
        )
    
    def _check_dane(self):
        """Verifica DANE/TLSA"""
        print("\n🔐 Verificando DANE/TLSA...")
        try:
            # Verifica TLSA para porta 443 (HTTPS)
            tlsa_domain = f"_443._tcp.{self.domain}"
            answers = self.resolver.resolve(tlsa_domain, 'TLSA')
            
            if answers:
                self._add_score(
                    "DANE", "DANE/TLSA", 5, 5,
                    "✅ DANE/TLSA configurado para HTTPS", "low"
                )
            else:
                self._add_score(
                    "DANE", "DANE/TLSA", 5, 0,
                    "⚠️ DANE/TLSA não configurado", "low"
                )
        except:
            self._add_score(
                "DANE", "DANE/TLSA", 5, 0,
                "⚠️ DANE/TLSA não configurado", "low"
            )
    
    def _analyze_txt_records(self):
        """Analisa registros TXT para problemas de segurança"""
        print("\n📝 Analisando registros TXT...")
        txt_records = self.results["dns_records"].get("TXT", [])
        
        points = 5
        details = []
        
        if not txt_records:
            self._add_score(
                "TXT", "Registros TXT", 5, 5,
                "✅ Nenhum registro TXT desnecessário", "low"
            )
            return
        
        # Verifica informações sensíveis
        sensitive_patterns = [
            (r'password|pwd|pass', "senha"),
            (r'api[_-]?key|apikey', "chave API"),
            (r'secret', "segredo"),
            (r'token', "token"),
            (r'private', "privado")
        ]
        
        for txt in txt_records:
            txt_lower = txt.lower()
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, txt_lower):
                    points = 0
                    details.append(f"❌ Possível informação sensível: {desc}")
                    break
        
        # Verifica registros obsoletos
        obsolete_patterns = [
            ('microsoft-domain-verification', 'Microsoft'),
            ('google-site-verification', 'Google'),
            ('facebook-domain-verification', 'Facebook'),
            ('adobe-sign-verification', 'Adobe')
        ]
        
        obsolete_found = []
        for txt in txt_records:
            for pattern, service in obsolete_patterns:
                if pattern in txt.lower():
                    obsolete_found.append(service)
        
        if obsolete_found and len(obsolete_found) > 2:
            points -= 1
            details.append(f"⚠️ Muitos registros de verificação ({len(obsolete_found)})")
        
        if points == 5:
            details.append("✅ Sem problemas identificados")
        
        self._add_score(
            "TXT", "Registros TXT", 5, max(0, points),
            f"Análise TXT: {', '.join(details) if details else '✅ OK'}", "low"
        )
    
    def _check_ipv6_support(self):
        """Verifica suporte IPv6"""
        print("\n🌍 Verificando suporte IPv6...")
        aaaa_records = self.results["dns_records"].get("AAAA", [])
        
        if aaaa_records:
            self._add_score(
                "IPv6", "Suporte IPv6", 5, 5,
                f"✅ IPv6 habilitado ({len(aaaa_records)} registro(s) AAAA)", "low"
            )
        else:
            self._add_score(
                "IPv6", "Suporte IPv6", 5, 0,
                "⚠️ Sem suporte IPv6 (nenhum registro AAAA)", "low"
            )
    
    def _calculate_final_score(self):
        """Calcula pontuação final e nota"""
        total_earned = sum(s["earned_points"] for s in self.results["security_scores"])
        total_max = sum(s["max_points"] for s in self.results["security_scores"])
        
        self.results["total_score"] = total_earned
        self.results["max_possible_score"] = total_max
        
        if total_max > 0:
            percentage = (total_earned / total_max) * 100
            
            if percentage >= 90:
                grade = "A+"
            elif percentage >= 85:
                grade = "A"
            elif percentage >= 80:
                grade = "A-"
            elif percentage >= 75:
                grade = "B+"
            elif percentage >= 70:
                grade = "B"
            elif percentage >= 65:
                grade = "B-"
            elif percentage >= 60:
                grade = "C+"
            elif percentage >= 55:
                grade = "C"
            elif percentage >= 50:
                grade = "C-"
            elif percentage >= 45:
                grade = "D+"
            elif percentage >= 40:
                grade = "D"
            else:
                grade = "F"
            
            self.results["grade"] = grade
            self.results["percentage"] = round(percentage, 2)
    
    def _generate_recommendations(self):
        """Gera recomendações baseadas na análise"""
        recommendations = []
        
        for score in self.results["security_scores"]:
            if score["earned_points"] < score["max_points"]:
                if score["severity"] == "critical":
                    priority = "🔴 CRÍTICO"
                elif score["severity"] == "high":
                    priority = "🟠 ALTO"
                elif score["severity"] == "medium":
                    priority = "🟡 MÉDIO"
                else:
                    priority = "🟢 BAIXO"
                
                if score["category"] == "DNSSEC" and score["earned_points"] == 0:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Habilitar DNSSEC para prevenir ataques de DNS spoofing e cache poisoning",
                        "impact": "Proteção contra manipulação de respostas DNS"
                    })
                
                elif score["category"] == "SPF" and score["earned_points"] < 10:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Configurar registro SPF com política '-all' para prevenir spoofing de email",
                        "impact": "Redução significativa de emails fraudulentos usando seu domínio"
                    })
                
                elif score["category"] == "DMARC" and score["earned_points"] < 10:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Implementar DMARC com política 'reject' ou 'quarantine'",
                        "impact": "Proteção completa contra phishing e spoofing de email"
                    })
                
                elif score["category"] == "DKIM" and score["earned_points"] == 0:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Configurar DKIM para autenticação de emails",
                        "impact": "Garantia de integridade e autenticidade dos emails enviados"
                    })
                
                elif score["category"] == "CAA" and score["earned_points"] == 0:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Adicionar registros CAA para controlar emissão de certificados SSL",
                        "impact": "Prevenção contra emissão não autorizada de certificados SSL"
                    })
                
                elif score["category"] == "MX" and score["earned_points"] < 7:
                    recommendations.append({
                        "priority": priority,
                        "category": score["category"],
                        "recommendation": "Configurar múltiplos servidores MX com prioridades diferentes",
                        "impact": "Alta disponibilidade e redundância para recebimento de emails"
                    })
        
        # Ordena por prioridade
        priority_order = {"🔴 CRÍTICO": 0, "🟠 ALTO": 1, "🟡 MÉDIO": 2, "🟢 BAIXO": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        self.results["recommendations"] = recommendations
    
    def save_to_json(self, filename: Optional[str] = None):
        """Salva resultados em arquivo JSON"""
        if not filename:
            filename = f"dns_security_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Resultados salvos em: {filename}")
        return filename
    
    def print_summary(self):
        """Imprime resumo da análise"""
        print("\n" + "=" * 60)
        print("📊 RESUMO DA ANÁLISE DE SEGURANÇA DNS")
        print("=" * 60)
        print(f"🌐 Domínio: {self.domain}")
        print(f"📅 Data: {self.results['timestamp']}")
        print(f"🎯 Pontuação: {self.results['total_score']}/{self.results['max_possible_score']} ({self.results.get('percentage', 0):.1f}%)")
        print(f"📈 Nota: {self.results['grade']}")
        
        if self.results["recommendations"]:
            print("\n🔧 PRINCIPAIS RECOMENDAÇÕES:")
            for i, rec in enumerate(self.results["recommendations"][:5], 1):
                print(f"\n{i}. {rec['priority']} [{rec['category']}]")
                print(f"   📌 {rec['recommendation']}")
                print(f"   💡 Impacto: {rec['impact']}")

def analyze_multiple_domains(domains: List[str], output_dir: str = "dns_analysis"):
    """Analisa múltiplos domínios"""
    import os
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    all_results = {}
    
    for domain in domains:
        print(f"\n{'='*60}")
        print(f"Analisando: {domain}")
        print(f"{'='*60}")
        
        try:
            analyzer = DNSSecurityAnalyzer(domain)
            results = analyzer.analyze()
            analyzer.print_summary()
            
            # Salva JSON individual
            json_file = os.path.join(output_dir, f"{domain.replace('.', '_')}.json")
            analyzer.save_to_json(json_file)
            
            all_results[domain] = results
            
        except Exception as e:
            print(f"❌ Erro ao analisar {domain}: {str(e)}")
            all_results[domain] = {"error": str(e)}
    
    # Salva arquivo consolidado
    consolidated_file = os.path.join(output_dir, f"consolidated_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(consolidated_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    
    print(f"\n📁 Análise completa salva em: {output_dir}")
    print(f"📊 Arquivo consolidado: {consolidated_file}")
    
    return all_results

def main():
    parser = argparse.ArgumentParser(description='Analisador de Segurança DNS')
    parser.add_argument('domain', nargs='?', help='Domínio para analisar')
    parser.add_argument('-f', '--file', help='Arquivo com lista de domínios (um por linha)')
    parser.add_argument('-o', '--output', help='Arquivo de saída JSON')
    parser.add_argument('-d', '--dir', default='dns_analysis', help='Diretório para salvar análises múltiplas')
    
    args = parser.parse_args()
    
    if args.file:
        # Analisa múltiplos domínios de um arquivo
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        if not domains:
            print("❌ Nenhum domínio encontrado no arquivo")
            sys.exit(1)
        
        print(f"📋 {len(domains)} domínios para analisar")
        analyze_multiple_domains(domains, args.dir)
        
    elif args.domain:
        # Analisa um único domínio
        analyzer = DNSSecurityAnalyzer(args.domain)
        results = analyzer.analyze()
        analyzer.print_summary()
        
        # Salva resultado
        if args.output:
            analyzer.save_to_json(args.output)
        else:
            analyzer.save_to_json()
    else:
        # Modo interativo
        print("🔍 Analisador de Segurança DNS")
        print("=" * 60)
        domain = input("Digite o domínio para analisar: ").strip()
        
        if not domain:
            print("❌ Domínio inválido")
            sys.exit(1)
        
        analyzer = DNSSecurityAnalyzer(domain)
        results = analyzer.analyze()
        analyzer.print_summary()
        
        save = input("\n💾 Deseja salvar os resultados em JSON? (s/n): ").strip().lower()
        if save == 's':
            filename = input("Nome do arquivo (Enter para nome padrão): ").strip()
            if filename:
                analyzer.save_to_json(filename)
            else:
                analyzer.save_to_json()

if __name__ == "__main__":
    main()