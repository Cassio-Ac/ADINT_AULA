#!/usr/bin/env python3
"""
DNS Security Analyzer — analisa a configuração DNS pública de um domínio e dá
uma nota.

Consulta os registros DNS do domínio (A, AAAA, NS, MX, TXT, SOA, CAA, CNAME,
DNSKEY, DMARC, DKIM, TLSA), avalia dez controles de segurança, soma pontos até
105 e converte o total numa nota de A+ a F, com recomendações do que arrumar
primeiro.

Uso:
    # um domínio (grava um JSON de nome automático no diretório atual)
    python3 DNS/dns-security-analyzer.py exemplo.com.br

    # um domínio, escolhendo o arquivo de saída
    python3 DNS/dns-security-analyzer.py exemplo.com.br -o exemplo.json

    # lista de domínios (um por linha), um JSON por domínio dentro de saida/
    python3 DNS/dns-security-analyzer.py -f dominios.txt -d saida/

    # sem argumento nenhum: pergunta o domínio no terminal
    python3 DNS/dns-security-analyzer.py

Produz:
    Relatório legível na tela e, sempre, um arquivo JSON com:
      dns_records          o que foi coletado, por tipo de registro
      security_scores      um item por controle (pontos ganhos, máximo,
                           detalhes e severidade)
      total_score / max_possible_score / percentage / grade
      recommendations      o que corrigir, já ordenado por prioridade
    Com -f, os arquivos vão para o diretório do -d (padrão: ./dns_analysis),
    um por domínio, mais um consolidated_<data>.json com tudo junto.
    Atenção: com -f, o -o é ignorado.

Precisa:
    - Python 3.10+
    - dnspython:  pip install dnspython
    - python-whois: o módulo "whois" é importado no topo e NÃO é usado por
      nenhuma função, mas sem ele o script nem inicia ("No module named
      'whois'"). É o erro mais comum na primeira execução.
    - saída UDP/53 para 8.8.8.8 e 8.8.4.4 (o resolver está fixado no DNS
      público do Google — veja o comentário no __init__)
    - nenhuma chave de API

Autorização:
    Tudo aqui é consulta DNS a servidores públicos: é passivo, não manda pacote
    para o alvo e não tenta transferência de zona. Mesmo assim, só analise
    domínios que são seus ou que você tem autorização escrita para avaliar.
    E leia a nota pelo que ela é: um retrato de FORA da configuração pública.
    Nota baixa não é vulnerabilidade confirmada — é controle ausente.
"""

# dnspython é a dependência externa que o script realmente usa: dns.resolver
# monta as consultas, e dns.query/dns.message/dns.flags aparecem só no teste de
# DNSSEC, onde é preciso olhar a flag AD da resposta crua.
# Já socket, whois, dns.name, dns.dnssec e subprocess são herança de versões
# anteriores: nenhuma função os usa. Não apague por conta própria sem testar —
# aqui eles estão documentados como dependência morta, mas obrigatória para o
# arquivo importar.
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
    """
    O resultado de UM controle avaliado.

    max_points é o peso do controle (quanto ele vale dentro dos 105 do total) e
    earned_points é quanto o domínio tirou nele. severity ('critical', 'high',
    'medium', 'low') NÃO entra na conta da nota: serve só para ordenar as
    recomendações no fim do relatório.
    """
    category: str
    description: str
    max_points: int
    earned_points: int
    details: str
    severity: str  # 'critical', 'high', 'medium', 'low'

class DNSSecurityAnalyzer:
    """
    Analisa um domínio. Um objeto por domínio: o estado (registros coletados,
    pontuações parciais) mora em self.results e é exatamente o que vira JSON.

    PESOS DOS CONTROLES — total de 105 pontos:
        DNSSEC  20    SPF  15    DMARC  15    DKIM  10
        CAA     10    MX   10    NS     10
        DANE     5    TXT   5    IPv6    5

    A nota sai do percentual (total ganho / 105) na escala que está em
    _calculate_final_score.

    PARA MUDAR A IMPORTÂNCIA DE UM CONTROLE: mude o max_points na chamada de
    _add_score dentro do método daquele controle — e lembre que os descontos
    parciais ali dentro foram calculados em cima do máximo antigo.
    """

    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        # Todo o relatório é montado neste dicionário e despejado como JSON no
        # fim. "percentage" nem aparece aqui: é criado em
        # _calculate_final_score, então use .get() para ler.
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
        # dns.resolver.Resolver() nasce lendo o resolver do seu sistema
        # (/etc/resolv.conf); a linha seguinte joga isso fora e FIXA o DNS
        # público do Google.
        #
        # Consequência que o aluno precisa entender: você passa a ver o domínio
        # como a internet o vê, não como a rede interna da empresa o vê. Se ela
        # usa split-horizon (uma zona interna com nomes que só o DNS dela
        # resolve), nada disso aparece aqui. E a resposta pode vir do cache do
        # Google, não refletindo uma mudança feita minutos antes.
        #
        # PARA TROCAR O RESOLVER: altere a lista abaixo — mas veja também o
        # '8.8.8.8' escrito à mão dentro de _check_dnssec, que não acompanha
        # esta configuração.
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS

    def analyze(self) -> Dict:
        """
        Executa a análise completa: coleta, dez controles, nota, recomendações.

        A ORDEM IMPORTA: _collect_dns_records vem primeiro porque metade dos
        controles (SPF, CAA, MX, NS, TXT, IPv6) só lê o que ele já trouxe, sem
        tocar na rede de novo. Os controles que dependem de um nome especial
        (_dmarc.dominio, seletor._domainkey.dominio, _443._tcp.dominio) fazem a
        própria consulta, porque esses nomes não dão para adivinhar antes.
        """
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

        # Calcula pontuação final: só depois que os dez controles registraram
        # os pontos, porque o máximo é somado a partir deles.
        self._calculate_final_score()

        # Gera recomendações
        self._generate_recommendations()

        return self.results

    def _collect_dns_records(self):
        """
        Coleta os registros base, que os controles seguintes vão ler.

        PARA QUE SERVE CADA REGISTRO na análise de superfície de ataque:
            A / AAAA  para onde o domínio aponta — são os IPs que você vai
                      enumerar e escanear nas etapas seguintes do pipeline
            NS        quem manda na zona; alvo de takeover e ponto único de
                      falha se estiverem todos no mesmo provedor
            MX        quem recebe e-mail do domínio: é o caminho de phishing
                      contra a empresa, e normalmente revela o provedor usado
            TXT       onde moram o SPF, as verificações de serviço e, às vezes,
                      segredo publicado por descuido
            SOA       serial da zona e e-mail do administrador
            CAA       quais autoridades podem emitir certificado para o domínio
            CNAME     apontamento para terceiro — a pista clássica de subdomain
                      takeover quando o destino já não existe mais
        """
        # Esta é a lista que define o que é coletado de uma vez. Para
        # acrescentar um tipo (SRV, PTR, NAPTR...), inclua a sigla aqui: ela já
        # vai aparecer em dns_records no JSON.
        record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CAA', 'CNAME']

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                # to_text() guarda a forma textual do registro, igual à do dig:
                # é o que preserva prioridade do MX e as aspas do TXT.
                self.results["dns_records"][record_type] = [
                    answer.to_text() for answer in answers
                ]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                # ARMADILHA GRANDE, e a mais importante do arquivo: o except
                # captura Exception, então NXDOMAIN (domínio não existe),
                # NoAnswer (existe e não tem esse tipo), timeout e erro de rede
                # caem todos no mesmo lugar e viram lista vazia.
                #
                # Lista vazia aqui significa "não obtive", NÃO "não existe". E
                # como vários controles dão 0 ponto quando a lista está vazia,
                # uma falha de rede derruba a nota do domínio sem avisar. Antes
                # de reportar nota F, confirme com dig que a consulta funciona.
                self.results["dns_records"][record_type] = []

    def _add_score(self, category: str, description: str, max_points: int,
                   earned_points: int, details: str, severity: str = "medium"):
        """
        Registra o resultado de um controle e imprime a linha de progresso.

        Todo controle termina chamando este método exatamente UMA vez — é isso
        que garante que max_possible_score feche sempre em 105.
        """
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
        """
        DNSSEC: as respostas desta zona são assinadas?

        Vale 20 pontos — é o controle mais pesado da planilha, e por um motivo:
        sem DNSSEC nada prova que a resposta DNS que você recebeu foi a que o
        dono do domínio publicou. É o que viabiliza cache poisoning e spoofing
        de DNS, e é a base sobre a qual o DANE depende.

        São DUAS perguntas diferentes, e daí os três níveis de nota:
            1. a zona publica chave? (existe registro DNSKEY)
            2. a assinatura confere? (o resolver validador liga a flag AD)
          20 pts  chave publicada e validação confirmada
          10 pts  chave publicada, mas a resposta veio sem AD
           5 pts  chave publicada e a segunda consulta falhou (não deu para
                  dizer se valida)
           0 pts  sem DNSKEY
        """
        print("\n🔐 Verificando DNSSEC...")
        try:
            # raise_on_no_answer=False para que "zona sem DNSKEY" chegue como
            # rrset None em vez de exceção: é uma resposta válida do DNS, não
            # um erro de consulta.
            response = self.resolver.resolve(self.domain, 'DNSKEY', raise_on_no_answer=False)
            if response.rrset is not None:
                # Verifica assinatura.
                # want_dnssec=True pede os RRSIG junto da resposta. Quem valida
                # de fato é o resolver (o 8.8.8.8), e ele avisa que validou
                # ligando a flag AD (Authenticated Data) — o script confia
                # nesse veredito em vez de conferir a assinatura por conta
                # própria, o que exigiria descer até a âncora da raiz.
                #
                # Repare no '8.8.8.8' escrito à mão: se você trocar o resolver
                # no __init__, esta consulta continua indo para o Google.
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
                    # Falha aqui costuma ser UDP/53 bloqueado na sua rede ou
                    # resposta truncada: resposta com DNSSEC é grande e muitas
                    # vezes só cabe em TCP. Dá 5 pontos porque há chave
                    # publicada — o que não deu para confirmar é a validação.
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
        """
        SPF: quais servidores estão autorizados a enviar e-mail usando este
        domínio.

        Vale 15 pontos. O SPF é publicado como registro TXT no domínio raiz —
        é por isso que este controle não consulta a rede: ele filtra o TXT que
        _collect_dns_records já trouxe.

        PONTUAÇÃO (descontos sobre os 15):
            -all  (fail)         0   o certo: rejeite quem não está na lista
            ~all  (softfail)    -3
            ?all  (neutral)     -5
            +all               -10   autoriza o mundo a mandar e-mail por você
            sem qualificador    -5
            mais de 5 includes  -2   difícil de auditar
            mais de 10 lookups  -3   estoura o limite do RFC 7208 e o SPF
                                     passa a falhar com permerror
        Dois ou mais registros SPF deixam o SPF INVÁLIDO pelo RFC: nesse caso
        a nota é fixa em 5 e o resto nem é avaliado.
        """
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

        # Verifica terminadores.
        # O qualificador do "all" é o que decide o destino de quem NÃO está na
        # lista de autorizados — é a parte do SPF que realmente protege. Sem
        # ele, o SPF publica a lista e não diz o que fazer com o resto.
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
        
        # Verifica complexidade: cada "include:" delega a autorização a um
        # terceiro, e um SPF cheio deles é um SPF que ninguém audita.
        if spf.count('include:') > 5:
            points -= 2
            details.append("⚠️ Muitos includes (>5)")

        # Verifica lookups DNS. O RFC 7208 limita a 10 as consultas que a
        # avaliação do SPF pode disparar; passando disso o receptor devolve
        # permerror e o SPF simplesmente para de valer.
        #
        # Triagem, não validador: a contagem é por substring, então só pega as
        # formas com ':' — "a" e "mx" soltos também custam lookup e passam
        # livres aqui, e os includes aninhados não são expandidos. Para checar
        # o limite de verdade, use uma ferramenta dedicada de SPF.
        if spf.count('a:') + spf.count('mx:') + spf.count('include:') > 10:
            points -= 3
            details.append("⚠️ Muitos lookups DNS (limite: 10)")
        
        self._add_score(
            "SPF", "Registro SPF", 15, max(0, points),
            f"SPF configurado: {', '.join(details)}", "high"
        )
    
    def _analyze_dmarc(self):
        """
        DMARC: o que o destinatário deve FAZER quando SPF e DKIM falham.

        Vale 15 pontos. Diferente do SPF, o DMARC mora num nome próprio —
        "_dmarc.<domínio>" — então aqui há consulta nova à rede.

        PONTUAÇÃO (descontos sobre os 15):
            p=reject         0   pede para descartar o que falhar
            p=quarantine    -3
            p=none          -7   só monitora: não bloqueia nada
            sem sp=         -2   subdomínio sem política é brecha de phishing
            sem rua=        -1   sem relatório você não descobre quem está
                                 usando o seu domínio
            pct<100         -2   aplicação parcial da política
        ruf= (relatório forense) aparece nos detalhes mas não vale ponto.

        SPF + DKIM + DMARC é o trio que impede alguém de mandar e-mail se
        passando pelo domínio, e é o achado mais comum deste script: muita
        empresa publica SPF e para em p=none, que não protege ninguém.
        """
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
            
            # Verifica política.
            # Busca por substring: um registro DMARC sem nenhum "p=" (inválido,
            # mas acontece) não cai em ramo nenhum e sai sem desconto.
            if 'p=reject' in dmarc:
                details.append("✅ Política reject")
            elif 'p=quarantine' in dmarc:
                points -= 3
                details.append("⚠️ Política quarantine")
            elif 'p=none' in dmarc:
                points -= 7
                details.append("❌ Política none")
            
            # Verifica subdomínios. Sem "sp=", o subdomínio herda a política do
            # pai — o que normalmente está certo, mas o script cobra o "sp="
            # explícito porque é onde o atacante tenta entrar
            # (nota-fiscal.exemplo.com.br costuma estar desprotegido).
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
            
            # Verifica porcentagem. "pct=20" com "p=reject" rejeita só 20% das
            # mensagens que falham: é etapa normal de implantação gradual, mas
            # enquanto estiver assim a proteção é parcial.
            pct_match = re.search(r'pct=(\d+)', dmarc)
            if pct_match and int(pct_match.group(1)) < 100:
                points -= 2
                details.append(f"⚠️ Aplicação parcial: {pct_match.group(1)}%")
            
            self._add_score(
                "DMARC", "Registro DMARC", 15, max(0, points),
                f"DMARC configurado: {', '.join(details)}", "high"
            )
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Aqui, diferente de _collect_dns_records, a distinção é feita: a
            # ausência do nome _dmarc é mesmo "não tem DMARC" — não é falha.
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
        """
        DKIM: assinatura criptográfica no e-mail que o domínio envia.

        Vale 10 pontos, tudo ou nada. A chave pública fica em
        "<seletor>._domainkey.<domínio>" — e o seletor é um nome escolhido por
        quem configurou o e-mail, não existe lista oficial. Como o DNS não
        permite listar os nomes de uma zona, o script CHUTA os seletores mais
        comuns, um por um.

        CONSEQUÊNCIA: "nenhum seletor encontrado" não significa "sem DKIM" —
        significa "não está em nenhum dos nomes que eu tentei". É o resultado
        mais propenso a falso negativo de todo o script, e o aluno precisa
        saber disso antes de escrever no relatório que a empresa não tem DKIM.
        """
        print("\n🔑 Verificando DKIM...")
        # PARA MELHORAR O ACERTO: acrescente aqui os seletores do provedor de
        # e-mail do alvo. O Google Workspace usa "google", o Microsoft 365 usa
        # "selector1"/"selector2", o Zimbra costuma usar o nome do servidor.
        # Cada seletor a mais é uma consulta DNS a mais por domínio — com 9
        # seletores, cada domínio já dispara 9 consultas só nesta etapa.
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
                # Seletor que não existe é o caso NORMAL aqui (a maioria dos 9
                # vai falhar), por isso o except silencioso e sem log.
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
        """
        CAA: quais autoridades certificadoras podem emitir certificado para
        este domínio.

        Vale 10 pontos (-3 se não houver política 'issue', -2 se não houver
        'issuewild'). Sem CAA, QUALQUER CA do mundo pode emitir um certificado
        válido para o seu domínio se conseguir passar na validação dela —
        inclusive uma CA de outro país que alguém convenceu. O CAA é o que
        fecha essa porta, e o 'issuewild' é o que impede um curinga
        (*.exemplo.com.br) que serviria para qualquer subdomínio.

        'iodef' pede que a CA avise você quando alguém tentar emitir sem
        autorização: aparece nos detalhes, mas não vale ponto.

        Detalhe de protocolo: na validação de verdade a CA sobe a árvore de
        nomes procurando CAA. Este script olha só o domínio consultado.
        """
        print("\n🔒 Verificando CAA...")
        # Lê do que já foi coletado (CAA está em record_types), sem rede nova.
        caa_records = self.results["dns_records"].get("CAA", [])
        
        if not caa_records:
            self._add_score(
                "CAA", "Registros CAA", 10, 0,
                "❌ Nenhum registro CAA encontrado", "medium"
            )
            return
        
        points = 10
        details = []
        
        # Verifica políticas.
        # Cuidado ao ler: 'issue' é substring de 'issuewild', então um domínio
        # que só publicou issuewild marca has_issue como True também.
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
        """
        MX: quem recebe e-mail do domínio.

        Vale 10 pontos, e aqui a nota é mais sobre DISPONIBILIDADE do que sobre
        segurança: -3 com um único MX, -2 se todos têm a mesma prioridade, -5
        se algum MX aponta para um IP literal (o RFC pede nome, e IP no MX
        impede validação de TLS por nome e inviabiliza DANE).

        Na análise de superfície, a lista de MX é a lista dos servidores de
        e-mail da empresa — e muitas vezes o primeiro indício de qual provedor
        ela usa, o que já sugere quais seletores DKIM procurar.
        """
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
        
        # Verifica prioridades.
        # O to_text() de um MX vem no formato "10 mail.exemplo.com.br.":
        # prioridade primeiro, host depois. É disso que o split() depende — se
        # algum dia a coleta mudar de formato, o int() aqui quebra.
        priorities = []
        for mx in mx_records:
            parts = mx.split()
            if parts:
                priorities.append(int(parts[0]))

        # Prioridades iguais fazem balanceamento, não failover ordenado: se o
        # primário cai, metade das mensagens continua indo para ele.
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
        """
        NS: os servidores autoritativos da zona.

        Vale 10 pontos. Zera com menos de dois NS (ponto único de falha: o
        domínio todo sai do ar junto com o servidor). Tendo dois ou mais:
        -3 se estão todos no mesmo provedor, -2 se nenhum responde em IPv6.

        "Mesmo provedor" é inferido pelos DOIS ÚLTIMOS rótulos do nome do NS, o
        que é uma aproximação grosseira: ns1.exemplo.com.br e ns2.exemplo.com.br
        podem estar em datacenters diferentes e contam como um provedor só, e
        duas marcas do mesmo dono contam como dois. Leia o desconto como
        indício, não como veredito.
        """
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
        
        # Verifica diversidade de provedores.
        #
        # ATENÇÃO, resultado não confiável: o nome do NS vem do DNS com ponto
        # final ("ns1.exemplo.com.br."), então split('.') deixa um elemento
        # VAZIO no fim e os "dois últimos rótulos" acabam sendo o TLD mais o
        # vazio — ou seja, a chave do provedor fica "br." para todo NS .br e
        # "com." para todo NS .com. Na prática o conjunto agrupa por TLD, não
        # por provedor, e o desconto de 3 pontos cai em quase todo domínio.
        # Está documentado aqui de propósito e não foi corrigido: é um bom
        # exercício de leitura crítica de ferramenta.
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
        
        # Verifica se tem NS com IPv6. Basta UM nameserver com AAAA para
        # pontuar — daí o break na primeira ocorrência, que também evita uma
        # consulta por nameserver em zonas com muitos NS.
        has_ipv6 = False
        for ns in ns_records:
            try:
                # rstrip('.') tira o ponto final do nome absoluto: aqui ele é
                # removido, ao contrário do que acontece no agrupamento acima.
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
        """
        DANE/TLSA: publicar no próprio DNS qual certificado o serviço deve
        apresentar, em vez de confiar só nas CAs.

        Vale só 5 pontos, e de propósito: DANE depende de DNSSEC e nenhum
        navegador relevante valida TLSA em HTTPS. Pouquíssimos domínios
        pontuam aqui — NÃO trate 0/5 como problema grave num relatório.

        O script olha só "_443._tcp.<domínio>" (HTTPS). Na vida real DANE é bem
        mais usado em SMTP, em "_25._tcp.<nome do MX>", que este controle não
        cobre — ampliar isso é um bom exercício.
        """
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
            # O caminho normal é este: domínio sem TLSA faz o resolve levantar
            # NXDOMAIN, que vira "não configurado". Um timeout de rede cai aqui
            # com a mesma mensagem — mais um lugar onde falha vira 0 ponto.
            self._add_score(
                "DANE", "DANE/TLSA", 5, 0,
                "⚠️ DANE/TLSA não configurado", "low"
            )

    def _analyze_txt_records(self):
        """
        TXT: higiene do que a empresa publicou em texto livre no DNS.

        Vale 5 pontos e é o único controle INVERTIDO: começa com os 5 e
        desconta. Zera se algum TXT casar com padrão de segredo (password,
        api_key, secret, token, private) — e isso acontece de verdade: gente
        usa registro TXT como bloco de notas, esquecendo que o DNS é público e
        que qualquer um lê.

        Dois avisos de leitura antes de escrever no relatório:
          - os padrões são substring solta, então "bypass" casa com "pass" e
            qualquer TXT com a palavra "token" no nome do serviço zera o
            controle. Confira o achado na mão;
          - os registros de verificação (Google, Microsoft, Facebook, Adobe)
            estão rotulados como "obsoletos" no código, mas muitos continuam em
            uso legítimo. O desconto de 1 ponto é por ACÚMULO (mais de dois),
            como indício de zona que nunca foi limpa — não por estarem errados.
        """
        print("\n📝 Analisando registros TXT...")
        txt_records = self.results["dns_records"].get("TXT", [])

        points = 5
        details = []

        # Nenhum TXT dá os 5 pontos cheios. Note a tensão com o controle de
        # SPF: um domínio sem TXT nenhum é também um domínio sem SPF, e já
        # perdeu 15 pontos lá — aqui ele ganha 5 por "limpeza".
        if not txt_records:
            self._add_score(
                "TXT", "Registros TXT", 5, 5,
                "✅ Nenhum registro TXT desnecessário", "low"
            )
            return
        
        # Verifica informações sensíveis.
        # PARA AJUSTAR A TRIAGEM: mexa nesta lista. Padrão mais específico
        # (r'\bapi[_-]?key\s*=') reduz muito o falso positivo; padrão mais
        # largo acha mais e incomoda mais.
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
        
        # Verifica registros obsoletos.
        # Cada um destes é a prova de que alguém, algum dia, ligou um serviço
        # externo a este domínio. Mesmo em uso, são sinal útil: dizem que
        # ferramentas de terceiros a empresa usa — informação de superfície.
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
        """
        IPv6: o domínio publica registro AAAA?

        Vale 5 pontos. Não é bem controle de segurança, é de SUPERFÍCIE: se a
        empresa publica AAAA, existe um segundo conjunto de endereços para
        enumerar e escanear — e, na prática, é comum o firewall de IPv6 estar
        menos cuidado que o de IPv4, quando existe.
        """
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
        """
        Soma os pontos e traduz o percentual numa nota.

        O máximo NÃO é constante no código: é a soma dos max_points que os
        controles registraram. Como cada um dos dez controles sempre registra
        exatamente um score, dá 105 em toda execução — mas se você acrescentar
        ou remover um controle, o total acompanha sozinho.

        ESCALA (percentual -> nota):
            >=90 A+   >=85 A   >=80 A-   >=75 B+   >=70 B   >=65 B-
            >=60 C+   >=55 C   >=50 C-   >=45 D+   >=40 D   abaixo de 40 F

        É AQUI QUE O ALUNO MEXE para usar outra escala: a cadeia de if/elif
        abaixo é a única coisa no arquivo que define nota. Vale saber que a
        escala é exigente de propósito — DANE (5) quase nunca pontua e o DKIM
        (10) depende de adivinhar o seletor, então 15 dos 105 pontos são
        difíceis mesmo num domínio bem configurado: na prática o teto realista
        fica na casa dos 85-90%, ou seja, nota A.
        """
        total_earned = sum(s["earned_points"] for s in self.results["security_scores"])
        total_max = sum(s["max_points"] for s in self.results["security_scores"])

        self.results["total_score"] = total_earned
        self.results["max_possible_score"] = total_max

        # Guarda de divisão por zero: se nenhum controle rodou, "grade" fica
        # como string vazia e "percentage" nem é criado no dicionário.
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
        """
        Transforma ponto perdido em texto de recomendação.

        Só gera recomendação para os controles listados no if/elif abaixo —
        DNSSEC, SPF, DMARC, DKIM, CAA e MX. NS, DANE, TXT e IPv6 descontam
        ponto mas NUNCA aparecem nas recomendações. Se você acrescentar um
        controle, acrescente o ramo aqui também, senão a perda fica invisível
        no relatório.

        Os limiares não são iguais de propósito: SPF e DMARC só recomendam
        abaixo de 10 (de 15), MX abaixo de 7 (de 10), e DNSSEC/DKIM/CAA só com
        0. É o jeito de não encher o relatório por causa de desconto pequeno.
        """
        recommendations = []

        # severity só vira prioridade visual aqui: ela não alterou nenhum ponto
        # da nota, serve para o aluno saber o que atacar primeiro.
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
        
        # Ordena por prioridade. A chave de ordenação é a própria string com
        # emoji — funciona, mas é frágil: mudar o texto do rótulo acima sem
        # mudar aqui faz tudo cair no valor padrão 4 e a ordem se perder.
        priority_order = {"🔴 CRÍTICO": 0, "🟠 ALTO": 1, "🟡 MÉDIO": 2, "🟢 BAIXO": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        self.results["recommendations"] = recommendations
    
    def save_to_json(self, filename: Optional[str] = None):
        """
        Salva o relatório em JSON. Sem nome, gera um automático com data e hora.
        """
        if not filename:
            # Data e hora no nome para não sobrescrever execução anterior — dá
            # para comparar antes/depois de uma correção. Sem caminho, o
            # arquivo cai no diretório de onde você rodou o comando; para
            # escolher o lugar, passe -o com o caminho (ou -d no modo lote).
            filename = f"dns_security_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # ensure_ascii=False preserva acento legível no arquivo; é esse JSON
        # que o orquestrador indexa no Elasticsearch depois.
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Resultados salvos em: {filename}")
        return filename
    
    def print_summary(self):
        """
        Imprime o resumo na tela: nota, percentual e as recomendações.

        O JSON é a saída completa; este resumo é a versão para ler em aula.
        """
        print("\n" + "=" * 60)
        print("📊 RESUMO DA ANÁLISE DE SEGURANÇA DNS")
        print("=" * 60)
        print(f"🌐 Domínio: {self.domain}")
        print(f"📅 Data: {self.results['timestamp']}")
        print(f"🎯 Pontuação: {self.results['total_score']}/{self.results['max_possible_score']} ({self.results.get('percentage', 0):.1f}%)")
        print(f"📈 Nota: {self.results['grade']}")
        
        if self.results["recommendations"]:
            print("\n🔧 PRINCIPAIS RECOMENDAÇÕES:")
            # Só as 5 primeiras na tela (já estão ordenadas por prioridade). A
            # lista completa está no JSON, em "recommendations".
            for i, rec in enumerate(self.results["recommendations"][:5], 1):
                print(f"\n{i}. {rec['priority']} [{rec['category']}]")
                print(f"   📌 {rec['recommendation']}")
                print(f"   💡 Impacto: {rec['impact']}")

def analyze_multiple_domains(domains: List[str], output_dir: str = "dns_analysis"):
    """
    Roda a análise para cada domínio da lista: um JSON por domínio mais um
    consolidado com tudo.

    Em SÉRIE, um domínio por vez. Cada domínio dispara dezenas de consultas DNS
    (só os seletores DKIM são 9), e paralelizar é o caminho curto para o
    resolver público começar a limitar as respostas — o que apareceria como
    NOTA MAIS BAIXA, não como erro na tela. Falso achado é pior que lentidão.
    """
    # import local, fora do topo do arquivo: é o estilo original e foi mantido
    # porque mover import muda a ordem de carga, e a regra aqui é não alterar
    # comportamento.
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
            # try/except por domínio, de propósito: num arquivo de 50 domínios,
            # um que falha vira {"error": ...} no consolidado e os outros 49
            # seguem. Confira esses "error" antes de analisar o resultado — eles
            # não entram em nenhuma estatística.
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
    """
    Três modos de uso, nesta ordem de precedência: -f (arquivo), domínio
    posicional, e nenhum dos dois (pergunta no terminal).
    """
    parser = argparse.ArgumentParser(description='Analisador de Segurança DNS')
    # nargs='?' deixa o domínio opcional: é o que permite o modo interativo
    # quando o script é chamado sem argumento nenhum.
    parser.add_argument('domain', nargs='?', help='Domínio para analisar')
    parser.add_argument('-f', '--file', help='Arquivo com lista de domínios (um por linha)')
    parser.add_argument('-o', '--output', help='Arquivo de saída JSON')
    # Cuidado com a convenção: aqui -d é DIRETÓRIO, e não "domínio" como no
    # whois_universal.py. Trocar os dois é o erro de digitação do dia.
    parser.add_argument('-d', '--dir', default='dns_analysis', help='Diretório para salvar análises múltiplas')

    args = parser.parse_args()

    # Precedência: com -f, o domínio posicional e o -o são IGNORADOS em
    # silêncio — a saída vai toda para o diretório do -d.
    if args.file:
        # Analisa múltiplos domínios de um arquivo.
        # Sem encoding explícito (usa o padrão do sistema) e sem filtro de
        # comentário: linha "# teste" é tratada como domínio.
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
        
        # Salva resultado. Note que SEMPRE grava arquivo: sem -o, com nome
        # automático no diretório atual. Não existe modo "só na tela".
        if args.output:
            analyzer.save_to_json(args.output)
        else:
            analyzer.save_to_json()
    else:
        # Modo interativo: cômodo na aula, mas depende de terminal. Chamado
        # pelo orquestrador, por cron ou com a entrada redirecionada e sem
        # argumento, o input() abaixo falha com EOFError — no pipeline, passe
        # sempre o domínio ou o -f.
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