#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEGRAU 4 — o agente ganha KNOWLEDGE BASE.

No degrau 3 os limiares estavam ESPALHADOS dentro de ifs. Aqui eles viram
uma estrutura separada: o conhecimento sai do codigo e vira DADO.

Por que importa: para mudar um criterio voce edita a KB, nao a logica.
E a KB pode ser revisada por quem entende de rede, nao por quem programa.

Rode da RAIZ do projeto:
    python3 fala_com_mcp.py MCP/mcp_4_kb.py diagnostico
"""
import re
import subprocess
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from sem_bom import tira_bom   # so precisa quando o Claude e Windows e o MCP e WSL

mcp = FastMCP("degrau-4-kb")
# o 1o caractere TEM que ser letra ou numero: senao "-f" passa como flag
VALIDO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$')

# ---------------------------------------------------------------- A KB
# Conhecimento tecnico, separado da logica. Cada faixa traz o que significa,
# o risco, e o que fazer. E isto que o agente "sabe".
KB = {
    'latencia_ms': [
        (0,   30,  'excelente', 'BAIXO',
         'Mesma regiao ou CDN proxima. Nada a fazer.'),
        (30,  80,  'boa', 'BAIXO',
         'Tipico de mesmo pais. Normal para SaaS.'),
        (80,  200, 'aceitavel', 'MEDIO',
         'Provavelmente outro continente. Evite chamadas em serie.'),
        (200, 10 ** 9, 'ruim', 'ALTO',
         'Satelite, rota ruim ou congestionamento. Investigue o traceroute.'),
    ],
    'perda_pct': [
        (0,  1,   'sem perda', 'BAIXO',   'Link saudavel.'),
        (1,  5,   'perda leve', 'MEDIO',  'TCP retransmite; VoIP ja sofre.'),
        (5,  20,  'perda alta', 'ALTO',   'Degrada tudo. Verifique enlace e MTU.'),
        (20, 101, 'perda severa', 'CRITICO',
         'Link quebrado ou filtro de ICMP no caminho.'),
    ],
}

# Conhecimento que NAO e faixa: contexto que muda a leitura do numero.
RESSALVAS = {
    'icmp_despriorizado':
        'Muito roteador trata ICMP com prioridade baixa. Latencia alta no ping '
        'nao prova latencia alta na aplicacao — confirme com TCP na porta real.',
    'perda_100':
        'Perda de 100% pode ser firewall bloqueando ICMP, nao host fora do ar. '
        'Nunca conclua "caiu" so com ping.',
}


def _classifica(metrica: str, valor: float):
    """Procura o valor na faixa da KB. A logica nao sabe nada: a KB sabe."""
    for ini, fim, rotulo, risco, acao in KB[metrica]:
        if ini <= valor < fim:
            return {'faixa': rotulo, 'risco': risco, 'recomendacao': acao}
    return {'faixa': 'fora de faixa', 'risco': 'DESCONHECIDO', 'recomendacao': '-'}


@mcp.tool()
def diagnostico(host: str = "8.8.8.8") -> Dict[str, Any]:
    """Faz ping e diagnostica usando a base de conhecimento de rede.

    Devolve, para cada metrica: o valor medido, a faixa em que ele cai,
    o risco e a recomendacao. Inclui ressalvas sobre o que o ping NAO prova.

    Args:
        host: IP ou dominio a diagnosticar
    """
    if not VALIDO.match(host):
        return {'erro': 'host invalido'}

    # sem -W: no Linux e SEGUNDOS, no macOS e MILISSEGUNDOS. Quem limita e o timeout=.
    saida = subprocess.run(['ping', '-c', '4', host],
                           capture_output=True, text=True, timeout=30).stdout
    # Linux: '0% packet loss' e 'rtt min/avg/max/mdev'
    # macOS: '0.0% packet loss' e 'round-trip min/avg/max/stddev'
    mp = re.search(r'([\d.]+)% packet loss', saida)
    mr = re.search(r'min/avg/max/\w+ = [\d.]+/([\d.]+)/', saida)
    perda = float(mp.group(1)) if mp else 100.0
    media = float(mr.group(1)) if mr else None

    achados = {'perda_pct': {'valor': perda, **_classifica('perda_pct', perda)}}
    if media is not None:
        achados['latencia_ms'] = {'valor': media, **_classifica('latencia_ms', media)}

    ressalvas = [RESSALVAS['icmp_despriorizado']]
    if perda == 100:
        ressalvas.append(RESSALVAS['perda_100'])

    ordem = ['BAIXO', 'MEDIO', 'ALTO', 'CRITICO']
    pior = max((a['risco'] for a in achados.values()), key=ordem.index)

    return {'host': host, 'risco_geral': pior,
            'achados': achados, 'ressalvas': ressalvas}


@mcp.tool()
def explica_kb() -> Dict[str, Any]:
    """Mostra a base de conhecimento que o diagnostico usa.

    Serve para auditar o criterio: qualquer um pode conferir os limiares
    sem ler o codigo.
    """
    return {m: [{'de': a, 'ate': b, 'faixa': r, 'risco': k, 'acao': ac}
                for a, b, r, k, ac in faixas]
            for m, faixas in KB.items()}


if __name__ == '__main__':
    tira_bom()
    mcp.run(transport='stdio')
