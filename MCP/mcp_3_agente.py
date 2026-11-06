#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEGRAU 3 — de FERRAMENTA para AGENTE.

O degrau 2 devolvia a saida crua: o modelo tinha que interpretar texto.
Aqui a funcao INTERPRETA: extrai os numeros, classifica, e devolve um
veredito. Mesma coleta, conhecimento aplicado.

Compare as duas tools no tools/list: `ping_cru` e `ping_analisado`.

Rode da RAIZ do projeto:
    python3 fala_com_mcp.py MCP/mcp_3_agente.py ping_analisado
"""
import re
import subprocess
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

from sem_bom import tira_bom   # so precisa quando o Claude e Windows e o MCP e WSL

mcp = FastMCP("degrau-3-agente")
# o 1o caractere TEM que ser letra ou numero: senao "-f" passa como flag
VALIDO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$')


def _roda_ping(host: str, n: int) -> str:
    # sem -W: no Linux e SEGUNDOS, no macOS e MILISSEGUNDOS ('-W 2' la seria 2ms,
    # e TUDO viraria perda de pacote). Quem limita o tempo e o timeout= do subprocess.
    return subprocess.run(['ping', '-c', str(n), host],
                          capture_output=True, text=True, timeout=30).stdout


@mcp.tool()
def ping_cru(host: str = "8.8.8.8") -> str:
    """Faz ping e devolve a saida do comando, sem interpretar nada."""
    if not VALIDO.match(host):
        return 'host invalido'
    return _roda_ping(host, 3)


@mcp.tool()
def ping_analisado(host: str = "8.8.8.8") -> Dict[str, Any]:
    """Faz ping, MEDE a latencia e a perda, e devolve um veredito.

    Nao devolve texto para alguem ler: devolve numeros e uma conclusao.

    Args:
        host: IP ou dominio a testar
    """
    if not VALIDO.match(host):
        return {'erro': 'host invalido'}

    saida = _roda_ping(host, 4)

    # Linux escreve '0% packet loss'; macOS escreve '0.0%'. Por isso [\d.]+ e float().
    perda = re.search(r'([\d.]+)% packet loss', saida)
    # Linux: 'rtt min/avg/max/mdev'  |  macOS: 'round-trip min/avg/max/stddev'
    rtt = re.search(r'min/avg/max/\w+ = ([\d.]+)/([\d.]+)/([\d.]+)', saida)
    perda = float(perda.group(1)) if perda else 100.0
    media = float(rtt.group(2)) if rtt else None
    jitter = (float(rtt.group(3)) - float(rtt.group(1))) if rtt else None

    # AQUI esta o conhecimento: os limiares. Eles nao vem do ping.
    if perda == 100:
        veredito, risco = 'host inalcancavel', 'CRITICO'
    elif perda > 20:
        veredito, risco = 'perda alta: rede instavel', 'ALTO'
    elif media is not None and media > 200:
        veredito, risco = 'latencia alta: provavelmente outro continente', 'MEDIO'
    elif jitter is not None and jitter > 50:
        veredito, risco = 'jitter alto: ruim para voz e video', 'MEDIO'
    else:
        veredito, risco = 'conexao saudavel', 'BAIXO'

    return {
        'host': host,
        'perda_pct': perda,
        'latencia_media_ms': media,
        'jitter_ms': round(jitter, 2) if jitter is not None else None,
        'veredito': veredito,
        'risco': risco,
    }


if __name__ == '__main__':
    tira_bom()
    mcp.run(transport='stdio')
