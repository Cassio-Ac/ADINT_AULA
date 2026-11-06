#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEGRAU 1 — o MCP minimo que existe.

Uma ferramenta, sem argumento, que roda um ping. E so isso.

Rode da RAIZ do projeto:
    python3 fala_com_mcp.py MCP/mcp_1_ping.py ping
"""
import subprocess

from mcp.server.fastmcp import FastMCP

from sem_bom import tira_bom   # so precisa quando o Claude e Windows e o MCP e WSL

mcp = FastMCP("degrau-1-ping")


@mcp.tool()
def ping() -> str:
    """Faz ping em 8.8.8.8 e devolve a saida do comando."""
    # sem -W de proposito: no Linux ele e SEGUNDOS, no macOS e MILISSEGUNDOS.
    # Quem limita o tempo aqui e o timeout= do subprocess, que e igual nos dois.
    r = subprocess.run(['ping', '-c', '3', '8.8.8.8'],
                       capture_output=True, text=True, timeout=20)
    return r.stdout


if __name__ == '__main__':
    tira_bom()
    mcp.run(transport='stdio')
