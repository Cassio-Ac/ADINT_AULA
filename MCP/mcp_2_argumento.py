#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEGRAU 2 — a ferramenta ganha ARGUMENTO.

O que muda: o tipo (host: str) vira JSON Schema, e a DOCSTRING vira a
descricao que o modelo le. Rode o tools/list e compare com o degrau 1 —
o modelo so conhece a ferramenta por isso.

Rode da RAIZ do projeto:
    python3 fala_com_mcp.py MCP/mcp_2_argumento.py
"""
import re
import subprocess

from mcp.server.fastmcp import FastMCP

from sem_bom import tira_bom   # so precisa quando o Claude e Windows e o MCP e WSL

mcp = FastMCP("degrau-2-argumento")

# O argumento vem de FORA: quem digita e o modelo, a partir do que alguem
# escreveu no chat. Toda tool e superficie de ataque.
#
# Repare no PRIMEIRO caractere: ele tem que ser letra ou numero. A versao
# anterior era ^[A-Za-z0-9.\-]{1,100}$ e deixava passar "-f" (o hifen estava
# na classe), ou seja, uma FLAG entrando no lugar do host. So descobri
# testando o filtro contra o que ele deveria barrar.
VALIDO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$')


@mcp.tool()
def ping(host: str = "8.8.8.8", pacotes: int = 3) -> str:
    """Faz ping num host e devolve a saida crua do comando.

    Args:
        host: IP ou dominio a testar. Ex.: 8.8.8.8, google.com
        pacotes: quantos pacotes enviar (1 a 10)
    """
    if not VALIDO.match(host):
        return 'host invalido: %r' % host
    n = max(1, min(10, pacotes))
    # sem -W: no Linux e SEGUNDOS, no macOS e MILISSEGUNDOS. Quem limita e o timeout=.
    r = subprocess.run(['ping', '-c', str(n), host],
                       capture_output=True, text=True, timeout=30)
    return r.stdout or r.stderr


if __name__ == '__main__':
    tira_bom()
    mcp.run(transport='stdio')
