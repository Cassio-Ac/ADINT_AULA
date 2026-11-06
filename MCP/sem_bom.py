#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A linha que o Windows cobra.

Quando o Claude roda no Windows e o servidor MCP roda no WSL, o comando e
`wsl.exe -e python3 servidor.py`. E o `wsl.exe` INJETA um BOM (EF BB BF) no
primeiro byte do stdin. Medido assim, com o od lendo o que chegou do outro lado:

    @('{"a":1}','{"b":2}') | wsl.exe -d Ubuntu-24.04 -e od -An -tx1
    ef bb bf 7b 22 61 22 3a 31 7d 0a 7b 22 62 22 3a 32 7d 0a
    ^^^^^^^^ ninguem mandou isso

Resultado: a PRIMEIRA mensagem do MCP (o `initialize`) chega como
'\\ufeff{"jsonrpc"...' e o servidor responde:

    Invalid JSON: expected value at line 1 column 1
    Internal Server Error

O `tools/list` depois funciona — so o handshake morre. No Claude isso aparece
como "servidor falhou", sem dizer por que. Entao tiramos os 3 bytes na mao.

Rodando DENTRO do WSL (ou no Linux/Mac) nao ha BOM e esta funcao nao faz nada.

E o mesmo BOM do arquivo de combo do bloco [9]. Ele volta sempre.
"""
import sys

BOM = b'\xef\xbb\xbf'


def tira_bom():
    """Chame ANTES do mcp.run(). Sem BOM, nao consome nada."""
    bruto = getattr(sys.stdin, 'buffer', None)
    if bruto is None or not hasattr(bruto, 'peek'):
        return
    # peek() espia sem consumir (espera chegar pelo menos 1 byte).
    # Nenhum JSON comeca com 0xEF: se veio EF, e BOM.
    if bruto.peek(1)[:1] == BOM[:1]:
        bruto.read(3)
