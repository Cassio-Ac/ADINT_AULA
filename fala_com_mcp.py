#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Conversa com o servidor MCP SEM NENHUM LLM.

MCP nao e magia de IA: e JSON-RPC 2.0 trocado por stdin/stdout. Este script
abre o servidor como subprocesso e manda as mensagens na mao. Tudo que o
Claude faz, voce ve aqui em texto.

    python3 fala_com_mcp.py                              # o com agentes
    python3 fala_com_mcp.py mcp_exposure_poc_semagentes.py
    python3 fala_com_mcp.py mcp_exposure_poc.py ping     # chama uma tool
"""
import json
import os
import subprocess
import sys

SERVIDOR = sys.argv[1] if len(sys.argv) > 1 else 'mcp_exposure_poc.py'
TOOL = sys.argv[2] if len(sys.argv) > 2 else None
PY = os.environ.get('PY', '/opt/adint-venv/bin/python3')


def envia(p, msg):
    """Uma mensagem por linha, JSON puro. E so isso."""
    p.stdin.write(json.dumps(msg) + '\n')
    p.stdin.flush()


def recebe(p, id_esperado):
    """Le ate achar a resposta do id pedido (ignora notificacoes)."""
    while True:
        linha = p.stdout.readline()
        if not linha:
            return None
        try:
            m = json.loads(linha)
        except ValueError:
            continue
        if m.get('id') == id_esperado:
            return m


p = subprocess.Popen([PY, SERVIDOR], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, bufsize=1)

print('=' * 74)
print('1. HANDSHAKE — quem e voce, quem sou eu')
print('=' * 74)
envia(p, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
    'protocolVersion': '2024-11-05', 'capabilities': {},
    'clientInfo': {'name': 'aula-adint', 'version': '1.0'}}})
r = recebe(p, 1)
info = (r or {}).get('result', {})
print('   servidor .... %s' % info.get('serverInfo', {}).get('name'))
print('   protocolo ... %s' % info.get('protocolVersion'))
print('   capacidades . %s' % list(info.get('capabilities', {})))
envia(p, {'jsonrpc': '2.0', 'method': 'notifications/initialized'})

print()
print('=' * 74)
print('2. tools/list — EXATAMENTE o que o Claude enxerga')
print('=' * 74)
envia(p, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
r = recebe(p, 2)
tools = (r or {}).get('result', {}).get('tools', [])
print('   %d ferramentas:' % len(tools))
for t in tools:
    args = list((t.get('inputSchema') or {}).get('properties', {}))
    print('      %-28s (%s)' % (t['name'], ', '.join(args) or 'sem argumento'))
    print('         %s' % (t.get('description') or '').strip().split('\n')[0][:68])

if tools:
    print()
    print('   --- o schema de UMA tool, como o Claude recebe ---')
    print(json.dumps(tools[0], ensure_ascii=False, indent=2)[:600])

if TOOL:
    print()
    print('=' * 74)
    print('3. tools/call — chamando "%s" na mao' % TOOL)
    print('=' * 74)
    envia(p, {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
              'params': {'name': TOOL, 'arguments': {}}})
    r = recebe(p, 3)
    res = (r or {}).get('result', {})
    for c in res.get('content', []):
        print('   %s' % c.get('text', '')[:900])
    if res.get('isError'):
        print('   (o servidor marcou como erro)')

p.stdin.close()
p.terminate()
print()
print('=' * 74)
print('Nenhum LLM participou disto. So JSON entrando e saindo por um cano.')
