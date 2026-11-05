#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_combo.py — le um arquivo ULP/combo e o transforma em NDJSON para o Elastic.

PARA QUE SERVE NA AULA
----------------------
Os canais de infostealer nao postam dado limpo: postam .rar/.zip com arquivos
.txt dentro, e cada .txt mistura SEIS formatos de linha diferentes, com BOM,
CRLF, duplicata e ruido. Este script e o gabarito de como tratar isso.

USE COM A BASE FICTICIA:
    samples/ULP_MIX_FICTICIO_2026.txt

NUNCA use este script, em aula, com arquivo baixado de canal real: aquilo e
credencial de vitima de verdade. A base ficticia tem a MESMA forma e nenhum
dado de pessoa real. A forma e o que se ensina; o dado da vitima nao e nosso.

OS SEIS FORMATOS (declarados no slide 32)
-----------------------------------------
    URL:USER:PASS
    USER:PASS:URL
    URL:USER            (sem PASS)
    URL                 (so a URL)
    URL sem esquema:USER:PASS
    USER:PASS           (sem URL)

A ARMADILHA CENTRAL
-------------------
`linha.split(':')` ESTA ERRADO e falha de dois jeitos ao mesmo tempo:
  1. a URL tem 'https://' — o split quebra no ':' do esquema;
  2. a senha pode CONTER ':' — o split quebra a senha em duas.
A saida e tirar o esquema primeiro e depois usar split(':', 2), que limita o
numero de cortes e deixa o resto inteiro na senha.
"""
import argparse
import io
import json
import re
import sys
from collections import Counter

# esquema no inicio da linha: https://, http://, ftp://, android://...
RX_ESQUEMA = re.compile(r'^([a-z][a-z0-9+.\-]*)://', re.I)

# parece host? precisa de um ponto e nenhum espaco. Aceita porta e caminho.
RX_HOST = re.compile(r'^[A-Za-z0-9\-._]+\.[A-Za-z]{2,}(?::\d{1,5})?(?:/|$)')

# host + PORTA OPCIONAL + caminho, consumido de uma vez so.
# Isto existe por causa de um bug REAL, achado medindo o parser contra o
# gabarito: em 'https://site.example:8443/login', depois de tirar o esquema
# sobra 'site.example:8443/login' — e um split(':') ingenuo le a PORTA como se
# fosse o usuario. Consumir host[:porta][/caminho] ANTES de dividir resolve.
RX_HOSTPORT = re.compile(
    r'^([A-Za-z0-9\-._]+\.[A-Za-z]{2,}(?::\d{1,5})?(?:/[^\s:]*)?)')

# onde comeca uma URL no MEIO da linha (caso USER:PASS:URL)
RX_URL_NO_MEIO = re.compile(
    r'(?:^|:)((?:[a-z][a-z0-9+.\-]*://)?[A-Za-z0-9\-._]+\.[A-Za-z]{2,}'
    r'(?::\d{1,5})?(?:/[^\s:]*)?)$', re.I)

RX_EMAIL = re.compile(r'^[^@\s:]+@[^@\s:]+\.[A-Za-z]{2,}$')


def parece_url(tok):
    """Token e uma URL/host? (ja sem o esquema)"""
    return bool(RX_HOST.match(tok))


def parse_linha(linha):
    """Devolve (formato, dict) ou (motivo_do_descarte, None)."""
    s = linha.strip().lstrip('﻿')
    if not s:
        return ('vazia', None)
    if s.startswith('=') or s.startswith('#') or s.startswith('---'):
        return ('ruido/cabecalho', None)

    # separador alternativo: alguns dumps usam '|'
    sep = ':'
    if '|' in s and s.count('|') >= 2 and s.count(':') <= 1:
        sep = '|'

    # 1) guarda o esquema e tira da frente, para o split nao quebrar nele
    esquema = ''
    m = RX_ESQUEMA.match(s)
    if m:
        esquema = m.group(0)          # ex.: 'https://'
        s = s[len(esquema):]

    # 2) A LINHA COMECA COM URL?
    #    Consome host[:porta][/caminho] de uma vez — assim a PORTA nunca e
    #    confundida com separador. Bug real, achado medindo contra o gabarito:
    #    'https://site.example:8443/login' virava usuario='8443/login'.
    mh = RX_HOSTPORT.match(s) if sep == ':' else None
    if mh and (esquema or parece_url(s)):
        alvo = mh.group(1)
        resto = s[len(alvo):]
        url_final = esquema + alvo
        if resto == '':
            return ('URL only', {'url': url_final, 'usuario': None, 'senha': None})
        if resto.startswith(':'):
            resto = resto[1:]
            if resto == '':
                return ('URL:USER (sem PASS)',
                        {'url': url_final, 'usuario': None, 'senha': None})
            if ':' in resto:
                u, p = resto.split(':', 1)        # a senha fica INTEIRA
                if p == '':
                    return ('URL:USER (PASS vazio)',
                            {'url': url_final, 'usuario': u, 'senha': None})
                return ('URL:USER:PASS', {'url': url_final, 'usuario': u, 'senha': p})
            return ('URL:USER (sem PASS)',
                    {'url': url_final, 'usuario': resto, 'senha': None})

    # 2b) NAO comeca com URL. Se existir uma, ela esta NO FIM da linha.
    #     Caso ambiguo real: 'user:Senha:42:http://site' — a senha tem ':'.
    #     Ancorar a busca no FIM resolve sem chutar.
    if sep == ':' and s.count(':') >= 2:
        mf = RX_URL_NO_MEIO.search(s)
        if mf and mf.start(1) > 0:
            cabeca = s[:mf.start(1)].rstrip(':')
            if ':' in cabeca:
                u, p = cabeca.split(':', 1)
                return ('USER:PASS:URL',
                        {'url': mf.group(1), 'usuario': u, 'senha': p})

    partes = s.split(sep, 2)          # <-- maxsplit=2: a senha fica INTEIRA

    # 3) so um token
    if len(partes) == 1:
        t = partes[0]
        if esquema or parece_url(t):
            return ('URL only', {'url': esquema + t, 'usuario': None, 'senha': None})
        return ('token solto', None)

    # 3) dois tokens
    if len(partes) == 2:
        a, b = partes
        if esquema or parece_url(a):
            if b == '':
                return ('URL:USER (sem PASS)', {'url': esquema + a, 'usuario': None, 'senha': None})
            return ('URL:USER (sem PASS)', {'url': esquema + a, 'usuario': b, 'senha': None})
        return ('USER:PASS (sem URL)', {'url': None, 'usuario': a, 'senha': b})

    # 4) tres tokens
    a, b, c = partes
    if esquema or parece_url(a):
        if c == '':
            return ('URL:USER (PASS vazio)', {'url': esquema + a, 'usuario': b, 'senha': None})
        return ('URL:USER:PASS', {'url': esquema + a, 'usuario': b, 'senha': c})

    # nao comeca com URL: entao e USER:PASS:URL — e o 'c' pode ter esquema proprio
    if parece_url(c) or RX_ESQUEMA.match(c):
        return ('USER:PASS:URL', {'url': c, 'usuario': a, 'senha': b})

    # tres tokens, nenhum parece URL: trata como USER:PASS com ':' na senha
    return ('USER:PASS (: na senha)', {'url': None, 'usuario': a, 'senha': b + ':' + c})


def main():
    ap = argparse.ArgumentParser(description='Converte combo/ULP em NDJSON.')
    ap.add_argument('entrada')
    ap.add_argument('--ndjson', help='escreve NDJSON pronto para o _bulk aqui')
    ap.add_argument('--fonte', default='ficticio', help='rotulo do canal de origem')
    ap.add_argument('--mostrar', type=int, default=0, help='imprime N exemplos parseados')
    args = ap.parse_args()

    # encoding='utf-8-sig' come o BOM; newline='' nao mexe no CRLF
    with io.open(args.entrada, 'r', encoding='utf-8-sig',
                 errors='replace', newline='') as f:
        bruto = f.read()

    linhas = bruto.replace('\r\n', '\n').replace('\r', '\n').split('\n')

    fmt = Counter()
    saida, vistos, exemplos = [], set(), []
    dup = 0

    for ln in linhas:
        rotulo, d = parse_linha(ln)
        fmt[rotulo] += 1
        if d is None:
            continue
        chave = (d.get('url'), d.get('usuario'), d.get('senha'))
        if chave in vistos:
            dup += 1
            continue
        vistos.add(chave)
        d['formato'] = rotulo
        d['fonte'] = args.fonte
        d['usuario_eh_email'] = bool(d.get('usuario') and RX_EMAIL.match(d['usuario']))
        saida.append(d)
        if len(exemplos) < args.mostrar:
            exemplos.append((ln[:70], rotulo, d))

    total = len(linhas)
    print('arquivo .............. %s' % args.entrada)
    print('bytes ................ %d' % len(bruto.encode('utf-8')))
    print('BOM removido ......... %s' % (not bruto.startswith('﻿')))
    print('linhas lidas ......... %d' % total)
    print('registros validos .... %d' % len(saida))
    print('duplicatas removidas . %d' % dup)
    print('')
    print('formatos reconhecidos:')
    for k, v in fmt.most_common():
        print('   %-28s %5d  (%4.1f%%)' % (k, v, 100.0 * v / total if total else 0))

    com_url = sum(1 for d in saida if d['url'])
    com_senha = sum(1 for d in saida if d['senha'])
    emails = sum(1 for d in saida if d['usuario_eh_email'])
    print('')
    print('com URL .............. %d (%.1f%%)' % (com_url, 100.0 * com_url / max(1, len(saida))))
    print('com senha ............ %d (%.1f%%)' % (com_senha, 100.0 * com_senha / max(1, len(saida))))
    print('usuario e email ...... %d (%.1f%%)' % (emails, 100.0 * emails / max(1, len(saida))))

    if exemplos:
        print('')
        print('exemplos:')
        for cru, rot, d in exemplos:
            print('   %-70s' % cru)
            print('      -> %-24s url=%s user=%s pass=%s'
                  % (rot, d['url'], d['usuario'],
                     ('*' * len(d['senha'])) if d['senha'] else None))

    if args.ndjson:
        with io.open(args.ndjson, 'w', encoding='utf-8') as f:
            for i, d in enumerate(saida):
                f.write(json.dumps({'index': {'_index': 'combo_ficticio',
                                              '_id': '%s-%d' % (args.fonte, i)}}) + '\n')
                f.write(json.dumps(d, ensure_ascii=False) + '\n')
        print('')
        print('NDJSON ............... %s (%d docs)' % (args.ndjson, len(saida)))


if __name__ == '__main__':
    main()
