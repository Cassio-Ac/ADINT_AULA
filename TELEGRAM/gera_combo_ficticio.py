#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gera uma base FICTICIA de combo/ULP no padrao real dos canais de infostealer.

POR QUE SINTETICA: os canais vivos so postam .rar/.zip de 63 MB a 2,3 GB com
credencial de VITIMA REAL. Para ensinar o PARSING nao e preciso — nem legitimo —
levar dado de vitima para a sala. O que o aluno precisa e da FORMA, e a forma
esta declarada no slide 32:

    URL:USER:PASS   /   USER:PASS:URL   /   URL:USER (no PASS)
    URL only        /   URL (no scheme):USER:PASS   /   USER:PASS (no URL)

Esta base reproduz as 6 variantes MAIS a sujeira real que quebra parser:
BOM, CRLF misturado, linha vazia, duplicata, separador trocado, porta na URL,
senha contendo ':', usuario que e email, lixo no meio.

Dominios: .invalid e .example (RFC 2606/6761) — nao resolvem, nao existem,
nao ha risco de apontar para alguem real.
"""
import hashlib
import io
import random
import sys

SEMENTE = 20260211          # mesma semente da base de APTs: aula reproduzivel
random.seed(SEMENTE)

SAIDA = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 2000

MARCAS = ['portalbanco', 'lojamodelo', 'webmail', 'intranet', 'crm', 'vpn',
          'contaonline', 'faturamento', 'rh', 'suporte', 'ead', 'clientes',
          'admin', 'extranet', 'cobranca']
TLDS = ['.invalid', '.example', '.test']
CAMINHOS = ['', '/login', '/login.php', '/signin', '/auth/login', '/admin',
            '/wp-login.php', '/portal/entrar', '/users/sign_in', '/#/login']
NOMES = ['ana', 'bruno', 'carla', 'diego', 'elisa', 'fabio', 'gisele', 'hugo',
         'ines', 'joao', 'karina', 'lucas', 'marina', 'nelson', 'olivia',
         'paulo', 'queila', 'rafael', 'sofia', 'tiago', 'ursula', 'vitor']
SOBRE = ['silva', 'souza', 'costa', 'lima', 'alves', 'rocha', 'dias', 'pinto',
         'moraes', 'farias', 'braga', 'cunha', 'teixeira', 'barros']
PALAVRAS = ['Senha', 'Acesso', 'Brasil', 'Futebol', 'Verao', 'Cachorro', 'Praia',
            'Musica', 'Estrela', 'Montanha', 'Girassol', 'Chocolate']


def dominio():
    return '%s%s' % (random.choice(MARCAS) +
                     random.choice(['', '-' + random.choice(['br', 'sp', 'app', 'web'])]),
                     random.choice(TLDS))


def url(com_esquema=True, com_porta=False):
    d = dominio()
    p = random.choice(CAMINHOS)
    porta = ':%d' % random.choice([8080, 8443, 3000, 8000]) if com_porta else ''
    if com_esquema:
        return '%s://%s%s%s' % (random.choice(['https', 'http']), d, porta, p)
    return '%s%s%s' % (d, porta, p)


def usuario():
    n, s = random.choice(NOMES), random.choice(SOBRE)
    estilo = random.random()
    if estilo < 0.45:                                   # email
        return '%s.%s@%s' % (n, s, dominio())
    if estilo < 0.70:
        return '%s%s%d' % (n, s, random.randint(1, 99))
    if estilo < 0.85:
        return '%s_%s' % (n, s)
    return n + str(random.randint(100, 9999))


def senha():
    e = random.random()
    if e < 0.30:
        return '%s%d' % (random.choice(PALAVRAS), random.randint(1, 999))
    if e < 0.50:
        return '%s@%d' % (random.choice(PALAVRAS), random.randint(10, 99))
    if e < 0.62:                                        # senha COM ':' — quebra split
        return '%s:%d' % (random.choice(PALAVRAS), random.randint(10, 99))
    if e < 0.72:
        return ''.join(random.choice('abcdefghijkmnpqrstuvwxyz23456789')
                       for _ in range(random.randint(8, 14)))
    if e < 0.80:
        return random.choice(['123456', 'senha123', 'admin', 'qwerty123', '102030'])
    return '%s%s%d!' % (random.choice(PALAVRAS), random.choice(['', '_', '-']),
                        random.randint(1, 99))


linhas, formatos = [], {}
GABARITO = []          # (linha, formato_verdadeiro)


def add(txt, rotulo):
    linhas.append(txt)
    GABARITO.append((txt, rotulo))
    formatos[rotulo] = formatos.get(rotulo, 0) + 1


for _ in range(N):
    r = random.random()
    if r < 0.46:
        add('%s:%s:%s' % (url(), usuario(), senha()), 'URL:USER:PASS')
    elif r < 0.62:
        add('%s:%s:%s' % (usuario(), senha(), url()), 'USER:PASS:URL')
    elif r < 0.72:
        add('%s:%s:%s' % (url(False), usuario(), senha()), 'URL(sem esquema):USER:PASS')
    elif r < 0.82:
        add('%s:%s' % (usuario(), senha()), 'USER:PASS (sem URL)')
    elif r < 0.90:
        add('%s:%s' % (url(), usuario()), 'URL:USER (sem PASS)')
    else:
        add(url(com_porta=random.random() < 0.3), 'URL only')

# ---- a sujeira que quebra parser de verdade -------------------------------
sujeira = []
for _ in range(int(N * 0.04)):
    sujeira.append(('', 'linha vazia'))
for _ in range(int(N * 0.03)):                       # separador trocado
    sujeira.append(('%s|%s|%s' % (url(), usuario(), senha()), 'separador | em vez de :'))
for _ in range(int(N * 0.02)):
    sujeira.append(('===== %s =====' % random.choice(
        ['ULP MIX 2026', 'FREE SAMPLE', 'PRIVATE CLOUD', 'by @canal_ficticio']), 'cabecalho/ruido'))
for _ in range(int(N * 0.02)):
    sujeira.append(('android://%s@%s' % (
        hashlib.md5(str(random.random()).encode()).hexdigest()[:22], dominio()),
        'android:// (app, nao site)'))
for _ in range(int(N * 0.01)):
    sujeira.append(('%s:%s:' % (url(), usuario()), 'PASS vazio (termina em :)'))

for txt, rot in sujeira:
    add(txt, rot)

# duplicatas exatas: 6% — o aluno PRECISA descobrir que elas existem
dups = random.sample(linhas, int(len(linhas) * 0.06))
for d in dups:
    add(d, '(duplicata exata)')

random.shuffle(linhas)

# CRLF misturado com LF em ~15% das linhas, e BOM no inicio: igual ao real
corpo = []
for ln in linhas:
    corpo.append(ln + ('\r\n' if random.random() < 0.15 else '\n'))
texto = '\ufeff' + ''.join(corpo)

with io.open(SAIDA, 'w', encoding='utf-8', newline='') as f:
    f.write(texto)

bruto = texto.encode('utf-8')
print('arquivo .............. %s' % SAIDA)
print('bytes ................ %d' % len(bruto))
print('linhas (total) ....... %d' % len(linhas))
print('BOM no inicio ........ %s' % (bruto[:3] == b'\xef\xbb\xbf'))
print('linhas com CRLF ...... %d' % texto.count('\r\n'))
print('')
print('composicao (o gabarito do exercicio):')
for k, v in sorted(formatos.items(), key=lambda x: -x[1]):
    print('   %-30s %5d  (%4.1f%%)' % (k, v, 100.0 * v / len(linhas)))
print('')
print('linhas unicas ........ %d' % len(set(l for l in linhas)))
print('duplicadas ........... %d' % (len(linhas) - len(set(linhas))))

# ---- gabarito: linha <TAB> formato verdadeiro ----------------------------
gab = SAIDA.replace('.txt', '') + '_GABARITO.tsv'
with io.open(gab, 'w', encoding='utf-8', newline='\n') as f:
    for txt, rot in GABARITO:
        f.write('%s\t%s\n' % (txt.replace('\t', ' '), rot))
print('gabarito ............. %s' % gab)
