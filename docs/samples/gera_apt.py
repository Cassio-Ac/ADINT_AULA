#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gera a base FICTICIA de grupos APT para a aula de Elastic (ADINT / CTI 2026).

Por que ficticia, e nao APT28/Fancy Bear de verdade:
  os numeros (nivel_sofisticacao, numero_ataques, faixa_danos, ip_origem) sao
  inventados. Pendurar numero inventado num ator REAL ensina fato errado — o
  aluno sai da aula achando que "APT28 tem sofisticacao 9.2". Com grupos
  ficticios, a aula ensina Elastic sem ensinar CTI errado.
  Os PAISES e as TECNICAS MITRE sao reais, porque e o que da realismo as
  agregacoes e ao mapa, e nao atribui nada falso a ninguem.

Saidas (na mesma pasta deste script):
  apt_mapping.json      o mapping explicito de apt_groups
  apt_bulk.ndjson       36 grupos    -> indice apt_groups
  apt_incidentes.ndjson ~5.000 ataques em 24 meses -> indice apt_incidentes
"""
import base64, hashlib, io, json, os, random
from datetime import datetime, timedelta, timezone

random.seed(20260211)        # reproduzivel: todo mundo gera o MESMO arquivo

# escreve AO LADO deste arquivo (docs/samples), nao num caminho fixo
SAIDA = os.path.dirname(os.path.abspath(__file__))
os.makedirs(SAIDA, exist_ok=True)

# --------------------------------------------------------------- geografia
# capitais reais: dao mapa de verdade no Kibana e agregacao por pais com sentido
PAISES = {
    'Rússia':         (55.7558,  37.6176, ['85.143.', '45.142.', '91.219.']),
    'China':          (39.9042, 116.4074, ['223.5.',  '101.226.', '114.114.']),
    'Coreia do Norte':(39.0392, 125.7625, ['175.45.', '210.52.']),
    'Irã':            (35.6892,  51.3890, ['2.144.',  '5.22.',   '78.157.']),
    'Vietnã':         (21.0278, 105.8342, ['113.160.', '14.177.']),
    'Índia':          (28.6139,  77.2090, ['103.21.', '117.239.']),
    'Paquistão':      (33.6844,  73.0479, ['39.32.',  '119.160.']),
    'Belarus':        (53.9006,  27.5590, ['86.57.',  '178.120.']),
    'Brasil':         (-15.7939, -47.8828, ['177.86.', '191.252.']),
    'Nigéria':        (9.0765,    7.3986, ['41.58.',  '105.112.']),
    'Romênia':        (44.4268,  26.1025, ['86.120.', '188.26.']),
    'Turquia':        (39.9334,  32.8597, ['78.161.', '85.105.']),
}

# tecnicas MITRE ATT&CK reais (ids publicos)
TECNICAS = [
    'T1566.001', 'T1566.002', 'T1190', 'T1078', 'T1059.001', 'T1059.003',
    'T1053.005', 'T1055', 'T1027', 'T1486', 'T1071.001', 'T1041',
    'T1021.001', 'T1003.001', 'T1098', 'T1505.003', 'T1133', 'T1195.002',
]
SETORES = ['Governo', 'Energia', 'Financeiro', 'Saúde', 'Defesa', 'Telecom',
           'Industrial', 'Eleitoral', 'Academia', 'Varejo', 'Logística', 'Mídia']
ALVO_PAISES = ['Ucrânia', 'EUA', 'Brasil', 'Alemanha', 'Coreia do Sul', 'Japão',
               'Reino Unido', 'Israel', 'Índia', 'Taiwan', 'França', 'Austrália']
CLASSIF  = ['PÚBLICO', 'RESERVADO', 'CONFIDENCIAL', 'SECRETO']
ANALISTAS = ['Agent Neo', 'Agent Trinity', 'Agent Morpheus', 'Agent Oracle',
             'Agent Cypher', 'Agent Dozer']
FONTES = ['OSINT', 'HUMINT', 'SIGINT', 'Parceiro Setorial', 'Telemetria Interna',
          'CERT Nacional']

# --------------------------------------------------------------- o elenco
# Nomes INVENTADOS, no estilo da industria (numero + codinome animal/cor).
# A faixa APT-9xx nao e usada por nenhum fornecedor: deixa obvio que e ficcao.
ELENCO = [
    # (numero, codinome,            pais,              sofisticacao, ativo)
    (901, 'Vermillion Bear',  'Rússia',          9.4, True),
    (902, 'Glacial Panda',    'China',           9.1, True),
    (903, 'Obsidian Chollima','Coreia do Norte', 8.8, True),
    (904, 'Saffron Kitten',   'Irã',             7.9, True),
    (905, 'Lacquer Buffalo',  'Vietnã',          7.2, True),
    (906, 'Cinder Tiger',     'Índia',           6.8, True),
    (907, 'Marble Bear',      'Rússia',          8.6, True),
    (908, 'Jade Panda',       'China',           8.9, True),
    (909, 'Rust Jackal',      'Turquia',         5.4, False),
    (910, 'Amber Spider',     'Romênia',         6.1, True),
    (911, 'Verdigris Panda',  'China',           7.7, True),
    (912, 'Pewter Kitten',    'Irã',             6.9, True),
    (913, 'Cobalt Chollima',  'Coreia do Norte', 9.0, True),
    (914, 'Ochre Bear',       'Belarus',         6.4, True),
    (915, 'Basalt Spider',    'Brasil',          5.8, True),
    (916, 'Quartz Jackal',    'Nigéria',         4.9, True),
    (917, 'Indigo Panda',     'China',           8.2, False),
    (918, 'Cerulean Bear',    'Rússia',          8.1, True),
    (919, 'Garnet Kitten',    'Irã',             7.4, True),
    (920, 'Slate Buffalo',    'Vietnã',          6.6, True),
    (921, 'Copper Tiger',     'Índia',           6.2, False),
    (922, 'Onyx Chollima',    'Coreia do Norte', 8.4, True),
    (923, 'Mauve Spider',     'Romênia',         5.6, True),
    (924, 'Thistle Jackal',   'Paquistão',       5.1, True),
    (925, 'Porcelain Panda',  'China',           7.1, True),
    (926, 'Ferrous Bear',     'Rússia',          7.8, False),
    (927, 'Umber Kitten',     'Irã',             6.3, True),
    (928, 'Lilac Buffalo',    'Vietnã',          5.9, True),
    (929, 'Granite Spider',   'Brasil',          6.7, True),
    (930, 'Sable Jackal',     'Nigéria',         4.4, False),
    (931, 'Celadon Panda',    'China',           7.5, True),
    (932, 'Crimson Chollima', 'Coreia do Norte', 8.0, True),
    (933, 'Bronze Tiger',     'Índia',           5.3, True),
    (934, 'Teal Bear',        'Belarus',         6.0, True),
    (935, 'Vellum Kitten',    'Irã',             7.0, False),
    (936, 'Ashen Spider',     'Turquia',         4.7, True),
]

# --------------------------------------------- o relatorio (o campo do TF-IDF)
# Engenharia proposital, para o slide de TF-IDF funcionar de verdade:
#
#   TF  -> "ataques ciberneticos" aparece 1..6 vezes, e SO em 14 dos 36 docs.
#          (se estivesse em todos, o IDF iria a zero e o score ficaria em 0,04
#           para todo mundo — foi o que aconteceu na primeira versao desta base)
#   IDF -> "malware" esta em TODOS (IDF baixo, score ~0)
#          FRASE_RARA esta em 3 (IDF alto, score ~7)
#   COMPRIMENTO -> todos os relatorios tem o MESMO numero de frases, com
#          enchimento neutro, para a normalizacao por tamanho do BM25 nao
#          cancelar o ganho de TF.
FRASE_RARA = 'cadeia de suprimentos de software'     # aparece em 3 docs so
FRASES_TOTAL = 8                                      # igual para todos

ENCHIMENTO = [
    'A atribuicao segue criterios de confianca media.',
    'O padrao de infraestrutura foi observado em multiplas campanhas.',
    'Houve reuso de certificados em servidores de comando.',
    'A janela de atividade concentra-se em horario comercial local.',
    'Relatorios parceiros corroboram parte dos indicadores.',
    'A telemetria indica persistencia em hospedeiros de borda.',
    'Nao ha evidencia de colaboracao com outros grupos.',
    'A cadencia operacional caiu no ultimo trimestre observado.',
]

def monta_relatorio(nome, codinome, pais, setor, repete, rnd):
    """repete = quantas vezes 'ataques ciberneticos' aparece (0 = nao aparece)."""
    frases = ['O grupo %s, tambem conhecido como %s, opera a partir de %s.'
              % (nome, codinome, pais),
              'O grupo emprega malware personalizado e tecnicas de evasao.']
    for _ in range(repete):
        frases.append('Os ataques ciberneticos do %s visam o setor %s.'
                      % (nome, setor.lower()))
    # completa ate FRASES_TOTAL com enchimento neutro -> comprimento parecido
    i = 0
    while len(frases) < FRASES_TOTAL:
        frases.append(ENCHIMENTO[i % len(ENCHIMENTO)])
        i += 1
    return ' '.join(frases[:FRASES_TOTAL])

# --------------------------------------------------------------- geracao
def jitter(base, grau=2.5):
    return round(base + random.uniform(-grau, grau), 4)

def ip_de(pais):
    pref = random.choice(PAISES[pais][2])
    falta = 4 - len(pref.rstrip('.').split('.'))
    return pref + '.'.join(str(random.randint(1, 254)) for _ in range(falta))

grupos = []
for idx, (num, codinome, pais, sofist, ativo) in enumerate(ELENCO, start=1):
    nome = 'APT-%d' % num
    lat, lon, _ = PAISES[pais]
    setor_principal = SETORES[idx % len(SETORES)]
    # TF: so 14 dos 36 falam em "ataques ciberneticos", com 1..6 ocorrencias.
    # Os outros 22 ficam com 0 -> IDF do termo fica saudavel (~0,9 em vez de 0,05).
    TF_POR_DOC = {1: 6, 2: 6, 3: 5, 4: 5, 5: 4, 6: 4, 7: 3, 8: 3,
                  9: 2, 10: 2, 11: 1, 12: 1, 13: 1, 14: 1}
    repete = TF_POR_DOC.get(idx, 0)

    ano_ini = random.randint(2006, 2019)
    primeiro = datetime(ano_ini, random.randint(1, 12), random.randint(1, 28),
                        random.randint(0, 23), random.randint(0, 59),
                        tzinfo=timezone.utc)
    if ativo:
        ultimo = datetime(2026, random.randint(1, 10), random.randint(1, 28),
                          random.randint(0, 23), random.randint(0, 59),
                          tzinfo=timezone.utc)
        fim_periodo = '2026-12-31'
    else:
        ano_fim = random.randint(2019, 2024)
        ultimo = datetime(ano_fim, random.randint(1, 12), random.randint(1, 28),
                          random.randint(0, 23), random.randint(0, 59),
                          tzinfo=timezone.utc)
        fim_periodo = '%d-12-31' % ano_fim

    n_alvos = random.randint(2, 4)
    alvos = []
    for k in range(n_alvos):
        alvos.append({
            'setor': setor_principal if k == 0 else random.choice(SETORES),
            'pais': random.choice(ALVO_PAISES),
            'prioridade': random.randint(4, 10),
        })

    relatorio = monta_relatorio(nome, codinome, pais, setor_principal, repete, random)
    if num in (902, 908, 913):                       # so 3 docs: IDF alto
        relatorio += (' A operacao incluiu comprometimento da %s.' % FRASE_RARA)

    doc = {
        'id': idx,
        'nome': nome,
        'nome_original': codinome,
        'pais_origem': pais,
        'ativo': ativo,
        'primeiro_avistamento': primeiro.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'ultimo_ataque': ultimo.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'nivel_sofisticacao': sofist,
        'numero_ataques': int(random.gauss(sofist * 130, 180)) + 40,
        'coordenadas_base': {'lat': jitter(lat), 'lon': jitter(lon)},
        'ip_origem': ip_de(pais),
        'periodo_atividade': {'gte': '%d-01-01' % ano_ini, 'lte': fim_periodo},
        # espalhamento largo de proposito: grupo pequeno vai de 80 mil a 3 mi,
        # grupo de ponta vai de 2 mi a 480 mi. Assim o range query DISCRIMINA
        # (na 1a versao todos continham 20 mi e a consulta devolvia 36 de 36).
        'faixa_danos': {'gte': round(10 ** (4.4 + sofist * 0.19), 1),
                        'lte': round(10 ** (5.9 + sofist * 0.28), 1)},
        'tecnicas_mitre': sorted(random.sample(TECNICAS, random.randint(3, 7))),
        'alvos_principais': alvos,
        'relatorio': relatorio,
        'metadados': {
            'classificacao': CLASSIF[min(3, int(sofist // 2.5))],
            'analista_responsavel': random.choice(ANALISTAS),
            'fonte_inteligencia': random.choice(FONTES),
        },
        'hash_malware': hashlib.md5(('%s-%s' % (nome, codinome)).encode()).hexdigest(),
        'autocomplete_busca': {
            'input': [nome, codinome, codinome.split()[-1], pais],
            'weight': int(sofist * 2),
        },
        'vetor_comportamental': [round(random.uniform(0.3, 1.0), 2) for _ in range(5)],
        'documento_classificado': base64.b64encode(
            ('Dossie ficticio %s / %s' % (nome, codinome)).encode('utf-8')
        ).decode('ascii'),
    }
    doc['numero_ataques'] = max(25, doc['numero_ataques'])
    grupos.append(doc)

# --------------------------------------------------------------- mapping
mapping = {
    'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    'mappings': {'properties': {
        'id':                   {'type': 'integer'},
        'nome':                 {'type': 'text',
                                 'fields': {'keyword': {'type': 'keyword'}}},
        'nome_original':        {'type': 'text',
                                 'fields': {'keyword': {'type': 'keyword'}}},
        'pais_origem':          {'type': 'keyword'},
        'ativo':                {'type': 'boolean'},
        'primeiro_avistamento': {'type': 'date'},
        'ultimo_ataque':        {'type': 'date'},
        'nivel_sofisticacao':   {'type': 'float'},
        'numero_ataques':       {'type': 'integer'},
        'coordenadas_base':     {'type': 'geo_point'},
        'ip_origem':            {'type': 'ip'},
        'periodo_atividade':    {'type': 'date_range'},
        'faixa_danos':          {'type': 'double_range'},
        'tecnicas_mitre':       {'type': 'keyword'},
        'alvos_principais':     {'type': 'nested', 'properties': {
                                    'setor':      {'type': 'keyword'},
                                    'pais':       {'type': 'keyword'},
                                    'prioridade': {'type': 'integer'}}},
        'relatorio':            {'type': 'text'},
        'metadados':            {'properties': {
                                    'classificacao':        {'type': 'keyword'},
                                    'analista_responsavel': {'type': 'keyword'},
                                    'fonte_inteligencia':   {'type': 'keyword'}}},
        'hash_malware':         {'type': 'keyword'},
        'autocomplete_busca':   {'type': 'completion'},
        'vetor_comportamental': {'type': 'dense_vector', 'dims': 5,
                                 'index': True, 'similarity': 'cosine'},
        'documento_classificado': {'type': 'binary'},
    }}
}

# --------------------------------------------------------------- escrita
with io.open(os.path.join(SAIDA, 'apt_mapping.json'), 'w', encoding='utf-8') as f:
    json.dump(mapping, f, ensure_ascii=False, indent=2)

with io.open(os.path.join(SAIDA, 'apt_bulk.ndjson'), 'w', encoding='utf-8') as f:
    for d in grupos:
        f.write(json.dumps({'index': {'_id': str(d['id'])}}, ensure_ascii=False) + '\n')
        f.write(json.dumps(d, ensure_ascii=False) + '\n')

# ------------------------------------------------- indice de INCIDENTES (volume)
TIPOS = ['Phishing', 'Exploração de borda', 'Ransomware', 'Exfiltração',
         'Movimentação lateral', 'Comprometimento de cadeia', 'Credential stuffing']
STATUS = ['contido', 'em investigação', 'confirmado', 'falso positivo']
inicio = datetime(2025, 1, 1, tzinfo=timezone.utc)

incidentes = []
iid = 0
for d in grupos:
    # grupo mais sofisticado -> mais incidentes
    n = int(d['nivel_sofisticacao'] * random.uniform(12, 26))
    for _ in range(n):
        iid += 1
        quando = inicio + timedelta(minutes=random.randint(0, 24 * 60 * 365 * 2))
        alvo = random.choice(d['alvos_principais'])
        lat, lon, _ = PAISES[d['pais_origem']]
        incidentes.append({
            'incidente_id': 'INC-%05d' % iid,
            '@timestamp': quando.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'grupo': d['nome'],
            'grupo_codinome': d['nome_original'],
            'pais_origem': d['pais_origem'],
            'origem_geo': {'lat': jitter(lat, 4.0), 'lon': jitter(lon, 4.0)},
            'ip_atacante': ip_de(d['pais_origem']),
            'tipo': random.choice(TIPOS),
            'tecnica_mitre': random.choice(d['tecnicas_mitre']),
            'setor_alvo': alvo['setor'],
            'pais_alvo': alvo['pais'],
            'severidade': random.randint(1, 10),
            'prejuizo_usd': round(random.lognormvariate(11, 1.4), 2),
            'status': random.choice(STATUS),
            'bloqueado': random.random() < 0.62,
        })

random.shuffle(incidentes)
with io.open(os.path.join(SAIDA, 'apt_incidentes.ndjson'), 'w', encoding='utf-8') as f:
    for d in incidentes:
        f.write('{"index":{}}\n')
        f.write(json.dumps(d, ensure_ascii=False) + '\n')

# --------------------------------------------------------------- relatorio
def kb(p):
    return os.path.getsize(os.path.join(SAIDA, p)) / 1024.0

print('=' * 72)
print('BASE FICTICIA DE APTs GERADA EM %s' % SAIDA)
print('=' * 72)
print('  apt_mapping.json        %7.1f KB   mapping explicito' % kb('apt_mapping.json'))
print('  apt_bulk.ndjson         %7.1f KB   %d grupos' % (kb('apt_bulk.ndjson'), len(grupos)))
print('  apt_incidentes.ndjson   %7.1f KB   %d incidentes' % (kb('apt_incidentes.ndjson'), len(incidentes)))
print()
print('  tipos de campo cobertos:')
for t in ['text + keyword', 'keyword', 'boolean', 'date', 'float', 'integer',
          'geo_point', 'ip', 'date_range', 'double_range', 'nested',
          'object', 'completion', 'dense_vector', 'binary']:
    print('     - %s' % t)
print()
print('  engenharia do TF-IDF no campo `relatorio`:')
from collections import Counter
c = Counter()
for d in grupos:
    c['ataques ciberneticos'] += d['relatorio'].lower().count('ataques ciberneticos')
    if 'malware' in d['relatorio'].lower():
        c['docs com "malware"'] += 1
    if FRASE_RARA in d['relatorio'].lower():
        c['docs com a frase rara'] += 1
print('     ocorrencias totais de "ataques ciberneticos": %d' % c['ataques ciberneticos'])
print('     docs com "malware" (IDF baixo)              : %d de %d' % (c['docs com "malware"'], len(grupos)))
print('     docs com "%s" (IDF alto)  : %d de %d' % (FRASE_RARA, c['docs com a frase rara'], len(grupos)))
