# Dados de exemplo — Dia 2

Arquivos para rodar os comandos de Elasticsearch **à mão**, um a um.

Este bloco da aula não é sobre automação: é sobre entender o que o Elastic faz
e o que os scripts dos outros módulos vinham fazendo por baixo. Por isso aqui
não há *loader* — os comandos estão em [`../COMANDOS_AULA_DIA2.txt`](../COMANDOS_AULA_DIA2.txt).

## O que tem aqui

| arquivo | o que é |
|---|---|
| `apt_mapping.json` | o mapeamento explícito de `apt_groups` — 21 campos |
| `apt_bulk.ndjson` | 36 grupos APT **fictícios** |
| `apt_incidentes.ndjson` | 4.655 incidentes fictícios, para o Kibana |
| `gera_apt.py` | gera os dois acima; semente fixa `20260211` |
| `ULP_MIX_FICTICIO_2026.txt` | base fictícia de combo, 6 formatos de linha |
| `ULP_MIX_FICTICIO_2026_GABARITO.tsv` | o formato verdadeiro de cada linha |
| `combo_bulk.ndjson` | a base fictícia já em NDJSON |

**Tudo é fictício.** Os APTs são gerados; os domínios do combo usam
`.invalid` / `.example` / `.test`, reservados pela RFC 2606 — não existem e não
resolvem. Nenhum dado de pessoa real está neste diretório.

## Antes de rodar

```bash
cd <raiz-do-projeto>
export ES="${ES:-http://localhost:9200}"
export S="$PWD/docs/samples"

echo "ES=$ES"; echo "S=$S"
curl -s "$ES" | head -3     # tem que responder com o cluster_name
```

Sem essas variáveis os comandos falham **em silêncio**: com `$ES` vazio o
`curl -s` devolve `(3) URL rejected` e não imprime nada; com `$S` vazio o
`--data-binary` não acha o arquivo.

## A sequência

```bash
# 1) indice com mapeamento explicito
curl -s -X PUT "$ES/apt_groups" -H 'Content-Type: application/json' \
  --data-binary @"$S/apt_mapping.json"

# 2) carga em massa
curl -s -X POST "$ES/apt_groups/_bulk" -H 'Content-Type: application/x-ndjson' \
  --data-binary @"$S/apt_bulk.ndjson" | grep -o '"errors":[a-z]*'

# 3) conferir
curl -s -X POST "$ES/apt_groups/_refresh" > /dev/null
curl -s "$ES/apt_groups/_count"
```

> **`_count` dá 36, mas `_cat/indices` mostra 144.** Não é erro: o campo
> `alvos_principais` é `nested`, e cada objeto aninhado vira um documento
> interno no Lucene. `_count` conta o que você indexou; `_cat` conta o que o
> Lucene guarda.

> **`apt_incidentes` precisa do `PUT` antes do `_bulk`.** O
> `action.auto_create_index` do laboratório libera `apt_groups*`, que **não**
> casa com `apt_incidentes` — sem criar o índice primeiro, o bulk devolve
> `index_not_found_exception` em todas as 4.655 linhas.

## O `shakespeare.json` não está aqui

São 25 MB e é download público. O comando está no runbook:

```bash
curl -sO https://download.elastic.co/demos/kibana/gettingstarted/8.x/shakespeare.json
```
