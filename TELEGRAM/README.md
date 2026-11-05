# Módulo Telegram — ADINT 2026

Coleta em canais públicos de Telegram e indexação no Elasticsearch.

Os scripts são **didáticos**: curtos, lineares, um assunto cada. Rode na ordem.

---

## Antes de começar

```bash
pip install -r TELEGRAM/requirements.txt
```

Crie o app em <https://my.telegram.org/apps> e preencha o `.env` **na raiz do projeto**:

```bash
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=<32 caracteres hexadecimais>
TELEGRAM_PHONE=+5511999999999
TELEGRAM_SESSION=sessao_adint          # só o NOME, sem caminho
ADINT_DOWNLOADS=~/adint_downloads      # opcional; é o default
ES_URL=http://localhost:9200           # opcional; é o default
```

> No `my.telegram.org`, **App title** e **Short name** aceitam só letras e números,
> 5 a 32 caracteres. Acento, espaço ou pontuação fazem o site devolver um erro
> genérico sem dizer qual campo está errado.

O `.env` e os `*.session` estão no `.gitignore`. **Não commite nenhum dos dois.**

---

## A ordem

| # | script | o que ensina |
|---|---|---|
| 1 | `criar_sessao.py` | cria o `.session`; por que `getpass` e não `input` |
| 2 | `usar_sessao.py` | usar a sessão: sem telefone, sem código, sem senha |
| 3 | `usar_sessao_id_fake.py` | **a sessão é a credencial** — entra com `api_id=1` |
| 4 | `campos_mensagem.py` | os campos de uma mensagem, em 5 famílias, e um JSON |
| 5 | `url_escondida.py` | `m.message` × `m.text`: a URL que some se indexar errado |
| 6 | `baixa_arquivo_aberto.py` | álbum: 6 arquivos num post, escolhe 1 e abre |
| 7 | `baixa_arquivo.py` | arquivo cifrado: baixa, mostra a senha, **não abre** |
| 8 | `manda_combo_elastic.py` | credencial vazada vira política de senha |
| 9 | `coletor_cve_leak.py` | as mensagens → `telegram_cve` / `telegram_leak` |

Apoio:

- `criar_sessao_completo.py` — a versão endurecida do passo 1 (validação, guardas
  de caminho, tratamento por exceção). Use como referência de "vira produção".
- `nome_grupos.py` — lista os diálogos da conta e seus IDs.
- `parse_combo.py` / `gera_combo_ficticio.py` — base **fictícia** de combo e o
  parser dos 6 formatos de linha. Domínios `.invalid` / `.example` (RFC 2606).

---

## Três regras que o código executa

**A sessão nasce em `~/.adint/telegram/`, nunca na pasta do projeto.**
Em `/mnt/c` o `chmod 600` é silenciosamente ignorado pelo DrvFs; no ext4 funciona.
O `criar_sessao_completo.py` recusa gravar em OneDrive, Dropbox ou dentro de um
repositório git — procurando `.git` árvore acima.

**`connect()`, nunca `start()`.**
`start()` pergunta o telefone no `stdin`. Em `cron`, container ou pipe ele espera
para sempre e parece problema de rede.

**Nada é baixado sem passar por um portão.**
O tamanho é conferido **antes** do download, e em `baixa_arquivo.py` a recusa é
por procedência, não só por tamanho — um `.csv` de 2 KB de canal real continua
sendo dado de vítima.

---

## Onde os arquivos caem

`ADINT_DOWNLOADS` (padrão `~/adint_downloads`). **Fora do repositório.**
Arquivo de canal de crime contém dado de terceiro: não commite, não sincronize
em nuvem, não projete em tela. Os scripts mascaram usuário e senha na saída —
o domínio é preservado de propósito, porque ele é o achado, não a vítima.

Nenhum script abre, extrai ou descompacta o que baixa.

---

## Índices gerados

| índice | origem | serve para |
|---|---|---|
| `telegram_cve` | `@CVEDetector` | CVEs com `cve_ids` extraídos |
| `telegram_leak` | `@breachdetect` | mensagens de vazamento |
| `telegram_combo_br` | arquivo de combo | e-mail, domínio, senha, termo-base |

Todos com mapeamento explícito e `_id` determinístico: **rodar duas vezes não duplica.**
