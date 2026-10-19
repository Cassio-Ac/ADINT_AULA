#!/usr/bin/env bash
# =============================================================================
#  coletor.sh — subfinder → httpx → naabu → tlsx → nuclei
#  Curso ADINT · etapa COLETAR do pipeline (COLETAR → TRATAR → ARMAZENAR → UTILIZAR)
# =============================================================================
#
#  #############################################################
#  ##                                                         ##
#  ##   ESTE SCRIPT MANDA PACOTE PARA O ALVO.                 ##
#  ##   NÃO É COLETA PASSIVA. É COLETA ATIVA.                 ##
#  ##                                                         ##
#  #############################################################
#
#  WHOIS, DNS e Shodan são passivos: você lê o banco de dados de um terceiro que
#  já coletou. AQUI NÃO. As etapas httpx, naabu, tlsx e nuclei abrem conexão TCP
#  com a máquina do alvo. Isso:
#    · aparece no log de acesso dele, com o SEU endereço IP;
#    · dispara alerta de WAF / IDS / SOC;
#    · tem consequência legal.
#
#  RODE SOMENTE CONTRA:
#    · domínio que é SEU; ou
#    · domínio para o qual você tem AUTORIZAÇÃO ESCRITA, com escopo e janela
#      de execução definidos por escrito.
#
#  PARA TREINAR SEM RISCO:
#    · vulnweb.com  — a Acunetix mantém esse domínio público exatamente para
#                     servir de alvo de treino. É o alvo padrão das aulas.
#    · um alvo seu  — o docker-compose.yml do repositório sobe um OWASP Juice
#                     Shop local (perfil `targets`).
#
#  "Eu só queria ver" não é autorização. Curiosidade não é escopo. Escanear
#  infraestrutura de terceiro sem permissão é crime em praticamente qualquer
#  jurisdição, inclusive no Brasil.
#
# -----------------------------------------------------------------------------
#  O QUE FAZ
# -----------------------------------------------------------------------------
#  Sai de uma lista de domínios e chega a um retrato da superfície exposta,
#  encadeando as cinco ferramentas do Project Discovery:
#
#    subfinder  →  dig  →  httpx  →  naabu  →  tlsx  →  nuclei
#    (passivo)   (resolve) (FILTRO) (portas)  (certs)  (assinaturas)
#
#  A ORDEM NÃO É DECORATIVA. Cada etapa existe para reduzir o trabalho da
#  seguinte; o httpx é o pedágio do pipeline. Cada seção numerada abaixo explica
#  o seu próprio papel — leia os comentários na ordem em que aparecem.
#
# -----------------------------------------------------------------------------
#  COMO RODAR
# -----------------------------------------------------------------------------
#    bash coletor.sh dominios.txt
#    bash coletor.sh --no-color dominios.txt            # sem ANSI (log / CI / pipe)
#    OUT_DIR=saida_treino bash coletor.sh dominios.txt  # troca o diretório de saída
#    PD_BIN_DIR="$(pdtm -sp -silent)" bash coletor.sh dominios.txt
#
#  É só isso: o script não tem mais nenhuma flag. O que ele aceita é
#
#    $1               arquivo de domínios, um por linha. Padrão: dominios.txt
#    --no-color       desliga as cores. PRECISA vir ANTES do arquivo — o script
#                     só olha essa opção na primeira posição.
#    OUT_DIR  (env)   diretório de saída. Padrão: out
#    PD_BIN_DIR (env) diretório dos binários do Project Discovery. Se vazio, o
#                     script descobre sozinho (ver o bloco "localizar binários").
#
#  Tudo o que é ajuste de agressividade (rate limit, concorrência, timeout, lista
#  de portas) está escrito direto na linha de comando de cada ferramenta, dentro
#  das seções. Os pontos exatos estão marcados com "AJUSTE AQUI".
#
# -----------------------------------------------------------------------------
#  O QUE PRODUZ   (tudo abaixo de $OUT_DIR — por padrão ./out)
# -----------------------------------------------------------------------------
#    subfinder/subdomains_all.txt       nomes crus do subfinder            (texto)
#    subfinder/subdomains_filtered.txt  idem, sem localhost.*              (texto)
#    httpx/httpx.jsonl                  url, status_code, title, scheme…  (JSONL)
#    httpx/hosts_alive.txt              hostnames que responderam          (texto)
#    httpx/urls_alive.txt               URLs que responderam               (texto)
#    naabu/naabu.json                   {ip, port, …} — é JSONL, apesar do .json
#    tlsx/san.jsonl   tlsx/san.txt      SAN dos certificados        (JSONL/texto)
#    tlsx/certs.jsonl tlsx/certs.txt    certificados                (JSONL/texto)
#    nuclei/nuclei.jsonl                um achado por linha                (JSONL)
#    tmp/                               intermediários — pode apagar depois
#    elk/                               cópia dos JSONL para indexar no Elastic
#
#  JSONL = um objeto JSON por linha, sem vírgula nem colchete em volta. É o
#  formato do pipeline inteiro porque dá para processar linha a linha (`jq`,
#  `_bulk` do Elasticsearch) sem carregar o arquivo todo na memória — e porque
#  uma linha corrompida não invalida o arquivo inteiro.
#
#  Para ler a saída:
#    jq -r '[.url, (.status_code|tostring), .title] | @tsv' out/httpx/httpx.jsonl
#    jq -r '[.host, .port] | @tsv'                          out/naabu/naabu.json
#    jq -r '[.host, .info.severity, .info.name] | @tsv'     out/nuclei/nuclei.jsonl
#
# -----------------------------------------------------------------------------
#  O QUE PRECISA
# -----------------------------------------------------------------------------
#  Project Discovery (instalados pelo pdtm, SEM sudo — ver aviso mais abaixo):
#    subfinder httpx naabu tlsx nuclei
#  Sistema:
#    dig (dnsutils)  jq  awk  column  tee  bc
#  Rede:
#    saída liberada; naabu usa SYN scan quando tem privilégio e cai sozinho para
#    CONNECT scan quando não tem — funciona igual, só mais lento e mais visível.
#
# -----------------------------------------------------------------------------
#  LEIA ANTES DE CONCLUIR QUALQUER COISA
# -----------------------------------------------------------------------------
#  "Zero achados" e "zero verificado" são a MESMA saída e coisas OPOSTAS. Um
#  scanner que não alcançou o alvo encerra com sucesso e relatório vazio. Antes
#  de dizer que algo está limpo, confirme que a ferramenta chegou lá: olhe as
#  contagens que cada seção imprime. Contagem zero no httpx invalida tudo o que
#  vem depois.
# =============================================================================

# set -u: usar variável não definida aborta o script. Pega erro de digitação em
# nome de variável, que em shell falharia calado (string vazia) e levaria o
# pipeline a escanear "" ou gravar em /.
# Note que NÃO há `set -e`: quase toda chamada de ferramenta termina com
# `|| true`, de propósito — um alvo morto no meio da lista não deve derrubar a
# coleta inteira. O preço é que falha silenciosa é possível: por isso cada etapa
# imprime a sua contagem.
set -u

# ---------- argumentos ----------
# Só uma opção, e só na primeira posição: `bash coletor.sh --no-color dominios.txt`.
# Depois do shift, $1 volta a ser o arquivo de domínios.
# Use --no-color quando a saída for para arquivo, pipe ou CI: os códigos ANSI
# sujam o log e atrapalham grep/awk em cima dele.
NO_COLOR=0
if [[ "${1:-}" == "--no-color" ]]; then NO_COLOR=1; shift; fi

# Arquivo de alvos: um domínio por linha. Coloque aqui SÓ o que você pode
# escanear — este arquivo é o escopo do teste, e é a única barreira entre o
# pipeline e um alvo que não é seu.
DOMS_FILE="${1:-dominios.txt}"

# Raiz de todas as saídas. Relativa ao diretório de onde você rodou o script.
# Sobrescreva com a variável de ambiente OUT_DIR para separar coletas:
#   OUT_DIR=out_vulnweb bash coletor.sh dominios.txt
OUT="${OUT_DIR:-out}"

# --- paths de saída
# Todo caminho daqui para baixo é derivado de $OUT, nunca absoluto: o script roda
# na máquina de cada aluno, com outro usuário e outro HOME. Caminho fixo aqui
# seria bug garantido.
SUBS_ALL="$OUT/subfinder/subdomains_all.txt"    # tudo que o subfinder achou (cru)
SUBS_FILT="$OUT/subfinder/subdomains_filtered.txt"  # sem localhost.*

HTTPX_JSON="$OUT/httpx/httpx.jsonl"             # o resultado mais importante do script

IPS_TXT="$OUT/tmp/ips.txt"                      # IPs resolvidos (todos)
IPS_FILT="$OUT/tmp/ips_filtered.txt"            # IPs sem 127.0.0.1 — entrada do naabu

NAABU_JSON="$OUT/naabu/naabu.json"              # JSONL (o nome .json engana)

# Os quatro nomes TLSX_* abaixo são montagens intermediárias de alvos para o
# tlsx. Atenção: parte deles é reatribuída na seção 5 e parte nunca é usada
# (TLSX_TARGETS_DOM / _IPS / _HTTPS, e este TLSX_HOSTS_RAW, que a seção 5 troca
# por tlsx_hosts_dom.txt). É resíduo de versão anterior; não apague sem rodar o
# script inteiro antes e depois.
TLSX_HOSTS_RAW="$OUT/tmp/tlsx_hosts_raw.txt"
TLSX_IPS443="$OUT/tmp/tlsx_ip_endpoints.txt"
TLSX_HTTPS_HOSTS="$OUT/tmp/tlsx_hosts_from_httpx.txt"
TLSX_TARGETS="$OUT/tmp/tlsx_targets.txt"
TLSX_TARGETS_DOM="$OUT/tmp/tlsx_targets_dom.txt"
TLSX_TARGETS_IPS="$OUT/tmp/tlsx_targets_ip.txt"
TLSX_TARGETS_HTTPS="$OUT/tmp/tlsx_targets_https.txt"

TLSX_SAN_TXT="$OUT/tlsx/san.txt"
TLSX_CERTS_TXT="$OUT/tlsx/certs.txt"

NUCLEI_JSONL="$OUT/nuclei/nuclei.jsonl"         # achados do nuclei, um por linha

ELK_DIR="$OUT/elk"                              # cópia plana dos JSONL p/ indexação

# Cria a árvore de saída de uma vez (brace expansion do bash). `-p` não reclama
# se já existir, então rodar o script duas vezes no mesmo OUT é seguro — mas os
# arquivos de saída são SOBRESCRITOS. Para guardar uma coleta, mude OUT_DIR.
mkdir -p "$OUT"/{subfinder,httpx,naabu,tlsx,nuclei,tmp,elk}

# ---------- UI helpers ----------
# Só apresentação: cor, carimbo de hora e os prefixos ✓ / ⚠ / ✗. Se o terminal
# não tiver tput (ou com --no-color), as variáveis ficam vazias e os printf
# continuam válidos — nada de código ANSI cru no meio do log.
# `cmd()` existe por motivo didático: antes de cada ferramenta o script IMPRIME
# o comando que vai executar, para o aluno poder copiar, rodar na mão e mexer
# nas flags. O que aparece em ciano no terminal é exatamente o que rodou.
if [[ $NO_COLOR -eq 0 ]] && command -v tput >/dev/null 2>&1; then
  BLD=$(tput bold); DIM=$(tput dim); RST=$(tput sgr0)
  RED=$(tput setaf 1); GRN=$(tput setaf 2); YLW=$(tput setaf 3)
  BLU=$(tput setaf 4); CYA=$(tput setaf 6); GRA=$(tput setaf 8)
else
  BLD=""; DIM=""; RST=""; RED=""; GRN=""; YLW=""; BLU=""; CYA=""; GRA=""
fi
ts(){ date +'%H:%M:%S'; }
hr(){ printf "${GRA}%s${RST}\n" "────────────────────────────────────────────────────────"; }
section(){ hr; printf "${BLD}${BLU}[%s] %s${RST}\n" "$(ts)" "$*"; hr; }
note(){ printf "${DIM}%s${RST}\n" "$*"; }
ok(){ printf "${GRN}✓ %s${RST}\n" "$*"; }
warn(){ printf "${YLW}⚠ %s${RST}\n" "$*"; }
err(){ printf "${RED}✗ %s${RST}\n" "$*"; }
cmd(){ printf "${CYA}\$ %s${RST}\n" "$*"; }

# ---------- localizar binários ----------
# PROBLEMA: o script precisa chamar subfinder/httpx/naabu/tlsx/nuclei, mas não
# sabe onde eles estão. E NÃO PODE SABER: ele roda na máquina de cada aluno, com
# outro usuário, outro HOME e outro PATH. Escrever o caminho fixo aqui
# (/home/aluno/.pdtm/go/bin) seria bug — funcionaria só na máquina de quem
# escreveu. Por isso o caminho é DESCOBERTO em tempo de execução.
#
# O pdtm sabe onde instalou. `pdtm -sp -silent` imprime exatamente o caminho, uma linha,
# sem cor — essa é a fonte de verdade. Ordem de tentativa:
#
#   1. PD_BIN_DIR do ambiente   → escape hatch: o aluno manda na mão
#   2. pdtm -sp -silent         → quem instalou é quem sabe
#   3. $HOME/.pdtm/go/bin       → chute padrão, usando $HOME (nunca caminho fixo)
#   4. PATH                     → último recurso, via `command -v` no pick_bin()
#
# O caminho escolhido é IMPRESSO no bloco BINÁRIOS como PD_BIN_DIR=[...] logo
# abaixo. É a primeira coisa a conferir quando o script não acha ferramenta:
# se vier [<não detectado>] ou um diretório errado, o problema é instalação, não
# o script.
#
# ATENÇÃO (é a pegadinha nº 1 do laboratório): o pdtm instala no HOME de QUEM RODOU.
# Se você instalou com `sudo`, as ferramentas foram para /root/.pdtm/go/bin — e o seu
# usuário comum não enxerga nada lá, porque /root é drwx------ (só o root entra).
# O sintoma é cruel: o script aborta com
#     ✗ binário não encontrado: subfinder
# COM o subfinder instalado e funcionando. A mensagem diz "não encontrado" quando
# o problema é "não visível". É PERMISSÃO, não ausência — e nenhuma reinstalação
# com sudo vai resolver, porque sudo é justamente a causa.
# A correção é instalar com o seu próprio usuário:  pdtm -i subfinder,httpx,naabu,nuclei,tlsx -ip
# E conferir:  pdtm -sp -silent    # deve imprimir o SEU home, não /root

# Pergunta ao pdtm onde está o diretório de binários. `tr -d '[:space:]'` tira o
# \n e eventual espaço/CR, porque o valor vai ser concatenado em "$DIR/$nome".
# Retorna 1 (e string vazia) se o pdtm não estiver instalado.
detect_pdtm_bin(){
  command -v pdtm >/dev/null 2>&1 || return 1
  pdtm -sp -silent 2>/dev/null | tr -d '[:space:]'
}

# Passo 1 e 2: respeita PD_BIN_DIR se o aluno já exportou; senão pergunta ao pdtm.
# O `|| true` evita que o retorno 1 de detect_pdtm_bin derrube a atribuição.
[[ -z "${PD_BIN_DIR:-}" ]] && PD_BIN_DIR="$(detect_pdtm_bin || true)"
# Passo 3: fallback com $HOME — expandido na máquina de quem roda, não aqui.
[[ -z "${PD_BIN_DIR:-}" ]] && PD_BIN_DIR="$HOME/.pdtm/go/bin"

# devolve o caminho absoluto se existir e for executável; senão tenta o PATH; senão o nome cru
# Preferir PD_BIN_DIR ao PATH não é capricho: existem DOIS programas chamados
# httpx — o scanner do Project Discovery (Go) e uma biblioteca HTTP do PyPI
# (Python). Se a biblioteca estiver instalada no venv, o PATH pode entregar a
# errada e a saída não faz sentido nenhum. Confira com:
#     command -v httpx     # deve apontar para ~/.pdtm/go/bin/httpx
#     httpx -version       # o scanner se identifica: v1.x.x, projectdiscovery.io
# O último caso (devolver o nome cru) é de propósito: deixa o `command -v` da
# verificação abaixo falhar e dar a mensagem de erro boa, em vez de estourar aqui.
pick_bin(){
  local n="$1"
  if [[ -n "${PD_BIN_DIR:-}" && -x "${PD_BIN_DIR}/$n" ]]; then printf '%s\n' "${PD_BIN_DIR}/$n"; return 0; fi
  command -v "$n" 2>/dev/null && return 0
  printf '%s\n' "$n"
}
SUBFINDER_BIN="$(pick_bin subfinder)"
HTTPX_BIN="$(pick_bin httpx)"
NAABU_BIN="$(pick_bin naabu)"
TLSX_BIN="$(pick_bin tlsx)"
NUCLEI_BIN="$(pick_bin nuclei)"

# Bloco BINÁRIOS: diagnóstico. Imprime o diretório descoberto e o caminho de cada
# ferramenta ANTES de tocar na rede, e aborta se faltar qualquer coisa. Melhor
# falhar aqui, em um segundo, do que no meio de uma varredura de duas horas.
section "BINÁRIOS"
# ESTA É A LINHA A LER PRIMEIRO quando algo não acha ferramenta.
note "PD_BIN_DIR=[${PD_BIN_DIR:-<não detectado>}]"
note "subfinder=[$SUBFINDER_BIN] httpx=[$HTTPX_BIN] naabu=[$NAABU_BIN] tlsx=[$TLSX_BIN] nuclei=[$NUCLEI_BIN]"
# Confere ferramenta por ferramenta. NOTA: `bc` é usado no contador de progresso
# do tlsx (seção 5) mas NÃO está nesta lista — em sistema enxuto sem bc o scan
# roda, só o percentual de progresso sai quebrado.
for bin in "$SUBFINDER_BIN" "$HTTPX_BIN" "$NAABU_BIN" "$TLSX_BIN" "$NUCLEI_BIN" dig jq awk column tee; do
  command -v "$bin" >/dev/null 2>&1 || {
    err "binário não encontrado: $bin"
    err "procurei em PD_BIN_DIR=[${PD_BIN_DIR:-vazio}] e no PATH."
    err "conserte com:  pdtm -i subfinder,httpx,naabu,nuclei,tlsx -ip   (com o SEU usuário, sem sudo)"
    err "ou aponte na mão:  export PD_BIN_DIR=\$(pdtm -sp -silent)"
    exit 1
  }
done
# -s = existe E não está vazio. Sem isso o subfinder rodaria com lista vazia e o
# pipeline inteiro terminaria "com sucesso" e zero resultado — exatamente a
# confusão entre "zero achados" e "zero verificado".
[[ -s "$DOMS_FILE" ]] || { err "arquivo de domínios não existe ou está vazio: $DOMS_FILE"; exit 1; }

# ---------- 1) Subfinder ----------
# ETAPA PASSIVA. O subfinder não fala com o alvo: ele consulta fontes de
# terceiros que já catalogaram nomes DNS — certificate transparency, bases de DNS
# passivo, buscadores, VirusTotal, SecurityTrails, Shodan, GitHub. Quem recebe a
# requisição são esses provedores, não o domínio alvo.
#
# Flags:
#   -dL        lê a LISTA de domínios do arquivo (não um domínio só)
#   -all       usa todas as fontes, inclusive as lentas. Mais nomes, mais tempo.
#   -recursive reenumera a partir dos nomes achados (acha nível 3, 4…)
#   -silent    só os nomes na saída, sem banner — facilita o pipe
#   -o         grava no arquivo
#
# As chaves de API das fontes NÃO vêm do .env do projeto: o subfinder é escrito
# em Go e lê ~/.config/subfinder/provider-config.yaml. Sem chave ele funciona,
# só acha bem menos.
#
# ATENÇÃO ao volume: com -all -recursive e um domínio com WILDCARD DNS, a saída
# aqui chega facilmente a milhares de nomes, a maioria inexistente. Isso é
# NORMAL e é o motivo de existir a seção 3.1.
section "SUBFINDER – enumerando subdomínios"
cmd "\"$SUBFINDER_BIN\" -dL \"$DOMS_FILE\" -all -recursive -silent -o \"$SUBS_ALL\""
"$SUBFINDER_BIN" -dL "$DOMS_FILE" -all -recursive -silent -o "$SUBS_ALL"
COUNT_SUBS=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
ok "subdomínios: $(printf '%7d' "$COUNT_SUBS")"
# Amostra de 10 só para o aluno ver o formato. Número alto aqui NÃO é vitória:
# compare com a contagem do httpx na seção 3 para saber quanto disso é real.
head -n 10 "$SUBS_ALL" 2>/dev/null | sed "s/^/• /"

# ---------- 2) Resolver A e filtrar ----------
# AINDA PASSIVO para o alvo: a consulta vai para o resolver DNS, não para o
# servidor web do alvo (a zona pode até ser hospedada em terceiro).
#
# Por que resolver antes de escanear portas: o naabu trabalha em cima de IP.
# Vários nomes costumam apontar para o mesmo IP; resolver e deduplicar com
# `sort -u` evita varrer o mesmo servidor cinco vezes. Isso é menos tempo e
# menos barulho para o mesmo resultado.
#
# Dois filtros de loopback, e eles existem por um motivo prático: é comum a zona
# pública ter nomes apontando para 127.0.0.1 (resto de configuração, bloqueio de
# propósito). Escanear isso é escanear a SUA PRÓPRIA máquina e poluir o relatório
# com "serviços expostos" que são seus.
section "DNS – resolvendo A e filtrando loopback"
cmd "grep -viE '^localhost\\.' \"$SUBS_ALL\" > \"$SUBS_FILT\""
grep -viE '^localhost\.' "$SUBS_ALL" > "$SUBS_FILT" || true

# Resolve A record de cada nome. Um `dig` por host, em série — é a parte lenta
# desta seção em listas grandes.
# O grep depois do dig filtra a saída para só IPv4: `dig +short` também devolve
# a cadeia de CNAME, e CNAME aqui não serve (o naabu quer endereço).
# O `|| true` segura o grep sem match (nome que não resolve), que retorna 1.
# Lê de $SUBS_ALL (lista crua) e refaz o filtro de localhost na marra — daí a
# comparação case-insensitive letra por letra no [[ =~ ]].
: > "$IPS_TXT"
while IFS= read -r h; do
  [[ "$h" =~ ^[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt]\. ]] && continue
  dig +short A "$h" | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
done < "$SUBS_ALL" | sort -u > "$IPS_TXT"
# `sort -u` acima: deduplica. 1706 nomes podem virar 3 IPs — e é esse número que
# define quanto tempo o naabu vai levar.

cmd "grep -v '^127\\.0\\.0\\.1\$' \"$IPS_TXT\" > \"$IPS_FILT\""
grep -v '^127\.0\.0\.1$' "$IPS_TXT" > "$IPS_FILT" || true

ok "hosts filtrados: $(printf '%7d' "$(wc -l < "$SUBS_FILT" 2>/dev/null || echo 0)")"
ok "IPs únicos:      $(printf '%7d' "$(wc -l < "$IPS_FILT" 2>/dev/null || echo 0)")"

# ---------- 3) HTTPX ----------
# ######################  AQUI COMEÇA A ATIVIDADE ATIVA  ######################
#
# Desta seção em diante o script ABRE CONEXÃO COM O ALVO. O seu IP vai aparecer
# no log dele. Se você não tem autorização escrita para este domínio, pare agora
# (Ctrl-C) e troque o dominios.txt por vulnweb.com ou por um alvo seu.
#
# O PAPEL DO HTTPX É SER O FILTRO — é a etapa mais importante do script, e não
# por achar vulnerabilidade: por SEPARAR o que existe do que não existe.
# Ele faz uma requisição HTTP barata em cada nome e reporta só quem respondeu.
#
# Flags:
#   -l            lê a lista do arquivo
#   -status-code  traz o código HTTP (200, 301, 403…)
#   -title        traz o <title> da página — é o que dá para reconhecer painel
#                 de admin, página de login, erro de framework etc.
#   -p 80,443     só HTTP e HTTPS. Varredura de porta é trabalho do naabu.
#   -json         saída JSONL, um objeto por linha
#   -silent       sem banner
#
# AJUSTE AQUI (agressividade): o httpx aceita `-rl N` (requisições por segundo)
# e `-t N` (threads, padrão 50). Nenhum dos dois está sendo usado, então ele roda
# no padrão. Em alvo pequeno ou com WAF, acrescente `-rl 20 -t 10`.
section "HTTPX – 80/443 (jsonl)"
cmd "\"$HTTPX_BIN\" -l \"$SUBS_FILT\" -status-code -title -p 80,443 -json -silent > \"$HTTPX_JSON\""
"$HTTPX_BIN" -l "$SUBS_FILT" -status-code -title -p 80,443 -json -silent > "$HTTPX_JSON" || true
# Plano B: algumas combinações de versão/terminal fazem o httpx não produzir nada
# com `-l`. Alimentar pela entrada padrão resolve. Se a segunda tentativa também
# vier vazia, o problema é outro: PATH entregando o httpx errado (o do PyPI),
# saída de rede bloqueada, ou o alvo realmente não responde.
if [[ ! -s "$HTTPX_JSON" ]]; then
  warn "httpx (-l) sem saída; tentando via PIPE"
  cmd "cat \"$SUBS_FILT\" | \"$HTTPX_BIN\" -status-code -title -p 80,443 -json -silent > \"$HTTPX_JSON\""
  cat "$SUBS_FILT" | "$HTTPX_BIN" -status-code -title -p 80,443 -json -silent > "$HTTPX_JSON" || true
fi
H_LINES=$(wc -l < "$HTTPX_JSON" 2>/dev/null || echo 0)
# CONTAGEM-CHAVE DO SCRIPT. Zero aqui significa que nada do alvo foi alcançado, e
# então tlsx e nuclei também vão vir vazios — não porque está limpo, mas porque
# não foi verificado. Não conclua nada a partir de um relatório com httpx = 0.
ok "linhas httpx:     $(printf '%7d' "$H_LINES")"
[[ "$H_LINES" -gt 0 ]] && head -n 3 "$HTTPX_JSON" | sed "s/^/• /"

# ---------- 3.1) ALVOS VIVOS (filtrados pelo httpx) ----------
# ESTA SEÇÃO É A RAZÃO DA ORDEM DO PIPELINE. Leia com atenção.
#
# POR QUE SÓ SE ESCANEIA ATIVAMENTE O QUE O HTTPX DISSE ESTAR VIVO:
#
# Em dominios com wildcard DNS (*.dominio) o subfinder traz MILHARES de nomes-lixo.
# Wildcard quer dizer que QUALQUER nome resolve — inclusive nome que nunca
# existiu. O subfinder, que trabalha com fonte passiva, não tem como saber disso
# e devolve tudo. Escanear ativo (tlsx/nuclei) a lista crua afoga o pipeline (ex.: vulnweb.com = 1706
# nomes, 3 vivos). O httpx ja diz o que esta REALMENTE vivo -> e isso que o scan
# ativo usa. HOSTS_ALIVE = hostname unico; URLS_ALIVE = url completa (scheme+porta).
#
# O custo de ignorar isso tem três faces:
#   TEMPO    nuclei roda dezenas de templates por alvo. 1706 alvos em vez de 3
#            transforma minutos em horas — e 1703 deles não existem.
#   BARULHO  cada nome inexistente ainda gera tentativa de conexão. É volume de
#            tráfego gratuito contra o alvo, que o WAF vê e registra. Pode
#            resultar no seu IP bloqueado antes de você chegar no que importa.
#   RUÍDO    achado em host que não existe é falso positivo que vai parar no
#            relatório e custar o tempo de alguém para ser desmentido.
#
# A regra geral: FONTE PASSIVA DÁ CANDIDATO, VERIFICAÇÃO ATIVA DÁ FATO. Só o
# fato alimenta a etapa ativa seguinte. É por isso que o httpx vem ANTES do
# naabu/tlsx/nuclei e não depois.
HOSTS_ALIVE="$OUT/httpx/hosts_alive.txt"
URLS_ALIVE="$OUT/httpx/urls_alive.txt"
: > "$HOSTS_ALIVE"; : > "$URLS_ALIVE"
if [[ -s "$HTTPX_JSON" ]]; then
  # .url  = URL completa (https://host:443/) — é o que o nuclei consome.
  # .input ou .host = só o nome — é o que o tlsx consome (ele monta host:443).
  # `// .host` é o fallback do jq: versões do httpx mudam o nome desse campo.
  # `awk 'NF'` descarta linha vazia; `sort -u` deduplica.
  jq -r '.url'            "$HTTPX_JSON" 2>/dev/null | awk 'NF' | sort -u > "$URLS_ALIVE"  || true
  jq -r '.input // .host' "$HTTPX_JSON" 2>/dev/null | awk 'NF' | sort -u > "$HOSTS_ALIVE" || true
fi
ok "hosts vivos (httpx): $(printf '%7d' "$(wc -l < "$URLS_ALIVE" 2>/dev/null || echo 0)")  <- alvo do scan ativo"

# ---------- 4) Naabu ----------
# ETAPA ATIVA. Varredura de portas: manda pacote para 1000 portas de cada IP.
# É a etapa mais visível de todas para um IDS — varredura de portas é
# literalmente o padrão que todo sistema de detecção procura.
#
# Roda sobre os IPs DEDUPLICADOS da seção 2, não sobre nomes: cinco nomes no
# mesmo servidor = um scan, não cinco.
#
# Flags:
#   -list          arquivo com os alvos
#   -top-ports 1000 as 1000 portas mais comuns (ordem de frequência do nmap),
#                  não 1-1000. AJUSTE AQUI: `-top-ports 100` é bem mais rápido;
#                  `-p -` varre as 65535 e é escolha para janela longa e
#                  autorizada, não para aula.
#   -json -silent  JSONL sem banner
#
# AJUSTE AQUI (agressividade): o naabu aceita `-rate N` (pacotes por segundo,
# padrão 1000) e `-c N` (concorrência). Nenhum está definido aqui, ou seja: está
# no padrão, que é AGRESSIVO. Em alvo de produção use algo como
# `-rate 100 -c 10`. Isso é cortesia (não derrubar serviço de quem te autorizou)
# e é OPSEC (1000 pps é assinatura óbvia; 100 pps se perde no ruído de fundo).
#
# Privilégio: sem root o naabu não consegue SYN scan e cai sozinho para CONNECT
# scan — completa o handshake TCP. Funciona, é mais lento e deixa registro de
# conexão completa no alvo, não só um SYN.
section "NAABU – top-ports 1000"
# Caminho normal: IPs. Se a resolução não produziu IP nenhum (DNS bloqueado, zona
# só com AAAA/CNAME), tenta os nomes direto — menos eficiente, mas melhor que
# pular a etapa calado.
if [[ -s "$IPS_FILT" ]]; then
  cmd "\"$NAABU_BIN\" -list \"$IPS_FILT\" -top-ports 1000 -json -silent > \"$NAABU_JSON\""
  "$NAABU_BIN" -list "$IPS_FILT" -top-ports 1000 -json -silent > "$NAABU_JSON"
else
  warn "sem IPs filtrados; tentando DOMÍNIOS diretamente"
  cmd "\"$NAABU_BIN\" -list \"$SUBS_FILT\" -top-ports 1000 -json -silent > \"$NAABU_JSON\""
  "$NAABU_BIN" -list "$SUBS_FILT" -top-ports 1000 -json -silent > "$NAABU_JSON" || true
fi
N_LINES=$(wc -l < "$NAABU_JSON" 2>/dev/null || echo 0)
ok "linhas naabu:     $(printf '%7d' "$N_LINES")"
[[ "$N_LINES" -gt 0 ]] && head -n 3 "$NAABU_JSON" | sed "s/^/• /"

# ---------- 5) TLSX (host:443/domínios + ip:443/naabu + https/httpx) ----------
# ETAPA ATIVA, mas de custo baixo: o tlsx só faz o handshake TLS e lê o
# certificado que o servidor apresenta. Uma conexão por alvo, nenhum payload.
#
# POR QUE ISSO IMPORTA NA ANÁLISE: o certificado é um documento que o próprio
# alvo entrega, assinado, e o campo SAN (Subject Alternative Name) lista TODOS os
# nomes para os quais aquele certificado vale. Um certificado de wildcard ou
# multi-domínio frequentemente revela nomes internos que nenhuma fonte passiva
# tinha — vpn, homologacao, api-interna. É a etapa que mais costuma devolver
# subdomínio novo, e por isso vale realimentar o subfinder com o que sai daqui.
# Além disso: validade (certificado vencido), emissor e algoritmo são achados por
# si sós.
#
# Os alvos são montados de TRÊS fontes, unidas e deduplicadas em 5.4:
#   5.1  hosts VIVOS do httpx       → host:443
#   5.2  IPs com 443 aberto no naabu → ip:443
#   5.3  hosts https do httpx        → host:443
# A sobreposição é grande e proposital: o `sort -u` resolve. O importante é que
# NENHUMA delas é a lista crua do subfinder.
section "TLSX – SAN e certs"

# Redefine variáveis para garantir paths corretos
# (reatribuição herdada de versão anterior do script — ver o comentário no bloco
# de paths no topo. As definições que valem para o tlsx são estas.)
TLSX_HOSTS_RAW="$OUT/tmp/tlsx_hosts_dom.txt"
TLSX_IPS443="$OUT/tmp/tlsx_ip_endpoints.txt"
TLSX_HTTPS_HOSTS="$OUT/tmp/tlsx_hosts_from_httpx.txt"
TLSX_TARGETS="$OUT/tmp/tlsx_targets.txt"

TLSX_SAN_JSON="$OUT/tlsx/san.jsonl"
TLSX_CERTS_JSON="$OUT/tlsx/certs.jsonl"
TLSX_SAN_TXT="$OUT/tlsx/san.txt"
TLSX_CERTS_TXT="$OUT/tlsx/certs.txt"

# 5.1: hosts VIVOS -> :443 (nao a lista crua do subfinder; ver HOSTS_ALIVE)
# O tlsx quer "host:porta". IGNORECASE=1 pega Localhost/LOCALHOST também.
awk 'BEGIN{IGNORECASE=1} !/^localhost\./ {print $0":443"}' "$HOSTS_ALIVE" | sort -u > "$TLSX_HOSTS_RAW"

# 5.2: ip:443 do naabu
# Aproveita o que o naabu já descobriu: só os IPs com 443 realmente aberto.
# Pegar o certificado por IP (e não por nome) às vezes entrega o certificado
# "default" do servidor, que pode pertencer a outro site hospedado ali.
: > "$TLSX_IPS443"
if [[ -s "$NAABU_JSON" ]]; then
  jq -r 'select(.port==443) | .ip' "$NAABU_JSON" 2>/dev/null \
  | grep -E '^[0-9]+(\.[0-9]+){3}$' | awk '{print $1":443"}' | sort -u > "$TLSX_IPS443" || true
fi

# 5.3: hosts https do httpx -> host:443
# Extrai o host da URL com awk -F/ (campo 3 de "https://host:porta/") e tira a
# porta com sed, para recolocar :443 de forma uniforme.
: > "$TLSX_HTTPS_HOSTS"
if [[ -s "$HTTPX_JSON" ]]; then
  jq -r 'select(.scheme=="https") | .url' "$HTTPX_JSON" 2>/dev/null \
  | awk -F/ 'NF>=3 {print $3}' | sed 's/:.*$//' \
  | grep -viE '^localhost$' \
  | awk '{print $0":443"}' | sort -u > "$TLSX_HTTPS_HOSTS" || true
fi

# 5.4: união final (sem 127.0.0.1:443)
# `sort -u` é o que torna seguro juntar as três fontes sobrepostas: o mesmo
# host:443 aparecendo nas três vira UMA conexão, não três.
cat "$TLSX_HOSTS_RAW" "$TLSX_IPS443" "$TLSX_HTTPS_HOSTS" 2>/dev/null \
  | awk 'NF' | sort -u | grep -vE '^127\.0\.0\.1:443$' > "$TLSX_TARGETS"

T_TOTAL=$(wc -l < "$TLSX_TARGETS" 2>/dev/null || echo 0)
ok "alvos tlsx: $T_TOTAL"
[[ "$T_TOTAL" -gt 0 ]] && head -n 10 "$TLSX_TARGETS" | sed "s/^/• /"

# 5.5: executar tlsx - VERSÃO CORRIGIDA COM MÚLTIPLAS ESTRATÉGIAS
# Zera os quatro arquivos antes de começar: eles são preenchidos com >> (append)
# no laço abaixo, então sem truncar aqui uma segunda execução empilharia em cima
# do resultado da primeira.
: > "$TLSX_SAN_JSON"; : > "$TLSX_CERTS_JSON"
: > "$TLSX_SAN_TXT"; : > "$TLSX_CERTS_TXT"

if [[ "$T_TOTAL" -gt 0 ]]; then
  # Sanitiza alvos (remove CR, vazias, dup, e 127.0.0.1:443)
  # O \r é o caso do dominios.txt editado no Windows: sem isso o alvo viraria
  # "host:443\r" e TODA conexão falharia, com o arquivo parecendo correto na tela.
  TLSX_TARGETS_CLEAN="$OUT/tmp/tlsx_targets.clean.txt"
  awk '{sub(/\r$/,"")} NF && $0!="127.0.0.1:443"{print}' "$TLSX_TARGETS" \
    | sort -u > "$TLSX_TARGETS_CLEAN"

  section "TLSX – executando"
  
  # Debug: mostra primeiros alvos
  note "Total de alvos: $(wc -l < "$TLSX_TARGETS_CLEAN")"
  note "Primeiros 5 alvos:"
  head -5 "$TLSX_TARGETS_CLEAN" | sed "s/^/  • /"
  
  # SOLUÇÃO: Usar pipe em vez de -l para evitar problemas de buffering
  # e remover -silent que pode estar suprimindo output

  # TLSX: Usando estratégia que funciona (loop linha por linha com paralelização)
  #
  # LEIA ISTO antes de usar em alvo grande: o laço abaixo é SERIAL (um alvo por
  # vez) e chama o tlsx DUAS VEZES por alvo — uma para JSON e uma para texto.
  # Ou seja: 2 handshakes TLS por alvo e nenhum paralelismo, apesar do que diz o
  # comentário acima. Em 3 alvos não se nota; em 300, isso é o gargalo do script
  # inteiro. O tlsx nativamente aceita `-l arquivo` e tem `-c N` de concorrência.
  # Flags usadas em cada chamada:
  #   -san              extrai os Subject Alternative Names (só no laço de SAN)
  #   -timeout 10       AJUSTE AQUI: 10s por alvo. Alvo lento multiplica isso
  #                     pelo número de alvos — é o que faz a etapa "travar".
  #   -retry 2          repete 2x antes de desistir
  #   -nc               sem cor (o resumo da seção 7 ainda limpa ANSI por garantia)
  #   -r 1.1.1.1,8.8.8.8 resolvers fixos, para não depender do DNS da máquina do
  #                     aluno. Cuidado: isso manda os nomes do alvo para
  #                     Cloudflare e Google — em trabalho com sigilo de cliente,
  #                     troque por um resolver que você controla.
  #   -j                saída JSON (só na primeira chamada de cada par)
  note "Executando tlsx (processamento linha por linha)..."
  
  # Processa SAN
  : > "$TLSX_SAN_JSON"
  : > "$TLSX_SAN_TXT"
  
  note "Processando SAN para $(wc -l < "$TLSX_TARGETS_CLEAN") alvos..."
  
  # Versão com progresso
  total_lines=$(wc -l < "$TLSX_TARGETS_CLEAN")
  current=0

  # LAÇO 1 de 2: SAN. Grava o mesmo resultado em dois formatos — .jsonl (o que
  # vai para o Elasticsearch) e .txt (o que alimenta o resumo da seção 7).
  while IFS= read -r target; do
    # JSON
    echo "$target" | "$TLSX_BIN" -san -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 -j 2>/dev/null >> "$TLSX_SAN_JSON"
    # TEXT
    echo "$target" | "$TLSX_BIN" -san -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 2>/dev/null >> "$TLSX_SAN_TXT"

    current=$((current + 1))
    # Mostra progresso a cada 10 alvos
    # NOTA: o cálculo do percentual usa `bc`, que não é verificado no bloco
    # BINÁRIOS. Sem bc instalado, só o indicador de progresso sai torto — o scan
    # e os arquivos de saída continuam corretos.
    if [[ $((current % 10)) -eq 0 ]]; then
      printf "\r  Progresso SAN: %d/%d (%.0f%%)" "$current" "$total_lines" "$(echo "scale=2; $current * 100 / $total_lines" | bc)"
    fi
  done < "$TLSX_TARGETS_CLEAN"
  printf "\n"
  ok "SAN processado: $current alvos"
  
  # Processa CERTS
  : > "$TLSX_CERTS_JSON"
  : > "$TLSX_CERTS_TXT"
  
  note "Processando certificados..."
  current=0

  # LAÇO 2 de 2: certificado completo. Mesma lista, mesmas flags, só SEM `-san`:
  # agora o tlsx devolve emissor, CN, validade e algoritmo em vez da lista de
  # nomes. São mais 2 handshakes por alvo (4 no total por alvo, somando o laço
  # anterior) — conte isso no seu orçamento de barulho.
  while IFS= read -r target; do
    # JSON
    echo "$target" | "$TLSX_BIN" -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 -j 2>/dev/null >> "$TLSX_CERTS_JSON"
    # TEXT
    echo "$target" | "$TLSX_BIN" -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 2>/dev/null >> "$TLSX_CERTS_TXT"
    
    current=$((current + 1))
    # Mostra progresso a cada 10 alvos
    if [[ $((current % 10)) -eq 0 ]]; then
      printf "\r  Progresso CERTS: %d/%d (%.0f%%)" "$current" "$total_lines" "$(echo "scale=2; $current * 100 / $total_lines" | bc)"
    fi
  done < "$TLSX_TARGETS_CLEAN"
  printf "\n"
  ok "CERTS processado: $current alvos"

  # Aguarda um momento para garantir que arquivos sejam escritos
  sleep 1

  # contagens finais
  # `jq -rc .` conta objetos JSON VÁLIDOS, não linhas: se o tlsx tiver cuspido
  # algo malformado, a contagem JSON fica menor que a de texto. Divergência
  # grande entre os dois pares de números é sinal de saída corrompida.
  SAN_COUNT=$(jq -rc . "$TLSX_SAN_JSON" 2>/dev/null | wc -l | tr -d ' ')
  CERTS_COUNT=$(jq -rc . "$TLSX_CERTS_JSON" 2>/dev/null | wc -l | tr -d ' ')
  SAN_TXT_COUNT=$(wc -l < "$TLSX_SAN_TXT" 2>/dev/null | tr -d ' ')
  CERTS_TXT_COUNT=$(wc -l < "$TLSX_CERTS_TXT" 2>/dev/null | tr -d ' ')
  
  ok "SAN JSON linhas:  $(printf '%7d' "${SAN_COUNT:-0}")"
  ok "SAN TXT linhas:   $(printf '%7d' "${SAN_TXT_COUNT:-0}")"
  ok "CERTS JSON linhas:$(printf '%7d' "${CERTS_COUNT:-0}")"
  ok "CERTS TXT linhas: $(printf '%7d' "${CERTS_TXT_COUNT:-0}")"
  
  # Mostra preview se houver resultados
  if [[ "${SAN_COUNT:-0}" -gt 0 ]]; then
    note "Preview SAN (primeiros 3):"
    jq -r '.subject_cn + " -> " + (.subject_an | join(","))' "$TLSX_SAN_JSON" 2>/dev/null | head -3 | sed "s/^/  • /"
  fi
else
  # "Nenhum alvo elegível" quase sempre quer dizer httpx vazio, não alvo sem TLS.
  warn "TLSX: nenhum alvo elegível."
fi

# ---------- 6) Nuclei ----------
# ETAPA ATIVA, e a de maior impacto: o nuclei roda milhares de templates (a
# comunidade mantém o acervo) contra cada URL.
#
# O QUE O NUCLEI FAZ E O QUE NÃO FAZ:
#   O nuclei IDENTIFICA ASSINATURA. NÃO EXPLORA.
# Ele manda uma requisição e compara a resposta com um padrão conhecido: versão
# de software no header, arquivo de configuração acessível, página de login
# padrão, erro característico. Um achado é "esta resposta PARECE com um caso
# conhecido" — é indício, não exploração e nem prova. Confirmar o impacto é
# trabalho humano, e confirmar exige autorização própria (quem autorizou um scan
# não autorizou necessariamente uma exploração).
# Consequência prática: achado do nuclei não vai para relatório sem validação.
# Ele aponta onde olhar; não diz que está explorado.
#
# Flags:
#   -l $URLS_ALIVE  SÓ URLs vivas (seção 3.1). Nunca a lista crua.
#   -jsonl          um achado por linha
#   -silent         sem banner
#   -rl 50          AJUSTE AQUI: 50 requisições por segundo
#   -c 20           AJUSTE AQUI: 20 templates em paralelo
#   -ni             sem interactsh — não usa o servidor público de callback da
#                   Project Discovery. Importante: com interactsh, dados do SEU
#                   alvo (hostname, DNS de saída) transitam por infraestrutura de
#                   terceiro. Desligado, você perde a detecção de alguns casos
#                   cegos (SSRF/RCE out-of-band) e ganha confidencialidade.
#   -o              arquivo de saída
#
# POR QUE AJUSTAR -rl E -c É CORTESIA E TAMBÉM OPSEC:
#   CORTESIA  você está mandando tráfego para um serviço de produção de alguém
#             que te deu permissão. 50 rps com 20 templates em paralelo derruba
#             aplicação pequena, e derrubar o alvo encerra o teste — e a
#             confiança. Combine a taxa com quem autorizou.
#   OPSEC     volume é assinatura. Rajada de centenas de requisições em segundos
#             é o padrão que o WAF existe para bloquear. Taxa mais baixa
#             (`-rl 10 -c 5`) leva mais tempo e tem muito mais chance de
#             completar sem ser cortada no meio — e scan cortado no meio devolve
#             relatório parcial que parece completo.
section "NUCLEI – varredura básica (rate-limit)"
if [[ -s "$URLS_ALIVE" ]]; then
  cmd "\"$NUCLEI_BIN\" -l \"$URLS_ALIVE\" -jsonl -silent -rl 50 -c 20 -ni -o \"$NUCLEI_JSONL\""
  "$NUCLEI_BIN" -l "$URLS_ALIVE" -jsonl -silent -rl 50 -c 20 -ni -o "$NUCLEI_JSONL" || true
else
  # Pula explicitamente em vez de rodar contra lista vazia: deixa claro no log
  # que o nuclei NÃO foi executado, em vez de produzir um arquivo vazio que
  # depois alguém leria como "nada encontrado".
  warn "nenhum host vivo (httpx) — nuclei pulado"
  : > "$NUCLEI_JSONL"
fi
NUC_LINES=$(wc -l < "$NUCLEI_JSONL" 2>/dev/null || echo 0)
# ===== SE ISTO VIER 0, NÃO CONCLUA "ALVO LIMPO" =====
# Zero achado tem três explicações possíveis, e o número não distingue entre elas:
#   1. o alvo realmente não casou com nenhum template;
#   2. um WAF/CDN está respondendo no lugar do alvo e bloqueou tudo (típico:
#      muitos 403 no httpx, ou o scan terminar rápido demais);
#   3. o alvo CAIU no meio do caminho — inclusive derrubado pelo próprio scan.
# "Zero achados" e "zero verificado" são a MESMA saída e coisas OPOSTAS.
# Como distinguir: confira que o httpx achou hosts vivos, e depois do scan
# confirme na mão que o alvo ainda responde (`curl -I https://alvo/`). Se o alvo
# não responde mais, o relatório inteiro é inválido, não limpo.
ok "linhas nuclei:    $(printf '%7d' "$NUC_LINES")"
[[ "$NUC_LINES" -gt 0 ]] && head -n 2 "$NUCLEI_JSONL" | sed "s/^/• /"

# ---------- 7) RESUMO ----------
# Só leitura dos arquivos já gravados — nenhuma conexão nova com o alvo daqui
# para baixo. É uma visão de 30 segundos para decidir onde olhar; a análise de
# verdade é feita nos JSONL (ou no Kibana, depois da seção 8).
section "RESUMO"

# LC_ALL=C: força ordenação por byte. Sem isso, `sort | uniq -c` se comporta
# diferente em cada locale e as contagens mudam de uma máquina para outra.
export LC_ALL=C LANG=C

# Agrupa por (status_code, title) e mostra as 8 combinações mais frequentes.
# O que procurar: title repetido centenas de vezes = página padrão de hospedagem
# ou de WAF (pouco interessante); title único = aplicação própria (é onde está o
# achado). 403/401 em massa costuma ser WAF; 200 com title de painel é prioridade.
printf "${BLD}HTTPX – status/title (top 8)${RST}\n"
if [[ -s "$HTTPX_JSON" ]]; then
  {
    printf "COUNT\tCODE\tTITLE\n"
    jq -r '[.status_code, (.title // "")] | @tsv' "$HTTPX_JSON" \
      | awk -F'\t' '{sc=$1; ttl=$2; if(length(ttl)>40) ttl=substr(ttl,1,37)"..."; print sc"\t"ttl}' \
      | sort | uniq -c | sort -nr | head -8 \
      | awk '{printf "%s\t%s\t",$1,$2; for (i=3;i<=NF;i++) printf (i==NF?$i:$i" "); print ""}'
  } | column -t -s $'\t'
else
  note "(sem dados)"
fi
echo

# Portas mais vistas. O que procurar: além de 80/443, qualquer coisa
# administrativa exposta — 22, 3306, 5432, 6379, 9200, 3389. Banco de dados ou
# Elasticsearch aberto para a internet é achado de severidade alta por si só.
printf "${BLD}NAABU – top portas (top 8)${RST}\n"
if [[ -s "$NAABU_JSON" ]]; then
  {
    printf "COUNT\tPORT\n"
    jq -r '.port' "$NAABU_JSON" \
      | sort -n | uniq -c | sort -nr | head -8 \
      | awk '{printf "%s\t%s\n",$1,$2}'
  } | column -t -s $'\t'
else
  note "(sem dados)"
fi
echo

# host → nomes do certificado. É AQUI que aparece subdomínio que nenhuma fonte
# passiva tinha. Nome novo nesta coluna volta para o dominios.txt (com o mesmo
# critério de autorização) e o ciclo recomeça — coleta é iterativa, não linear.
printf "${BLD}TLSX – SAN (host → SAN)${RST}\n"
if [[ -s "$TLSX_SAN_TXT" ]]; then
  {
    printf "HOST\tSAN\n"
    # remove ANSI e formata linhas do tipo: host:443 (IP) [SAN]
    sed -E 's/\x1B\[[0-9;]*m//g' "$TLSX_SAN_TXT" \
      | awk -F'[][]' 'NF>=2 {h=$1; gsub(/[[:space:]]+$/,"",h); gsub(/:443$/,"",h); san=$2; print h"\t"san}'
  } | column -t -s $'\t' | head -12
elif [[ -s "$TLSX_SAN_JSON" ]]; then
  # Fallback: tenta extrair do JSON
  {
    printf "HOST\tSAN\n"
    jq -r '[.host, (.subject_an | join(","))] | @tsv' "$TLSX_SAN_JSON" 2>/dev/null | head -12
  } | column -t -s $'\t'
else
  note "(sem dados)"
fi
echo

# Contagem por severidade. Lembre que a severidade é do TEMPLATE, atribuída por
# quem o escreveu sem conhecer o seu contexto: "high" em sistema de teste pode
# não ser nada, e "info" que revela versão exata de software pode ser o começo da
# cadeia que importa. A severidade ordena a fila de análise; não é o veredito.
printf "${BLD}NUCLEI – severidade (top)${RST}\n"
if [[ -s "$NUCLEI_JSONL" ]]; then
  {
    printf "COUNT\tSEVERITY\n"
    jq -r '.info.severity // "unknown"' "$NUCLEI_JSONL" \
      | tr '[:upper:]' '[:lower:]' \
      | sort | uniq -c | sort -nr \
      | awk '{printf "%s\t%s\n",$1,$2}'
  } | column -t -s $'\t'
else
  note "(sem dados)"
fi
echo

ok "Saídas em: $OUT"

# ---------- 8) ELK – copiar JSONs para indexação ----------
# Junta num único diretório plano ($OUT/elk) tudo o que vai ser indexado no
# Elasticsearch, para a etapa ARMAZENAR do pipeline não precisar conhecer a
# estrutura de pastas do coletor. Copia, não move: os originais ficam onde estão.
# O "vazio/ausente" aqui é informação, não falha: diz qual etapa não produziu
# dado — e é a pista de onde o pipeline parou.
section "ELK – copiando saídas"
mkdir -p "$ELK_DIR"
copy_or_warn(){
  local src="$1" dst="$2"
  if [[ -s "$src" ]]; then
    cp "$src" "$dst" && ok "copiado: $(basename "$dst")" || warn "falha ao copiar: $src"
  else
    warn "vazio/ausente: $(basename "$dst")"
  fi
}
copy_or_warn "$HTTPX_JSON"      "$ELK_DIR/httpx.jsonl"
copy_or_warn "$NAABU_JSON"      "$ELK_DIR/naabu.json"
copy_or_warn "$TLSX_CERTS_JSON" "$ELK_DIR/certs.jsonl"
copy_or_warn "$TLSX_SAN_JSON"   "$ELK_DIR/san.jsonl"
copy_or_warn "$TLSX_CERTS_TXT"  "$ELK_DIR/certs.txt"
copy_or_warn "$TLSX_SAN_TXT"    "$ELK_DIR/san.txt"
copy_or_warn "$NUCLEI_JSONL"    "$ELK_DIR/nuclei.jsonl"