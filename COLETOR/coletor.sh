#!/usr/bin/env bash
# coletor.sh – subfinder → httpx → naabu → tlsx → nuclei
# deps: subfinder httpx naabu tlsx nuclei dig jq awk column tee

set -u

NO_COLOR=0
if [[ "${1:-}" == "--no-color" ]]; then NO_COLOR=1; shift; fi

DOMS_FILE="${1:-dominios.txt}"
OUT="${OUT_DIR:-out}"

# --- paths de saída
SUBS_ALL="$OUT/subfinder/subdomains_all.txt"
SUBS_FILT="$OUT/subfinder/subdomains_filtered.txt"

HTTPX_JSON="$OUT/httpx/httpx.jsonl"

IPS_TXT="$OUT/tmp/ips.txt"
IPS_FILT="$OUT/tmp/ips_filtered.txt"

NAABU_JSON="$OUT/naabu/naabu.json"

TLSX_HOSTS_RAW="$OUT/tmp/tlsx_hosts_raw.txt"
TLSX_IPS443="$OUT/tmp/tlsx_ip_endpoints.txt"
TLSX_HTTPS_HOSTS="$OUT/tmp/tlsx_hosts_from_httpx.txt"
TLSX_TARGETS="$OUT/tmp/tlsx_targets.txt"
TLSX_TARGETS_DOM="$OUT/tmp/tlsx_targets_dom.txt"
TLSX_TARGETS_IPS="$OUT/tmp/tlsx_targets_ip.txt"
TLSX_TARGETS_HTTPS="$OUT/tmp/tlsx_targets_https.txt"

TLSX_SAN_TXT="$OUT/tlsx/san.txt"
TLSX_CERTS_TXT="$OUT/tlsx/certs.txt"

NUCLEI_JSONL="$OUT/nuclei/nuclei.jsonl"

ELK_DIR="$OUT/elk"

mkdir -p "$OUT"/{subfinder,httpx,naabu,tlsx,nuclei,tmp,elk}

# ---------- UI helpers ----------
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

# ---------- localizar binários (pdtm → PATH) ----------
detect_pdtm_bin(){
  command -v pdtm >/dev/null 2>&1 || return 1
  pdtm 2>/dev/null | awk -F': ' '/Path to download project binary/{print $2;exit}'
}
PD_BIN_DIR="$(detect_pdtm_bin || true)"
[[ -z "${PD_BIN_DIR:-}" ]] && PD_BIN_DIR="$HOME/.pdtm/go/bin"

SUBFINDER_BIN="${PD_BIN_DIR}/subfinder"; command -v "$SUBFINDER_BIN" >/dev/null 2>&1 || SUBFINDER_BIN="subfinder"
HTTPX_BIN="${PD_BIN_DIR}/httpx";       command -v "$HTTPX_BIN"       >/dev/null 2>&1 || HTTPX_BIN="httpx"
NAABU_BIN="${PD_BIN_DIR}/naabu";       command -v "$NAABU_BIN"       >/dev/null 2>&1 || NAABU_BIN="naabu"
TLSX_BIN="${PD_BIN_DIR}/tlsx";         command -v "$TLSX_BIN"        >/dev/null 2>&1 || TLSX_BIN="tlsx"
NUCLEI_BIN="${PD_BIN_DIR}/nuclei";     command -v "$NUCLEI_BIN"      >/dev/null 2>&1 || NUCLEI_BIN="nuclei"

section "BINÁRIOS"
note "subfinder=[$SUBFINDER_BIN] httpx=[$HTTPX_BIN] naabu=[$NAABU_BIN] tlsx=[$TLSX_BIN] nuclei=[$NUCLEI_BIN]"
for bin in "$SUBFINDER_BIN" "$HTTPX_BIN" "$NAABU_BIN" "$TLSX_BIN" "$NUCLEI_BIN" dig jq awk column tee; do
  command -v "$bin" >/dev/null 2>&1 || { err "binário não encontrado: $bin"; exit 1; }
done
[[ -s "$DOMS_FILE" ]] || { err "arquivo de domínios não existe ou está vazio: $DOMS_FILE"; exit 1; }

# ---------- 1) Subfinder ----------
section "SUBFINDER – enumerando subdomínios"
cmd "\"$SUBFINDER_BIN\" -dL \"$DOMS_FILE\" -all -recursive -silent -o \"$SUBS_ALL\""
"$SUBFINDER_BIN" -dL "$DOMS_FILE" -all -recursive -silent -o "$SUBS_ALL"
COUNT_SUBS=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
ok "subdomínios: $(printf '%7d' "$COUNT_SUBS")"
head -n 10 "$SUBS_ALL" 2>/dev/null | sed "s/^/• /"

# ---------- 2) Resolver A e filtrar ----------
section "DNS – resolvendo A e filtrando loopback"
cmd "grep -viE '^localhost\\.' \"$SUBS_ALL\" > \"$SUBS_FILT\""
grep -viE '^localhost\.' "$SUBS_ALL" > "$SUBS_FILT" || true

: > "$IPS_TXT"
while IFS= read -r h; do
  [[ "$h" =~ ^[Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt]\. ]] && continue
  dig +short A "$h" | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
done < "$SUBS_ALL" | sort -u > "$IPS_TXT"

cmd "grep -v '^127\\.0\\.0\\.1\$' \"$IPS_TXT\" > \"$IPS_FILT\""
grep -v '^127\.0\.0\.1$' "$IPS_TXT" > "$IPS_FILT" || true

ok "hosts filtrados: $(printf '%7d' "$(wc -l < "$SUBS_FILT" 2>/dev/null || echo 0)")"
ok "IPs únicos:      $(printf '%7d' "$(wc -l < "$IPS_FILT" 2>/dev/null || echo 0)")"

# ---------- 3) HTTPX ----------
section "HTTPX – 80/443 (jsonl)"
cmd "\"$HTTPX_BIN\" -l \"$SUBS_FILT\" -status-code -title -p 80,443 -json -silent > \"$HTTPX_JSON\""
"$HTTPX_BIN" -l "$SUBS_FILT" -status-code -title -p 80,443 -json -silent > "$HTTPX_JSON" || true
if [[ ! -s "$HTTPX_JSON" ]]; then
  warn "httpx (-l) sem saída; tentando via PIPE"
  cmd "cat \"$SUBS_FILT\" | \"$HTTPX_BIN\" -status-code -title -p 80,443 -json -silent > \"$HTTPX_JSON\""
  cat "$SUBS_FILT" | "$HTTPX_BIN" -status-code -title -p 80,443 -json -silent > "$HTTPX_JSON" || true
fi
H_LINES=$(wc -l < "$HTTPX_JSON" 2>/dev/null || echo 0)
ok "linhas httpx:     $(printf '%7d' "$H_LINES")"
[[ "$H_LINES" -gt 0 ]] && head -n 3 "$HTTPX_JSON" | sed "s/^/• /"

# ---------- 4) Naabu ----------
section "NAABU – top-ports 1000"
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
section "TLSX – SAN e certs"

# Redefine variáveis para garantir paths corretos
TLSX_HOSTS_RAW="$OUT/tmp/tlsx_hosts_dom.txt"
TLSX_IPS443="$OUT/tmp/tlsx_ip_endpoints.txt"
TLSX_HTTPS_HOSTS="$OUT/tmp/tlsx_hosts_from_httpx.txt"
TLSX_TARGETS="$OUT/tmp/tlsx_targets.txt"

TLSX_SAN_JSON="$OUT/tlsx/san.jsonl"
TLSX_CERTS_JSON="$OUT/tlsx/certs.jsonl"
TLSX_SAN_TXT="$OUT/tlsx/san.txt"
TLSX_CERTS_TXT="$OUT/tlsx/certs.txt"

# 5.1: domínios -> :443 (ignora localhost)
awk 'BEGIN{IGNORECASE=1} !/^localhost\./ {print $0":443"}' "$SUBS_FILT" | sort -u > "$TLSX_HOSTS_RAW"

# 5.2: ip:443 do naabu
: > "$TLSX_IPS443"
if [[ -s "$NAABU_JSON" ]]; then
  jq -r 'select(.port==443) | .ip' "$NAABU_JSON" 2>/dev/null \
  | grep -E '^[0-9]+(\.[0-9]+){3}$' | awk '{print $1":443"}' | sort -u > "$TLSX_IPS443" || true
fi

# 5.3: hosts https do httpx -> host:443
: > "$TLSX_HTTPS_HOSTS"
if [[ -s "$HTTPX_JSON" ]]; then
  jq -r 'select(.scheme=="https") | .url' "$HTTPX_JSON" 2>/dev/null \
  | awk -F/ 'NF>=3 {print $3}' | sed 's/:.*$//' \
  | grep -viE '^localhost$' \
  | awk '{print $0":443"}' | sort -u > "$TLSX_HTTPS_HOSTS" || true
fi

# 5.4: união final (sem 127.0.0.1:443)
cat "$TLSX_HOSTS_RAW" "$TLSX_IPS443" "$TLSX_HTTPS_HOSTS" 2>/dev/null \
  | awk 'NF' | sort -u | grep -vE '^127\.0\.0\.1:443$' > "$TLSX_TARGETS"

T_TOTAL=$(wc -l < "$TLSX_TARGETS" 2>/dev/null || echo 0)
ok "alvos tlsx: $T_TOTAL"
[[ "$T_TOTAL" -gt 0 ]] && head -n 10 "$TLSX_TARGETS" | sed "s/^/• /"

# 5.5: executar tlsx - VERSÃO CORRIGIDA COM MÚLTIPLAS ESTRATÉGIAS
: > "$TLSX_SAN_JSON"; : > "$TLSX_CERTS_JSON"
: > "$TLSX_SAN_TXT"; : > "$TLSX_CERTS_TXT"

if [[ "$T_TOTAL" -gt 0 ]]; then
  # Sanitiza alvos (remove CR, vazias, dup, e 127.0.0.1:443)
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
  note "Executando tlsx (processamento linha por linha)..."
  
  # Processa SAN
  : > "$TLSX_SAN_JSON"
  : > "$TLSX_SAN_TXT"
  
  note "Processando SAN para $(wc -l < "$TLSX_TARGETS_CLEAN") alvos..."
  
  # Versão com progresso
  total_lines=$(wc -l < "$TLSX_TARGETS_CLEAN")
  current=0
  
  while IFS= read -r target; do
    # JSON
    echo "$target" | "$TLSX_BIN" -san -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 -j 2>/dev/null >> "$TLSX_SAN_JSON"
    # TEXT
    echo "$target" | "$TLSX_BIN" -san -timeout 10 -retry 2 -nc -r 1.1.1.1,8.8.8.8 2>/dev/null >> "$TLSX_SAN_TXT"
    
    current=$((current + 1))
    # Mostra progresso a cada 10 alvos
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
  warn "TLSX: nenhum alvo elegível."
fi

# ---------- 6) Nuclei ----------
section "NUCLEI – varredura básica (rate-limit)"
if [[ -s "$SUBS_FILT" ]]; then
  cmd "\"$NUCLEI_BIN\" -l \"$SUBS_FILT\" -jsonl -silent -rl 50 -c 20 -ni -o \"$NUCLEI_JSONL\""
  "$NUCLEI_BIN" -l "$SUBS_FILT" -jsonl -silent -rl 50 -c 20 -ni -o "$NUCLEI_JSONL" || true
else
  : > "$NUCLEI_JSONL"
fi
NUC_LINES=$(wc -l < "$NUCLEI_JSONL" 2>/dev/null || echo 0)
ok "linhas nuclei:    $(printf '%7d' "$NUC_LINES")"
[[ "$NUC_LINES" -gt 0 ]] && head -n 2 "$NUCLEI_JSONL" | sed "s/^/• /"

# ---------- 7) RESUMO ----------
section "RESUMO"

export LC_ALL=C LANG=C

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