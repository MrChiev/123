#!/data/data/com.termux/files/usr/bin/bash
# Cloudflare IP Scanner - Termux version
# Setup (once):  pkg update && pkg install -y curl coreutils findutils gawk
# Run:           bash cf_ip_scan.sh            (results go to ~/cf_scan)
#                bash cf_ip_scan.sh /sdcard/cf  (custom output folder)

# ======================== SETTINGS ========================
DOMAIN='proxy.angkor.pp.ua'          # Cloudflare-proxied hostname (SNI + Host)
TEST_PATH='/'                        # tip: set to your XRAY_WS_PATH, then HTTP 400 = reaches Xray
TEST_MODE='1003'                     # '1003'   = request https://IP/ directly; an IP counts as good ONLY if
                                     #            Cloudflare answers "error code: 1003" (direct IP access blocked)
                                     # 'domain' = original test through your domain (any HTTP reply counts)
TEST_PORT=80                         # bare-IP mode only (plain HTTP, no TLS, no path):
                                     #   80  = http://IP/      -> Cloudflare answers "error code: 1003"
                                     #   443 = http://IP:443/  -> Cloudflare answers "400 Bad Request, plain HTTP
                                     #         request was sent to HTTPS port" (proves port 443 is open on that IP)
KNOWN_GOOD=('104.18.0.51' '172.64.151.167')   # IPs you know work (also used as canaries)
SAMPLES=(1 100)                      # mode 2 only: host numbers tried in every /24
TCP_TIMEOUT=1.5                      # seconds to wait for port 443 to open
TCP_BATCH=300                        # IPs per batch (lower it if the canary check fails)
TCP_PAR=100                          # simultaneous TCP probes (phones: 60-150 is sensible)
THREADS=30                           # parallel HTTPS tests
CURL_TIMEOUT=6                       # seconds per HTTPS test
TOP_SUBNETS=5                        # subnets to deep-scan at the end (modes 1 and 2)
MAX_HTTPS=3000                       # max IPs given to the real HTTPS test
# ==========================================================

# port used by the fast TCP sweep (domain mode always needs 443)
if [ "$TEST_MODE" = "1003" ]; then SWEEP_PORT=$TEST_PORT; else SWEEP_PORT=443; fi

OUTDIR="${1:-$HOME/cf_scan}"
mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR"; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
START=$SECONDS

for cmd in curl timeout xargs awk split shuf; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing '$cmd'. Run: pkg install -y curl coreutils findutils gawk"; exit 1; }
done

command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock   # keep CPU awake while scanning

C_CYAN=$'\e[36m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_RED=$'\e[31m'; C_OFF=$'\e[0m'

echo "${C_CYAN}====================================================="
if [ "$TEST_MODE" = "1003" ]; then
  echo "  Cloudflare IP Scanner  (no domain needed: looking for error 1003)"
else
  echo "  Cloudflare IP Scanner  (domain: $DOMAIN)"
fi
echo "=====================================================${C_OFF}"

# ---------- Cloudflare IPv4 ranges ----------
CIDRS=(173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
       108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17
       162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22)
live=$(curl -s --max-time 8 https://www.cloudflare.com/ips-v4 | tr -d '\r' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$')
if [ "$(printf '%s\n' "$live" | grep -c .)" -ge 10 ]; then
  mapfile -t CIDRS <<<"$live"
  echo "Loaded ${#CIDRS[@]} ranges from cloudflare.com"
else
  echo "Using built-in range list"
fi

# ---------- helpers ----------
ip2long() { local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24) + (b<<16) + (c<<8) + d )); }

# prints every /24 prefix ("a.b.c") of every Cloudflare range
all_subnets() {
  local cidr base len start count k n
  for cidr in "${CIDRS[@]}"; do
    base=${cidr%/*}; len=${cidr#*/}
    start=$(ip2long "$base")
    if [ "$len" -ge 24 ]; then count=1; else count=$(( 1 << (24 - len) )); fi
    for (( k=0; k<count; k++ )); do
      n=$(( start + k*256 ))
      printf '%d.%d.%d\n' $(( (n>>24)&255 )) $(( (n>>16)&255 )) $(( (n>>8)&255 ))
    done
  done | sort -u
}

# reads /24 prefixes on stdin, prints .1-.254 of each
expand_subnets() { awk '{for(i=1;i<=254;i++) print $0"."i}'; }

# ---------- TCP probe ----------
tcp_one() { timeout "$TCP_TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$SWEEP_PORT" 2>/dev/null && echo "$1"; }

# $1 = file with IPs, $2 = label, $3 = output file (open IPs, canaries excluded)
sweep_tcp() {
  local in=$1 label=$2 out=$3
  : > "$out"
  local total done=0 canhit=0 cantot=0 f res g pct
  total=$(wc -l < "$in")
  local cdir; cdir=$(mktemp -d -p "$WORK")
  split -l "$TCP_BATCH" "$in" "$cdir/c_"
  for f in "$cdir"/c_*; do
    if [ "$HAVE_PY" = 1 ]; then
      res=$( { cat "$f"; printf '%s\n' "${KNOWN_GOOD[@]}"; } | python3 "$WORK/tcp.py" "$TCP_PAR" "$TCP_TIMEOUT" "$SWEEP_PORT" )
    else
      res=$( { cat "$f"; printf '%s\n' "${KNOWN_GOOD[@]}"; } | xargs -P "$TCP_PAR" -n1 bash -c 'tcp_one "$1"' _ )
    fi
    for g in "${KNOWN_GOOD[@]}"; do
      cantot=$((cantot+1))
      grep -qx "$g" <<<"$res" && canhit=$((canhit+1))
    done
    printf '%s\n' "$res" | grep -vxF -f <(printf '%s\n' "${KNOWN_GOOD[@]}") | grep . >> "$out"
    done=$(( done + $(wc -l < "$f") ))
    printf '\r    %s: %d / %d tested, %d open   ' "$label" "$done" "$total" "$(wc -l < "$out")"
  done
  echo
  pct=$(( cantot > 0 ? 100*canhit/cantot : 0 ))
  echo "    Canary check: known-good IPs answered ${pct}% of the time during the sweep"
  if [ "$pct" -lt 40 ]; then
    echo "${C_RED}    WARNING: the sweep is being throttled (network drops the flood). Results are incomplete."
    echo "             Lower TCP_PAR / TCP_BATCH in the settings (e.g. 50 / 100) and run again.${C_OFF}"
  fi
}

# ---------- Real HTTPS test (curl with SNI, through the chosen IP) ----------
https_one() {
  local ip=$1 out body meta code tls tot
  if [ "$TEST_MODE" = "1003" ]; then
    local scheme=http   # always plain HTTP, even on 443 (Cloudflare answers 400 "plain HTTP request was sent to HTTPS port")
    out=$(curl -sk --connect-timeout 4 --max-time "$CURL_TIMEOUT" \
          -w '|||%{http_code}|%{time_connect}|%{time_total}' "${scheme}://${ip}:${TEST_PORT}/" 2>/dev/null)
    meta=${out##*|||}; body=${out%|||*}
    IFS='|' read -r code tls tot <<<"$meta"
    # only a real Cloudflare "error code: 1003" counts; anything else that answered is marked 000
    if [ "$TEST_PORT" = "443" ]; then
      if grep -qi 'sent to HTTPS port' <<<"$body"; then code=400; else code=000; fi
    else
      if grep -qiE 'error code: ?1003|error 1003' <<<"$body" && [ "$code" = "403" ]; then code=1003; else code=000; fi
    fi
  else
    out=$(curl -s -o /dev/null --resolve "${DOMAIN}:443:${ip}" --connect-timeout 4 --max-time "$CURL_TIMEOUT" \
          -w '%{http_code}|%{time_appconnect}|%{time_total}' "https://${DOMAIN}${TEST_PATH}" 2>/dev/null)
    IFS='|' read -r code tls tot <<<"$out"
  fi
  awk -v ip="$ip" -v c="${code:-000}" -v t="${tls:-0}" -v o="${tot:-0}" \
      'BEGIN{printf "%s,%s,%d,%d\n", ip, c, t*1000, o*1000}'
}
# Fast TCP probe (python asyncio) - thousands of probes per minute instead of dozens per second.
# Install with: pkg install python   (the script falls back to slow bash probes without it)
HAVE_PY=0
if command -v python3 >/dev/null 2>&1; then
  HAVE_PY=1
  TCP_PAR=400; TCP_BATCH=1500
  cat > "$WORK/tcp.py" <<'PYEOF'
import asyncio, sys
par, tmo, port = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
async def probe(ip, sem, out):
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), tmo)
            w.close()
            out.append(ip)
        except Exception:
            pass
async def main():
    ips = [l.strip() for l in sys.stdin if l.strip()]
    sem = asyncio.Semaphore(par); out = []
    await asyncio.gather(*(probe(i, sem, out) for i in ips))
    print("\n".join(out))
asyncio.run(main())
PYEOF
fi
export -f tcp_one https_one
export DOMAIN TEST_PATH TEST_MODE TEST_PORT SWEEP_PORT TCP_TIMEOUT CURL_TIMEOUT

ALL="$WORK/all.csv"; : > "$ALL"     # ip,code,tlsMs,totalMs

# $1 = file with IPs, $2 = label ; appends to $ALL
run_https() {
  local in=$1 label=$2 total tmp pid
  total=$(wc -l < "$in")
  tmp="$WORK/https_$$.csv"; : > "$tmp"
  xargs -P "$THREADS" -n1 bash -c 'https_one "$1"' _ < "$in" >> "$tmp" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r    %s: %d / %d tested   ' "$label" "$(wc -l < "$tmp")" "$total"
    sleep 1
  done
  wait "$pid"
  printf '\r    %s: %d / %d tested   \n' "$label" "$(wc -l < "$tmp")" "$total"
  cat "$tmp" >> "$ALL"; rm -f "$tmp"
}

good_sorted() { awk -F, '$2!="000"' "$ALL" | sort -t, -k4,4n; }

save_results() {
  local g="$WORK/good.csv"
  good_sorted > "$g"
  if [ -s "$g" ]; then
    { echo "IP,Code,TlsMs,TotalMs"; cat "$g"; } > "$OUTDIR/cf_results.csv"
    head -n 50 "$g" | cut -d, -f1 > "$OUTDIR/best_ips.txt"
  fi
  GOOD_COUNT=$(wc -l < "$g")
}

print_table() { # $1 = number of rows
  printf '    %-16s %-5s %-8s %-8s\n' IP HTTP "TLS ms" "Total ms"
  good_sorted | head -n "$1" | awk -F, '{printf "    %-16s %-5s %-8s %-8s\n",$1,$2,$3,$4}'
}

# ---------- Control test ----------
echo
echo "${C_YEL}[0] Control test with your known-good IPs...${C_OFF}"
printf '%s\n' "${KNOWN_GOOD[@]}" > "$WORK/known.txt"
run_https "$WORK/known.txt" 'Control test'
awk -F, '{printf "    %-16s HTTP %s  TLS %s ms  total %s ms\n",$1,$2,$3,$4}' "$ALL"
if [ -z "$(good_sorted)" ]; then
  echo "${C_RED}WARNING: your known-good IPs failed this test. Check the domain / your connection first.${C_OFF}"
fi

# ---------- Choose scan mode ----------
echo
echo "${C_YEL}Choose a scan mode:${C_OFF}"
echo '  [1] Neighborhood : EVERY IP in the /20 block around each known-good IP  (a few minutes)'
echo '  [2] Sample sweep : 2 IPs per Cloudflare subnet (fast, but can miss single working IPs)'
echo '  [3] Full scan    : EVERY IP in ALL Cloudflare blocks, about 1.5 million  <- default'
echo '                     (python: roughly 1-2 hours; without python: many hours). Ctrl+C stops it;'
echo '                     open IPs found so far are kept in tcp_open.txt'
read -r -p 'Mode [1/2/3] (Enter = 3): ' mode
case "$mode" in 1|2|3) ;; *) mode=3 ;; esac

# ---------- Build candidate list ----------
all_subnets > "$WORK/subnets.txt"
CAND="$WORK/candidates.txt"

if [ "$mode" = 1 ]; then
  : > "$WORK/bases.txt"
  for k in "${KNOWN_GOOD[@]}"; do
    n=$(ip2long "$k"); n=$(( n - n % 4096 ))
    for (( j=0; j<16; j++ )); do
      m=$(( n + j*256 ))
      printf '%d.%d.%d\n' $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) >> "$WORK/bases.txt"
    done
  done
  sort -u "$WORK/bases.txt" -o "$WORK/bases.txt"
  expand_subnets < "$WORK/bases.txt" > "$CAND"
  echo; echo "${C_YEL}[1] Neighborhood scan: $(wc -l < "$CAND") IPs in $(wc -l < "$WORK/bases.txt") subnets...${C_OFF}"
elif [ "$mode" = 2 ]; then
  for s in $(cat "$WORK/subnets.txt"); do for n in "${SAMPLES[@]}"; do echo "$s.$n"; done; done > "$CAND"
  echo; echo "${C_YEL}[1] Sample sweep: $(wc -l < "$WORK/subnets.txt") subnets x ${#SAMPLES[@]} IPs...${C_OFF}"
else
  expand_subnets < "$WORK/subnets.txt" > "$CAND"
  echo; echo "${C_YEL}[1] FULL scan: $(wc -l < "$CAND") IPs. This takes a long time...${C_OFF}"
fi

# shuffle so a throttled stretch of the network doesn't hit one subnet only (modes 1/3 order doesn't matter)
OPEN="$OUTDIR/tcp_open.txt"
sweep_tcp "$CAND" "Stage 1: TCP $SWEEP_PORT sweep" "$OPEN"
echo "    $(wc -l < "$OPEN") IPs answered on port $SWEEP_PORT"

# ---------- Real HTTPS test ----------
declare -A DONE OPENSET
while IFS=, read -r ip _; do DONE[$ip]=1; done < "$ALL"
while read -r ip; do OPENSET[$ip]=1; done < "$OPEN"

: > "$WORK/tohttps.txt"
if [ "$mode" = 2 ]; then
  while read -r s; do
    for n in "${SAMPLES[@]}"; do
      ip="$s.$n"
      if [ -n "${OPENSET[$ip]}" ]; then echo "$ip" >> "$WORK/tohttps.txt"; break; fi
    done
  done < "$WORK/subnets.txt"
else
  cat "$OPEN" > "$WORK/tohttps.txt"
fi
while read -r ip; do [ -z "${DONE[$ip]}" ] && echo "$ip"; done < "$WORK/tohttps.txt" > "$WORK/todo.txt"
cnt=$(wc -l < "$WORK/todo.txt")
if [ "$cnt" -gt "$MAX_HTTPS" ]; then
  echo "${C_YEL}    Too many open IPs ($cnt); testing a random $MAX_HTTPS of them.${C_OFF}"
  shuf -n "$MAX_HTTPS" "$WORK/todo.txt" > "$WORK/todo2.txt"; mv "$WORK/todo2.txt" "$WORK/todo.txt"
fi

echo; echo "${C_YEL}[2] Real HTTPS test on $(wc -l < "$WORK/todo.txt") IPs...${C_OFF}"
[ -s "$WORK/todo.txt" ] && run_https "$WORK/todo.txt" 'Stage 2: HTTPS test'
save_results
echo "    $GOOD_COUNT IPs passed the real test"

if [ "$GOOD_COUNT" -gt 0 ]; then
  echo; echo "${C_GRN}Top 15 so far (fastest first):${C_OFF}"
  print_table 15
fi

# ---------- Optional deep scan (modes 1 and 2) ----------
if [ "$GOOD_COUNT" -gt 0 ] && [ "$mode" != 3 ]; then
  read -r -p "Deep-scan every IP inside the $TOP_SUBNETS best subnets? [Y/N]: " ans
  if [[ "$ans" =~ ^[Yy] ]]; then
    good_sorted | cut -d, -f1 | awk '{sub(/\.[0-9]+$/,""); if(!s[$0]++) print}' | head -n "$TOP_SUBNETS" > "$WORK/topsubs.txt"
    unset DONE; declare -A DONE
    while IFS=, read -r ip _; do DONE[$ip]=1; done < "$ALL"
    expand_subnets < "$WORK/topsubs.txt" | while read -r ip; do
      [ -z "${DONE[$ip]}" ] && [ -z "${OPENSET[$ip]}" ] && echo "$ip"
    done > "$WORK/deep.txt"
    echo; echo "${C_YEL}[3] Deep scan: $(wc -l < "$WORK/deep.txt") IPs in $(paste -sd, "$WORK/topsubs.txt")...${C_OFF}"
    if [ -s "$WORK/deep.txt" ]; then
      sweep_tcp "$WORK/deep.txt" 'Stage 3a: TCP sweep' "$WORK/open2.txt"
      cat "$WORK/open2.txt" >> "$OPEN"
      [ -s "$WORK/open2.txt" ] && run_https "$WORK/open2.txt" 'Stage 3b: HTTPS test'
    fi
    save_results
    echo "    $GOOD_COUNT IPs passed in total"
  fi
fi

# ---------- Summary ----------
echo
echo "${C_CYAN}====================================================="
echo "  DONE in $(( SECONDS - START )) seconds. $GOOD_COUNT working Cloudflare IPs found."
echo -n "${C_OFF}"
if [ "$GOOD_COUNT" -gt 0 ]; then
  echo "${C_GRN}  Best 10 (fastest first):${C_OFF}"
  good_sorted | head -n 10 | awk -F, '{printf "    %-16s HTTP %s   TLS %s ms   total %s ms\n",$1,$2,$3,$4}'
  echo "${C_GRN}  Saved: $OUTDIR/best_ips.txt  and  cf_results.csv${C_OFF}"
else
  echo "${C_RED}  Nothing passed. Check your internet connection and the domain.${C_OFF}"
fi
echo "${C_CYAN}=====================================================${C_OFF}"
command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock
