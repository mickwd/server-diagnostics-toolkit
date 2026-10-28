#!/usr/bin/env bash
# Diagnóstico rápido de un servidor Linux, sin Python ni jq.
#
# Versión en bash del toolkit sysdiag para servidores donde no se puede instalar
# nada. Corre una batería de checks y escribe un JSON listo para adjuntar a un
# ticket. El exit code refleja el peor estado: 0 OK, 1 WARN, 2 CRIT, 3 ERROR.
#
# Uso:
#   ./quick_diag.sh [-d nombres] [-t host:puerto,...] [-p hosts] [-c hosts_tls]
#                   [-s servicios] [-H horas] [-o archivo.json] [-u]
#
#   -d  nombres DNS a resolver            (default: google.com,github.com)
#   -t  targets TCP host:puerto           (default: github.com:443,1.1.1.1:53)
#   -p  hosts para ping                   (default: 8.8.8.8,1.1.1.1)
#   -c  hosts para revisar certificados   (default: github.com,www.google.com)
#   -s  servicios systemd requeridos      (default: cron,ssh)
#   -H  horas hacia atrás para errores    (default: 24)
#   -o  archivo de salida (default: stdout)
#   -u  omite la consulta de actualizaciones pendientes

set -uo pipefail
export LC_ALL=C

DNS_NAMES="google.com,github.com"
TCP_TARGETS="github.com:443,1.1.1.1:53"
PING_HOSTS="8.8.8.8,1.1.1.1"
CERT_HOSTS="github.com,www.google.com"
SERVICES="cron,ssh"
EVENT_HOURS=24
OUT_FILE=""
SKIP_UPDATES=0

DISK_WARN=80
DISK_CRIT=90
MEM_WARN=85
MEM_CRIT=95
CERT_WARN_DAYS=30
CERT_CRIT_DAYS=7

usage() {
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts "d:t:p:c:s:H:o:uh" opt; do
    case "$opt" in
        d) DNS_NAMES=$OPTARG ;;
        t) TCP_TARGETS=$OPTARG ;;
        p) PING_HOSTS=$OPTARG ;;
        c) CERT_HOSTS=$OPTARG ;;
        s) SERVICES=$OPTARG ;;
        H) EVENT_HOURS=$OPTARG ;;
        o) OUT_FILE=$OPTARG ;;
        u) SKIP_UPDATES=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 3 ;;
    esac
done

RESULTS=()
WORST="OK"

severity() {
    case "$1" in
        OK) echo 0 ;; WARN) echo 1 ;; ERROR) echo 2 ;; CRIT) echo 3 ;; *) echo 2 ;;
    esac
}

worst_of() {
    # worst_of ESTADO_ACTUAL ESTADO_NUEVO -> imprime el más severo
    if [ "$(severity "$2")" -gt "$(severity "$1")" ]; then echo "$2"; else echo "$1"; fi
}

threshold() {
    # threshold VALOR WARN CRIT (enteros, mayor es peor)
    if [ "$1" -ge "$3" ]; then echo CRIT
    elif [ "$1" -ge "$2" ]; then echo WARN
    else echo OK
    fi
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

now_ms() {
    date +%s%3N
}

have() {
    command -v "$1" >/dev/null 2>&1
}

add_result() {
    # add_result NOMBRE CATEGORIA ESTADO MENSAJE DETALLES_JSON INICIO_MS
    local duration=$(( $(now_ms) - $6 ))
    RESULTS+=("{\"name\":\"$1\",\"category\":\"$2\",\"status\":\"$3\",\"message\":\"$(json_escape "$4")\",\"details\":$5,\"duration_ms\":$duration}")
    WORST=$(worst_of "$WORST" "$3")
}

split_csv() {
    tr ',' '\n' <<<"$1" | sed '/^$/d'
}

# --- Red -------------------------------------------------------------------------

check_dns() {
    local start status="OK" items="" failed="" name addr
    start=$(now_ms)
    while read -r name; do
        addr=$(getent ahosts "$name" 2>/dev/null | awk 'NR==1 {print $1}')
        if [ -n "$addr" ]; then
            items+="{\"name\":\"$name\",\"status\":\"OK\",\"address\":\"$addr\"},"
        else
            items+="{\"name\":\"$name\",\"status\":\"CRIT\",\"address\":null},"
            failed+="$name "
            status="CRIT"
        fi
    done < <(split_csv "$DNS_NAMES")
    local msg="Nombres resueltos correctamente"
    [ -n "$failed" ] && msg="No resuelven: ${failed% }"
    add_result dns network "$status" "$msg" "{\"items\":[${items%,}]}" "$start"
}

check_tcp() {
    local start status="OK" items="" bad="" target host port result
    start=$(now_ms)
    while read -r target; do
        host=${target%:*}
        port=${target##*:}
        # /dev/tcp de bash: sin dependencias. "timeout" corta los paquetes descartados por firewall.
        if timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
            result="abierto"
            items+="{\"target\":\"$target\",\"status\":\"OK\",\"result\":\"$result\"},"
        else
            if [ $? -eq 124 ]; then result="timeout (posible firewall)"; else result="rechazado o sin ruta"; fi
            items+="{\"target\":\"$target\",\"status\":\"CRIT\",\"result\":\"$result\"},"
            bad+="$target ($result); "
            status="CRIT"
        fi
    done < <(split_csv "$TCP_TARGETS")
    local msg="Puertos accesibles"
    [ -n "$bad" ] && msg="Sin acceso: ${bad%; }"
    add_result tcp_ports network "$status" "$msg" "{\"items\":[${items%,}]}" "$start"
}

check_ping() {
    local start status="OK" items="" msg="" host out loss avg item_status
    start=$(now_ms)
    if ! have ping; then
        add_result ping network ERROR "ping no está instalado" "{}" "$start"
        return
    fi
    while read -r host; do
        out=$(ping -c 4 -W 1 "$host" 2>&1)
        loss=$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' <<<"$out")
        avg=$(sed -n 's/.*min\/avg\/max[^=]*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p' <<<"$out")
        loss=${loss:-100}
        loss=${loss%.*}
        item_status=$(threshold "$loss" 10 50)
        if [ -n "$avg" ]; then
            item_status=$(worst_of "$item_status" "$(threshold "${avg%.*}" 100 300)")
            msg+="$host ${avg} ms/${loss}% loss; "
            items+="{\"host\":\"$host\",\"status\":\"$item_status\",\"loss_pct\":$loss,\"rtt_avg\":$avg},"
        else
            item_status="CRIT"
            msg+="$host sin respuesta; "
            items+="{\"host\":\"$host\",\"status\":\"CRIT\",\"loss_pct\":$loss,\"rtt_avg\":null},"
        fi
        status=$(worst_of "$status" "$item_status")
    done < <(split_csv "$PING_HOSTS")
    add_result ping network "$status" "${msg%; }" "{\"items\":[${items%,}]}" "$start"
}

check_gateway() {
    local start gw
    start=$(now_ms)
    gw=$(ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}')
    if [ -z "$gw" ]; then
        add_result gateway network CRIT "No hay gateway por defecto configurado" "{}" "$start"
    elif ping -c 2 -W 1 "$gw" >/dev/null 2>&1; then
        add_result gateway network OK "Gateway $gw responde" "{\"gateway\":\"$gw\"}" "$start"
    else
        add_result gateway network WARN "Gateway $gw no responde a ping" "{\"gateway\":\"$gw\"}" "$start"
    fi
}

check_tls() {
    local start status="OK" items="" msg="" target host port end end_epoch days item_status
    start=$(now_ms)
    if ! have openssl; then
        add_result tls_certs tls ERROR "openssl no está instalado" "{}" "$start"
        return
    fi
    while read -r target; do
        host=${target%:*}
        port=443
        [ "$host" != "$target" ] && port=${target##*:}
        end=$(timeout 10 openssl s_client -connect "$host:$port" -servername "$host" </dev/null 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -z "$end" ]; then
            items+="{\"host\":\"$target\",\"status\":\"ERROR\",\"days_left\":null},"
            msg+="$target (sin certificado); "
            status=$(worst_of "$status" ERROR)
            continue
        fi
        end_epoch=$(date -d "$end" +%s)
        days=$(( (end_epoch - $(date +%s)) / 86400 ))
        if [ "$days" -le "$CERT_CRIT_DAYS" ]; then item_status=CRIT
        elif [ "$days" -le "$CERT_WARN_DAYS" ]; then item_status=WARN
        else item_status=OK
        fi
        [ "$item_status" != OK ] && msg+="$target vence en $days días; "
        items+="{\"host\":\"$target\",\"status\":\"$item_status\",\"days_left\":$days,\"expires\":\"$(date -d "$end" +%F)\"},"
        status=$(worst_of "$status" "$item_status")
    done < <(split_csv "$CERT_HOSTS")
    [ -z "$msg" ] && msg="Certificados vigentes"
    add_result tls_certs tls "$status" "${msg%; }" "{\"items\":[${items%,}]}" "$start"
}

# --- Sistema ---------------------------------------------------------------------

check_disk() {
    local start status="OK" items="" fullest="" max=0 dev avail pct mount
    start=$(now_ms)
    while read -r dev _ _ avail pct mount; do
        pct=${pct%\%}
        [[ $pct =~ ^[0-9]+$ ]] || continue
        items+="{\"mountpoint\":\"$mount\",\"device\":\"$dev\",\"status\":\"$(threshold "$pct" "$DISK_WARN" "$DISK_CRIT")\",\"percent\":$pct,\"free_gib\":$(( avail / 1048576 ))},"
        status=$(worst_of "$status" "$(threshold "$pct" "$DISK_WARN" "$DISK_CRIT")")
        if [ "$pct" -ge "$max" ]; then max=$pct; fullest=$mount; fi
    done < <(df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2)
    add_result disk system "$status" "$fullest al ${max}%" "{\"items\":[${items%,}]}" "$start"
}

check_memory() {
    local start total avail pct
    start=$(now_ms)
    total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    # Kernels muy viejos no exponen MemAvailable: aproximamos con MemFree.
    [ -z "$avail" ] && avail=$(awk '/^MemFree:/ {print $2}' /proc/meminfo)
    pct=$(( (total - avail) * 100 / total ))
    add_result memory system "$(threshold "$pct" "$MEM_WARN" "$MEM_CRIT")" "Memoria al ${pct}%" \
        "{\"percent\":$pct,\"total_mib\":$(( total / 1024 )),\"available_mib\":$(( avail / 1024 ))}" "$start"
}

check_cpu() {
    local start load cores per_core_x100 status
    start=$(now_ms)
    load=$(cut -d' ' -f1 /proc/loadavg)
    cores=$(nproc 2>/dev/null || echo 1)
    per_core_x100=$(awk -v l="$load" -v c="$cores" 'BEGIN {printf "%d", (l / c) * 100}')
    status=$(threshold "$per_core_x100" 150 300)
    add_result cpu system "$status" "Load 1m $load en $cores cores" \
        "{\"load_1m\":$load,\"cores\":$cores}" "$start"
}

check_uptime() {
    local start seconds days status="OK" msg
    start=$(now_ms)
    seconds=$(cut -d. -f1 /proc/uptime)
    days=$(( seconds / 86400 ))
    msg="Uptime ${days}d $(( seconds % 86400 / 3600 ))h"
    if [ "$seconds" -lt 900 ]; then status=WARN; msg="Reinicio reciente: $msg"
    elif [ "$days" -gt 90 ]; then status=WARN; msg="Sin reiniciar hace $days días"
    fi
    if [ -f /var/run/reboot-required ]; then status=WARN; msg="$msg (reinicio pendiente)"; fi
    add_result uptime system "$status" "$msg" "{\"seconds\":$seconds}" "$start"
}

check_services() {
    local start status="OK" items="" bad="" unit state
    start=$(now_ms)
    if ! have systemctl; then
        add_result services services ERROR "systemctl no disponible" "{}" "$start"
        return
    fi
    while read -r unit; do
        state=$(systemctl is-active "$unit" 2>/dev/null)
        state=${state:-unknown}
        if [ "$state" = "active" ]; then
            items+="{\"service\":\"$unit\",\"status\":\"OK\",\"state\":\"$state\"},"
        else
            items+="{\"service\":\"$unit\",\"status\":\"CRIT\",\"state\":\"$state\"},"
            bad+="$unit ($state), "
            status="CRIT"
        fi
    done < <(split_csv "$SERVICES")
    while read -r unit; do
        [ -z "$unit" ] && continue
        items+="{\"service\":\"$unit\",\"status\":\"WARN\",\"state\":\"failed\"},"
        bad+="$unit (failed), "
        status=$(worst_of "$status" WARN)
    done < <(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}')
    local msg="Servicios corriendo"
    [ -n "$bad" ] && msg="Servicios con problemas: ${bad%, }"
    add_result services services "$status" "$msg" "{\"items\":[${items%,}]}" "$start"
}

# --- Eventos y actualizaciones -------------------------------------------------------

check_recent_errors() {
    local start count top
    start=$(now_ms)
    if ! have journalctl; then
        add_result recent_errors events ERROR "journalctl no disponible" "{}" "$start"
        return
    fi
    # -o json imprime una línea por entrada, así los mensajes multilínea no inflan la cuenta.
    count=$(journalctl -p err --since "$EVENT_HOURS hours ago" --no-pager -q -o json 2>/dev/null | wc -l)
    top=$(journalctl -p err --since "$EVENT_HOURS hours ago" --no-pager -q -o short 2>/dev/null \
        | awk '{print $5}' | sed 's/\[.*//; s/:$//' | sort | uniq -c | sort -rn | head -1 | awk '{print $2 " x" $1}')
    if [ "$count" -eq 0 ]; then
        add_result recent_errors events OK "Sin errores en las últimas $EVENT_HOURS h" "{\"total\":0}" "$start"
    else
        add_result recent_errors events "$(threshold "$count" 1 25)" \
            "$count errores en las últimas $EVENT_HOURS h (más frecuente: $top)" "{\"total\":$count}" "$start"
    fi
}

check_updates() {
    local start pending security=0 manager rc status
    start=$(now_ms)
    if have apt; then
        manager=apt
        pending=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable from')
        security=$(apt list --upgradable 2>/dev/null | grep -c -- '-security')
    elif have dnf || have yum; then
        manager=yum
        if have dnf; then manager=dnf; fi
        "$manager" -q check-update >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 1 ]; then
            add_result updates updates ERROR "$manager check-update falló" "{}" "$start"
            return
        fi
        pending=$("$manager" -q check-update 2>/dev/null | grep -cE '^[[:alnum:]_.+-]+\.[[:alnum:]_]+[[:space:]]')
        security=$("$manager" -q updateinfo list --security 2>/dev/null | grep -c '/Sec')
    else
        add_result updates updates ERROR "No se encontró apt, dnf ni yum" "{}" "$start"
        return
    fi
    if [ "$security" -gt 0 ]; then status=CRIT
    elif [ "$pending" -gt 0 ]; then status=WARN
    else status=OK
    fi
    add_result updates updates "$status" "$pending actualizaciones pendientes ($security de seguridad)" \
        "{\"manager\":\"$manager\",\"pending\":$pending,\"security\":$security}" "$start"
}

# --- Ejecución -------------------------------------------------------------------------

STARTED=$(now_ms)
check_dns
check_tcp
check_ping
check_gateway
check_tls
check_disk
check_memory
check_cpu
check_uptime
check_services
check_recent_errors
[ "$SKIP_UPDATES" -eq 0 ] && check_updates

case "$WORST" in
    OK) EXIT_CODE=0 ;; WARN) EXIT_CODE=1 ;; CRIT) EXIT_CODE=2 ;; *) EXIT_CODE=3 ;;
esac

count_status() {
    local n=0 r
    for r in "${RESULTS[@]}"; do
        [[ $r == *"\"status\":\"$1\",\"message\""* ]] && n=$((n + 1))
    done
    echo "$n"
}

# shellcheck disable=SC1091
OS_NAME=$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)
JOINED=$(IFS=,; echo "${RESULTS[*]}")
JSON=$(cat <<EOF
{
  "generated_at": "$(date +%Y-%m-%dT%H:%M:%S%:z)",
  "host": {"hostname": "$(json_escape "$(hostname)")", "os": "$(json_escape "$OS_NAME") ($(uname -r))", "mode": "bash"},
  "overall_status": "$WORST",
  "exit_code": $EXIT_CODE,
  "summary": {"OK": $(count_status OK), "WARN": $(count_status WARN), "CRIT": $(count_status CRIT), "ERROR": $(count_status ERROR)},
  "duration_ms": $(( $(now_ms) - STARTED )),
  "results": [$JOINED]
}
EOF
)

if [ -n "$OUT_FILE" ]; then
    printf '%s\n' "$JSON" >"$OUT_FILE"
else
    printf '%s\n' "$JSON"
fi
exit "$EXIT_CODE"
