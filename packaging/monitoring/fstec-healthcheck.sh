#!/usr/bin/env bash
set -u

COMPOSE_DIR="${FSTEC_COMPOSE_DIR:-/home/raport/fstec-service/services}"
PUBLIC_URL="${FSTEC_HEALTH_URL:-http://127.0.0.1:8080/gw/api/health}"
DIRECT_URL="${FSTEC_DIRECT_HEALTH_URL:-http://127.0.0.1:8666/api/health}"
LOG_FILE="${FSTEC_HEALTH_LOG:-/home/raport/fstec-health.log}"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/fstec-health"
STATE_FILE="$STATE_DIR/last-alert"

mkdir -p "$STATE_DIR"

healthy() {
    curl -fsS --max-time 8 "$1" >/dev/null 2>&1
}

alert() {
    local message="$1"
    local now_epoch last_epoch=0
    now_epoch="$(date +%s)"
    [ -f "$STATE_FILE" ] && last_epoch="$(cat "$STATE_FILE" 2>/dev/null || echo 0)"
    if [ $((now_epoch - last_epoch)) -lt 300 ]; then
        return 0
    fi
    printf '%s %s\n' "$(date -Is)" "$message" >> "$LOG_FILE"
    logger -t fstec-health "$message" 2>/dev/null || true
    printf '%s' "$now_epoch" > "$STATE_FILE"
    if [ -n "${FSTEC_ALERT_WEBHOOK:-}" ]; then
        curl -fsS --max-time 8 -X POST "$FSTEC_ALERT_WEBHOOK" \
            -H 'Content-Type: application/json' \
            --data "{\"text\":\"$message\"}" >/dev/null 2>&1 || true
    fi
}

reload_nginx() {
    if docker exec fstec-nginx nginx -t >/dev/null 2>&1; then
        docker exec fstec-nginx nginx -s reload >/dev/null 2>&1 || true
    else
        (cd "$COMPOSE_DIR" && docker compose up -d --force-recreate --no-deps nginx >/dev/null 2>&1) || true
    fi
}

if healthy "$PUBLIC_URL"; then
    rm -f "$STATE_FILE"
    exit 0
fi

alert "FSTEC health check failed: $PUBLIC_URL"
if healthy "$DIRECT_URL"; then
    reload_nginx
else
    (cd "$COMPOSE_DIR" && docker compose up -d --no-deps api-gateway >/dev/null 2>&1) || true
    sleep 3
    reload_nginx
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if healthy "$PUBLIC_URL"; then
        printf '%s recovered after automatic action\n' "$(date -Is)" >> "$LOG_FILE"
        rm -f "$STATE_FILE"
        exit 0
    fi
    sleep 3
done

alert "FSTEC health check still failing after automatic action: $PUBLIC_URL"
exit 1
