#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# codexRC - AUTO-UPDATE DESDE GITHUB
# ------------------------------------------------------------
# Flujo: editas en GitHub -> haces commit -> este script detecta
# el commit nuevo -> git pull automatico -> reinicia el servidor
# -> localhost queda actualizado al instante.
#
# Uso en Termux:
#   bash auto_update.sh              (chequea cada 20 segundos)
#   bash auto_update.sh 10           (chequea cada 10 segundos)
#
# Detener: Ctrl+C (detiene el watcher Y el servidor)
# Log de actividad: auto_update.log
# ============================================================

set -uo pipefail

INTERVALO="${1:-20}"
BRANCH="${2:-main}"

cd "$(dirname "$0")"
ROOT="$(pwd)"
PID_FILE="$ROOT/.server.pid"
LOG="$ROOT/auto_update.log"

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

# Evita que Android duerma el proceso (si Termux:API esta instalado)
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock 2>/dev/null

# El repo debe ser un clon git (no un zip descargado)
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: esta carpeta no es un clon de git."
    echo "Clona de nuevo con: git clone https://github.com/Eliezer1817/codexRC.git"
    exit 1
fi

server_pid() { [ -f "$PID_FILE" ] && cat "$PID_FILE" 2>/dev/null; }

HEALTH_URL="http://127.0.0.1:8000/health"

# Espera a que el servidor responda /health tras arrancar; si el puerto
# quedo ocupado por un proceso zombi, lo caza y reintenta una vez.
wait_healthy() {
    local i pid_zombi
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
            log "Health OK tras ${i} chequeos: servidor vivo"
            return 0
        fi
        sleep 2
    done
    # puerto tomado por un proceso que no es el nuestro: liberarlo
    if command -v fuser >/dev/null 2>&1; then
        pid_zombi="$(fuser 8000/tcp 2>/dev/null | tr -d ' ')"
        if [ -n "$pid_zombi" ]; then
            log "PUERTO 8000 ocupado por pid $pid_zombi (zombi): liberando"
            kill -9 $pid_zombi 2>/dev/null
            sleep 2
            for i in 1 2 3 4 5; do
                curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1 && return 0
                sleep 2
            done
        fi
    fi
    log "AVISO: el servidor no responde /health tras el arranque; el watcher sigue y reintenta en cada ciclo"
    return 1
}

start_server() {
    setsid bash start_termux.sh >> "$LOG" 2>&1 &
    echo $! > "$PID_FILE"
    log "Servidor iniciado (pid $(cat "$PID_FILE"))"
    wait_healthy
}

stop_server() {
    local pid
    pid="$(server_pid)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        sleep 2
        kill -9 "$pid" 2>/dev/null
        log "Servidor detenido (pid $pid)"
    fi
    rm -f "$PID_FILE"
}

remote_head() { git ls-remote origin "refs/heads/$BRANCH" 2>/dev/null | awk '{print $1}'; }
local_head()  { git rev-parse "refs/heads/$BRANCH" 2>/dev/null; }

cleanup() {
    log "Watcher detenido. Apagando servidor..."
    stop_server
    command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock 2>/dev/null
    exit 0
}
trap cleanup INT TERM

log "=== Auto-update iniciado (cada ${INTERVALO}s, rama $BRANCH) ==="
echo "codexRC auto-update ACTIVO (chequeo cada ${INTERVALO}s)"
echo "Servidor: http://localhost:8000"
echo "Log: auto_update.log  |  Ctrl+C detiene todo"

start_server

while true; do
    REMOTE="$(remote_head)"
    LOCAL="$(local_head)"

    if [ -n "$REMOTE" ] && [ "$REMOTE" != "$LOCAL" ]; then
        log "Commit nuevo detectado: $LOCAL -> $REMOTE"
        echo "[$(date '+%T')] Commit nuevo detectado, actualizando..."
        stop_server

        if git pull --ff-only origin "$BRANCH" >> "$LOG" 2>&1; then
            log "git pull OK. Reiniciando servidor..."
            echo "[$(date '+%T')] Pull OK, servidor reiniciandose"
        else
            log "ERROR: git pull fallo. Reiniciando con el codigo anterior."
        fi

        start_server
    fi

    # autorresurreccion: si el server murio (OOM, Android, crash), volver a levantarlo
    pid="$(server_pid)"
    if [ -z "${pid:-}" ] || ! kill -0 "$pid" 2>/dev/null; then
        log "Servidor CAIDO (pid ausente/muerto): reiniciando"
        echo "[$(date '+%T')] Servidor caido, reiniciando..."
        rm -f "$PID_FILE"
        start_server
    fi

    sleep "$INTERVALO"
done
