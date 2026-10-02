#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# codexRC - AUTO-UPDATE BLINDADO (guardian del servidor)
# ------------------------------------------------------------
# Flujo: detecta commit nuevo en GitHub -> git pull -> reinicia
# el servidor -> localhost queda actualizado al instante.
#
# BLINDAJE v0.38.3:
#   - instancia unica (lock con PID): dos watchers nunca pelean
#   - resurreccion: si el server MUERE (OOM/Android/crash), revive solo
#   - anti-cuelgue: si el proceso vive pero /health no responde 3
#     ciclos seguidos, lo da por colgado y lo reinicia
#   - anti-zombis: puerto 8000 liberado por PID (fuser -> ss -> lsof),
#     nunca pkill -f (se autokillaba, leccion aprendida)
#   - anti-bucle: 5 caidas rapidas seguidas -> espera progresiva
#     (30s/60s/120s) y avisa en el log; no martillea el telefono
#   - diagnostico: el output del server va a server.log; si muere,
#     sus ultimas 15 lineas quedan en auto_update.log
#   - rotacion de log: si pasa de 512KB conserva las ultimas 200 lineas
#
# Uso en Termux:
#   bash auto_update.sh              (chequea cada 20 segundos)
#   bash auto_update.sh 10           (chequea cada 10 segundos)
#
# Detener: Ctrl+C (detiene watcher Y servidor)
# Log: auto_update.log  |  Server: server.log
#
# NOTA ANDROID: si Termux se cierra COMPLETO (proceso padre matado
# por el sistema), ningun script puede revivirlo desde dentro.
# Blindaje necesario en el telefono (una sola vez):
#   1. Ajustes -> Apps -> Termux -> Bateria -> Sin restricciones
#   2. Mantener la notificacion de Termux activa (wakelock visible)
#   3. Con Termux:API instalado, este script pide wake-lock solo
# ============================================================

set -uo pipefail

INTERVALO="${1:-20}"
BRANCH="${2:-main}"

cd "$(dirname "$0")"
ROOT="$(pwd)"
PID_FILE="$ROOT/.server.pid"
LOCK_FILE="$ROOT/.watcher.lock"
LOG="$ROOT/auto_update.log"
SERVER_LOG="$ROOT/server.log"
LOG_MAX=524288   # 512 KB
HEALTH_URL="http://127.0.0.1:8000/health"

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

# ---------------- rotacion de log (evita log gigante en el celu) ----
if [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt "$LOG_MAX" ]; then
    tail -n 200 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# ---------------- instancia unica del watcher ------------------------
if [ -f "$LOCK_FILE" ]; then
    old_pid="$(cat "$LOCK_FILE" 2>/dev/null)"
    if [ -n "${old_pid:-}" ] && kill -0 "$old_pid" 2>/dev/null; then
        echo "Ya hay un watcher corriendo (pid $old_pid). Este sale."
        echo "Para reiniciarlo: kill $old_pid y volvé a lanzar."
        exit 1
    fi
    log "Lock viejo de watcher muerto (pid ${old_pid:-?}): limpiando"
fi
echo $$ > "$LOCK_FILE"

cleanup() {
    log "Watcher detenido. Apagando servidor..."
    stop_server
    rm -f "$LOCK_FILE"
    command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock 2>/dev/null
    exit 0
}
trap cleanup INT TERM

# ---------------- wake-lock (evita que Android duerma Termux) -------
if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock 2>/dev/null && log "wake-lock adquirido"
else
    echo "AVISO: 'termux-wake-lock' no existe."
    echo "  Instala Termux:API (pkg install termux-api) para que el"
    echo "  guardia pueda impedir que Android duerma el proceso."
    echo "  Mientras tanto: Ajustes -> Apps -> Termux -> Bateria -> Sin restricciones"
    log "AVISO: termux-wake-lock no disponible"
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: esta carpeta no es un clon de git."
    echo "Clona de nuevo: git clone https://github.com/Eliezer1817/codexRC.git"
    rm -f "$LOCK_FILE"
    exit 1
fi

server_pid() { [ -f "$PID_FILE" ] && cat "$PID_FILE" 2>/dev/null; }

# ---------------- cazador de zombis del puerto 8000 ------------------
# Nunca pkill -f (matchea este mismo script y se autokillaba).
# Orden de intento: fuser -> ss -> lsof.
matar_zombi_puerto() {
    local pid_z=""
    if command -v fuser >/dev/null 2>&1; then
        pid_z="$(fuser 8000/tcp 2>/dev/null | tr -d ' ')"
    fi
    if [ -z "$pid_z" ] && command -v ss >/dev/null 2>&1; then
        pid_z="$(ss -ltnp 2>/dev/null | grep ':8000' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)"
    fi
    if [ -z "$pid_z" ] && command -v lsof >/dev/null 2>&1; then
        pid_z="$(lsof -t -i :8000 2>/dev/null | head -1)"
    fi
    if [ -n "$pid_z" ]; then
        log "PUERTO 8000 ocupado por pid $pid_z (zombi): liberando"
        kill -9 "$pid_z" 2>/dev/null
        sleep 2
    fi
}

wait_healthy() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
            log "Health OK tras ${i} chequeos: servidor vivo"
            return 0
        fi
        sleep 2
    done
    matar_zombi_puerto
    for i in 1 2 3 4 5; do
        curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1 && return 0
        sleep 2
    done
    log "AVISO: el servidor no responde /health tras el arranque; el watcher sigue y reintenta en cada ciclo"
    return 1
}

start_server() {
    setsid bash start_termux.sh >> "$SERVER_LOG" 2>&1 &
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

log "=== Guardia blindado v0.38.3 activo (cada ${INTERVALO}s, rama $BRANCH) ==="
echo "codexRC guardia ACTIVO (cada ${INTERVALO}s) · instancias: unica por lock"
echo "Servidor: http://localhost:8000"
echo "Logs: auto_update.log (guardia) · server.log (servidor)"
echo "Ctrl+C detiene todo"

start_server

# ---------------- estado de resurreccion ----------------------------
CAIDAS_RAPIDAS=0          # caidas sin levantar estabilidad despues
FALLOS_HEALTH=0           # ciclos seguidos con /health muerto
ESPERA_BLOQUEO=0          # backoff progresivo tras bucle de caidas

while true; do
    # --- backoff: si el server cae en bucle, no martillar el celu ---
    if [ "$ESPERA_BLOQUEO" -gt 0 ]; then
        echo "[$(date '+%T')] Bucle de caidas: esperando ${ESPERA_BLOQUEO}s antes de revivir..."
        sleep "$ESPERA_BLOQUEO"
        ESPERA_BLOQUEO=0
    fi

    REMOTE="$(remote_head)"
    LOCAL="$(local_head)"

    if [ -n "$REMOTE" ] && [ "$REMOTE" != "$LOCAL" ]; then
        log "Commit nuevo detectado: ${LOCAL:0:7} -> ${REMOTE:0:7}"
        echo "[$(date '+%T')] Commit nuevo detectado, actualizando..."
        stop_server
        if git pull --ff-only origin "$BRANCH" >> "$LOG" 2>&1; then
            log "git pull OK. Reiniciando servidor..."
            echo "[$(date '+%T')] Pull OK, servidor reiniciandose"
        else
            log "ERROR: git pull fallo. Reiniciando con el codigo anterior."
        fi
        start_server
        CAIDAS_RAPIDAS=0
    fi

    pid="$(server_pid)"

    # --- caso 1: el proceso MURIO (OOM, Android, crash) -----------
    if [ -z "${pid:-}" ] || ! kill -0 "$pid" 2>/dev/null; then
        CAIDAS_RAPIDAS=$((CAIDAS_RAPIDAS + 1))
        log "Servidor CAIDO (${CAIDAS_RAPIDAS}a caida): diagnostico de server.log:"
        tail -n 15 "$SERVER_LOG" 2>/dev/null | while IFS= read -r l; do log "  | $l"; done
        if [ "$CAIDAS_RAPIDAS" -ge 5 ]; then
            ESPERA_BLOQUEO=$(( (CAIDAS_RAPIDAS - 4) * 30 ))   # 30/60/90/120s
            [ "$ESPERA_BLOQUEO" -gt 120 ] && ESPERA_BLOQUEO=120
            log "BUCLE DE CAIDAS: 5 o mas seguidas. Backoff ${ESPERA_BLOQUEO}s."
            echo "[$(date '+%T')] El server cae en bucle: revisa server.log (tip: RAM baja o puerto)."
        fi
        rm -f "$PID_FILE"
        echo "[$(date '+%T')] Servidor caido, reviviendo..."
        start_server
        FALLOS_HEALTH=0
    # --- caso 2: vive pero colgado (/health no responde) -----------
    elif ! curl -s --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
        FALLOS_HEALTH=$((FALLOS_HEALTH + 1))
        if [ "$FALLOS_HEALTH" -ge 3 ]; then
            log "Servidor COLGADO: proceso vivo pero /health fallo ${FALLOS_HEALTH} ciclos. Reiniciando."
            echo "[$(date '+%T')] Servidor colgado (no responde), reiniciando..."
            stop_server
            start_server
            FALLOS_HEALTH=0
            CAIDAS_RAPIDAS=$((CAIDAS_RAPIDAS + 1))
        fi
    else
        # todo sano: resetear contadores (estabilidad alcanzada)
        FALLOS_HEALTH=0
        if [ "$CAIDAS_RAPIDAS" -gt 0 ]; then
            log "Servidor estable tras caida: contadores a cero"
            CAIDAS_RAPIDAS=0
        fi
    fi

    sleep "$INTERVALO"
done
