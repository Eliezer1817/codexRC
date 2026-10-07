#!/usr/bin/env bash
# hunt_forever.sh - caza en loop infinito, nunca corta sola.
# Ciclo: WIDE-HUNT (corpus completo) -> RETRO-HUNT (pre-cooldown) ->
# refresca el corpus (trae altas/actualizaciones nuevas de wp.org) ->
# repite. Para: Ctrl+C en esta terminal (o matar la sesion tmux).
#
# Uso:
#   bash scripts/hunt_forever.sh            # workers=4 por defecto
#   bash scripts/hunt_forever.sh 2          # workers=2
set -u
cd "$(dirname "$0")/.."
WORKERS="${1:-4}"
LOG="hechos/wide_hunt.log"
mkdir -p hechos

trap 'echo; echo "[$(date -u +%FT%TZ)] parado por el operador"; exit 0' SIGINT SIGTERM

vuelta=0
while true; do
  vuelta=$((vuelta + 1))
  echo "===== [$(date -u +%FT%TZ)] vuelta $vuelta: WIDE-HUNT =====" | tee -a "$LOG"
  python3 core/hunt_wide.py --dias 36500 --workers "$WORKERS" 2>&1 | tee -a "$LOG"
  echo "===== [$(date -u +%FT%TZ)] vuelta $vuelta: RETRO-HUNT =====" | tee -a "$LOG"
  python3 core/retro_hunt.py --workers "$WORKERS" 2>&1 | tee -a "$LOG"
  echo "===== [$(date -u +%FT%TZ)] vuelta $vuelta: refrescando corpus =====" | tee -a "$LOG"
  python3 core/wide_corpus.py --refresh 2>&1 | tee -a "$LOG"
  echo "===== [$(date -u +%FT%TZ)] vuelta $vuelta terminada, pausa 30s antes de seguir =====" | tee -a "$LOG"
  sleep 30
done
