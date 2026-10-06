#!/usr/bin/env python3
"""FIN-RACE-ENGINE (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 7.

Experimento controlado, NO fuzzing masivo de concurrencia. Solo se usa
cuando el flujo ya senalo una operacion sensible (cupon, balance,
inventario, reembolso, reward -- lo decide quien llama, con evidencia
de que ese endpoint toca una de esas categorias, no se dispara a
ciegas sobre cualquier endpoint).

Compara:
  SECUENCIAL   N llamadas a la MISMA accion, una despues de la otra
               (reset antes): cuantas tienen exito.
  CONCURRENTE  las MISMAS N llamadas disparadas en paralelo (reset
               antes): cuantas tienen exito.

Si CONCURRENTE logra MAS exitos que SECUENCIAL (ej. secuencial: 1
exito + 1 rechazo; concurrente: 2 exitos), hay una ventana de carrera
real que el flujo normal no expone.

Escalera:
  RACE-CANDIDATE  concurrente > secuencial Y concurrente >= 2 exitos
                  (doble beneficio demostrado una vez).
  RACE-IMPACT     se reproduce en una segunda tanda independiente
                  (reset + repetir TODO el experimento).

Uso programatico (sin CLI: libreria para fin_logic_probe):
    from core.fin_race_engine import race_with_reproduction
"""
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

StepFn = Callable[[], Tuple[int, Dict[str, Any]]]
SuccessPred = Callable[[int, Dict[str, Any]], bool]


def run_sequential(reset_fn: Optional[Callable[[], None]],
                    do_action: StepFn, n: int = 2
                    ) -> List[Tuple[int, Dict[str, Any]]]:
    if reset_fn:
        reset_fn()
    return [do_action() for _ in range(n)]


def run_concurrent(reset_fn: Optional[Callable[[], None]],
                    do_action: StepFn, n: int = 2
                    ) -> List[Tuple[int, Dict[str, Any]]]:
    if reset_fn:
        reset_fn()
    results: List[Optional[Tuple[int, Dict[str, Any]]]] = [None] * n
    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        barrier.wait()  # alinea el disparo: maximiza la ventana real
        results[i] = do_action()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results  # type: ignore[return-value]


def _count_successes(results: List[Tuple[int, Dict[str, Any]]],
                      success: SuccessPred) -> int:
    return sum(1 for st, body in results if success(st, body))


def race_test(reset_fn: Optional[Callable[[], None]], do_action: StepFn,
               success: SuccessPred, n: int = 2) -> Dict[str, Any]:
    seq = run_sequential(reset_fn, do_action, n)
    seq_ok = _count_successes(seq, success)
    conc = run_concurrent(reset_fn, do_action, n)
    conc_ok = _count_successes(conc, success)

    veredicto = ("RACE-CANDIDATE" if (conc_ok > seq_ok and conc_ok >= 2)
                else "DESCARTADO")
    return {"veredicto": veredicto, "n": n,
           "secuencial_exitos": seq_ok, "concurrente_exitos": conc_ok,
           "secuencial": seq, "concurrente": conc}


def race_with_reproduction(reset_fn: Optional[Callable[[], None]],
                            do_action: StepFn, success: SuccessPred,
                            n: int = 2) -> Dict[str, Any]:
    if reset_fn is None:
        r1 = race_test(reset_fn, do_action, success, n)
        if r1["veredicto"] == "RACE-CANDIDATE":
            r1["nota"] = ("sin reset_fn no se puede reproducir de forma "
                         "independiente: techo RACE-CANDIDATE")
        return r1

    r1 = race_test(reset_fn, do_action, success, n)
    if r1["veredicto"] != "RACE-CANDIDATE":
        return {"veredicto": "DESCARTADO", "ronda_1": r1}

    r2 = race_test(reset_fn, do_action, success, n)
    if r2["veredicto"] == "RACE-CANDIDATE":
        return {"veredicto": "RACE-IMPACT", "ronda_1": r1, "ronda_2": r2,
               "evidencia": "doble beneficio concurrente reproducido en "
                           "2 tandas independientes (reset entre medio)"}
    return {"veredicto": "RACE-CANDIDATE", "ronda_1": r1, "ronda_2": r2,
           "nota": "no se reprodujo en la segunda tanda: queda "
                   "candidato, no impacto"}
