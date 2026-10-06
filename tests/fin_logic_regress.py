#!/usr/bin/env python3
"""FIN-LOGIC-REGRESS (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 10.

Matriz de regresion minima (seccion 19 del pedido): para cada nivel del
motor, UN caso vulnerable y UN caso seguro contra labs/fin_logic_lab.py.

Objetivo estricto:
    vulnerable -> IMPACT
    safe       -> DESCARTADO
    NUNCA      safe -> IMPACT

No corre nada en paralelo (lecciones previas del proyecto: los labs
compiten por puerto si se lanzan juntos). Cada caso levanta su propio
proceso de lab, prueba, y lo mata antes de pasar al siguiente.

Uso:
    python3 tests/fin_logic_regress.py
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import fin_logic_probe as flp  # noqa: E402
from core import fin_replay_engine as fre  # noqa: E402
from core import fin_race_engine as frc  # noqa: E402
from core import fin_state_engine as fse  # noqa: E402
from core import fin_state_transitions as fst  # noqa: E402
from labs import fin_logic_lab as lab_mod  # noqa: E402

RESULTS = []


def _start_lab(scenario, port):
    p = subprocess.Popen([sys.executable,
                          os.path.join(ROOT, "labs", "fin_logic_lab.py"),
                          scenario, str(port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/order/5001" % port,
                                   timeout=0.3)
            return p
        except Exception:
            time.sleep(0.1)
    return p


def _stop_lab(p):
    try:
        p.kill()
        p.wait(timeout=3)
    except Exception:
        pass


def _check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    RESULTS.append({"case": name, "status": status, "detail": detail})
    print("[%s] %s %s" % (status, name, ("- " + detail) if detail else ""))


# ----------------------------------------------------------------- L0
def test_l0():
    for scenario, port, expect_impact in (
            ("price_negative", 19801, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            res = flp.audit_lab(scenario, port=port)
            has_impact = res["resumen"].get("FIN-IMPACT-DEMO", 0) > 0
            name = "L0-%s" % ("vulnerable" if expect_impact else "safe")
            _check(name, has_impact == expect_impact,
                  "FIN-IMPACT-DEMO=%d" % res["resumen"].get(
                      "FIN-IMPACT-DEMO", 0))
        finally:
            _stop_lab(p)


# ----------------------------------------------------------------- L1
def test_l1():
    def run(scenario, port):
        base = "http://127.0.0.1:%d" % port
        flp._http(base + "/order/5001/reset", "POST")
        headers = {"X-Fin-Role": "subscriber", "X-Fin-User": "7"}
        st0, b0 = flp._http(base + "/order/5001")
        snap0 = fse.snapshot(st0, b0["order"])
        st1, b1 = flp._http(base + "/order/5001/bulk_update", "POST",
                            headers, {"price": -1, "quantity": 2})
        if st1 != 200 or not b1.get("ok"):
            return False  # rechazado: no hay beneficio
        snap1 = fse.snapshot(st1, b1["order"])
        d = fse.diff(snap0, snap1)
        total_after = snap1["fields"].get("total", 1)
        return total_after < 0

    for scenario, port, expect_impact in (
            ("multi_field", 19807, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            benefit = run(scenario, port)
            # reproducir una 2da vez de forma independiente
            flp._http("http://127.0.0.1:%d/order/5001/reset" % port, "POST")
            benefit2 = run(scenario, port)
            impacted = benefit and benefit2
            name = "L1-%s" % ("vulnerable" if expect_impact else "safe")
            _check(name, impacted == expect_impact,
                  "beneficio 1ra=%s 2da=%s" % (benefit, benefit2))
        finally:
            _stop_lab(p)


# ----------------------------------------------------------------- L2
def test_l2():
    def run(scenario, port):
        base = "http://127.0.0.1:%d" % port
        flp._http(base + "/order/5001/reset", "POST")
        headers = {"X-Fin-Role": "subscriber", "X-Fin-User": "7"}
        # operandos en valores de control validos, target forzado a 1
        flp._http(base + "/order/5001/price", "POST", headers, {"price": 100})
        flp._http(base + "/order/5001/qty", "POST", headers, {"qty": 2})
        st, b = flp._http(base + "/order/5001/subtotal_override", "POST",
                          headers, {"total_override": 1})
        if st != 200 or not b.get("ok"):
            return False
        total = b["order"].get("total")
        expected_formula = 100 * 2  # price*qty, discount=0
        return total != expected_formula and total == 1

    for scenario, port, expect_impact in (
            ("invariant_subtotal", 19808, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            v1 = run(scenario, port)
            v2 = run(scenario, port)
            impacted = v1 and v2
            name = "L2-%s" % ("vulnerable" if expect_impact else "safe")
            _check(name, impacted == expect_impact,
                  "violacion 1ra=%s 2da=%s" % (v1, v2))
        finally:
            _stop_lab(p)


# -------------------------------------------------------------- STATE
def test_state():
    # dinamico: transicion directa pending->paid sin pasar por /pay
    for scenario, port, expect_impact in (
            ("status_force_paid", 19804, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            base = "http://127.0.0.1:%d" % port
            flp._http(base + "/order/5001/reset", "POST")
            headers = {"X-Fin-Role": "subscriber", "X-Fin-User": "7"}
            st, b = flp._http(base + "/order/5001/status", "POST", headers,
                              {"status": "paid"})
            impacted = st == 200 and b.get("ok") and \
                b["order"].get("status") == "paid"
            name = "STATE-%s" % ("vulnerable" if expect_impact else "safe")
            _check(name, impacted == expect_impact,
                  "status forzado=%s" % impacted)
        finally:
            _stop_lab(p)

    # estatico: el grafo de transiciones distingue esperada vs candidata
    # (fixture sintetico, no requiere red)
    import tempfile
    fixture = """<?php
add_action('wp_ajax_order_action', 'oa_handle');
function oa_handle() {
    $status = get_order_status($order_id);
    if ($status == 'pending') {
        if ($action == 'pay') { $status = 'paid'; }
    }
    if ($status == 'paid') {
        if ($action == 'refund') { $status = 'refunded'; }
    }
    update_post_meta($order_id, 'status', $status);
}
"""
    tmpdir = tempfile.mkdtemp(prefix="fin_state_fixture_")
    with open(os.path.join(tmpdir, "wf.php"), "w") as f:
        f.write(fixture)
    g = fst.build_graph(tmpdir)
    esperada = fst.classify_transition(g, "pending", "paid")["expected"]
    candidata = not fst.classify_transition(g, "pending", "refunded")["expected"]
    _check("STATE-transition-graph-static", esperada and candidata,
          "pending->paid esperada=%s, pending->refunded candidata=%s" % (
              esperada, candidata))


# ------------------------------------------------------------- REPLAY
def test_replay():
    for scenario, port, expect_impact in (
            ("replay_claim", 19809, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            base = "http://127.0.0.1:%d" % port
            headers = {"X-Fin-Role": "subscriber", "X-Fin-User": "7"}

            def get_state():
                return flp._http(base + "/order/5001")

            def do_action():
                return flp._http(base + "/order/5001/claim_reward", "POST",
                                 headers, {})

            def reset():
                flp._http(base + "/order/5001/reset", "POST")

            reset()
            r = fre.replay_with_reproduction(reset, get_state, do_action,
                                             "reward_balance")
            name = "REPLAY-%s" % ("vulnerable" if expect_impact else "safe")
            impacted = r["veredicto"] == "REPLAY-IMPACT"
            _check(name, impacted == expect_impact,
                  "veredicto=%s" % r["veredicto"])
        finally:
            _stop_lab(p)


# --------------------------------------------------------------- RACE
def test_race():
    for scenario, port, expect_impact in (
            ("coupon_race", 19806, True),
            ("validated_control", 19805, False)):
        p = _start_lab(scenario, port)
        try:
            base = "http://127.0.0.1:%d" % port

            def reset():
                flp._http(base + "/order/5001/reset", "POST")

            def do_action():
                return flp._http(base + "/coupon/SAVE10/redeem", "POST",
                                 payload={"code": "SAVE10"})

            def success(st, body):
                return st == 200 and body.get("ok") is True

            r = frc.race_with_reproduction(reset, do_action, success, n=2)
            name = "RACE-%s" % ("vulnerable" if expect_impact else "safe")
            impacted = r["veredicto"] == "RACE-IMPACT"
            _check(name, impacted == expect_impact,
                  "veredicto=%s" % r["veredicto"])
        finally:
            _stop_lab(p)


def main():
    print("=== FIN-LOGIC-REGRESS v0.97.0 (BUSINESS LOGIC STATE ENGINE v2) ===")
    test_l0()
    test_l1()
    test_l2()
    test_state()
    test_replay()
    test_race()

    print()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    print("RESULTADO: %d/%d PASS" % (passed, total))
    if passed != total:
        print("FALLOS:")
        for r in RESULTS:
            if r["status"] == "FAIL":
                print("  - %s: %s" % (r["case"], r["detail"]))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
