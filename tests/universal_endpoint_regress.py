#!/usr/bin/env python3
# ============================================================
# codexRC - UNIVERSAL ENDPOINT REGRESS (v0.98.0)
# ------------------------------------------------------------
# Suite de regresion propia del motor UNIVERSAL ENDPOINT GRAPH.
# No toca el corpus certificado de core/regress.py; se corre por
# separado y, al final, dispara tambien el corpus existente para
# confirmar que nada se rompio (REGLA 33 DE v0.98.0).
# ============================================================
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core import universal_endpoint as ue
from core import gates_audit as ga
from core import fin_param_graph as fpg
from labs import router_lab


def _find(endpoints, method=None, path=None, handler_substr=None):
    out = []
    for e in endpoints:
        if method and e["method"] != method:
            continue
        if path and e["path"] != path:
            continue
        if handler_substr and (not e["handler"]
                               or handler_substr not in e["handler"]):
            continue
        out.append(e)
    return out


def run() -> int:
    fails = 0
    root = router_lab.build_lab()
    try:
        res = ue.discover(root)
        eps = res["endpoints"]

        # --- 1. slim route ---------------------------------------------
        m = _find(eps, "POST", "/api/bookings", "BookingController")
        ok = (len(m) == 1 and m[0]["handler_resolved"]
              and m[0]["confidence"] == "HIGH"
              and m[0]["source"] == "custom_router")
        print(f"[slim_route] -> {'PASS' if ok else 'FAIL'} {m}")
        fails += 0 if ok else 1

        # --- 2. psr7 route -----------------------------------------------
        m = _find(eps, "POST", "/api/pay", "PayController")
        ok = (len(m) == 1 and m[0]["handler_resolved"]
              and m[0]["handler"] == "PayController::charge")
        print(f"[psr7_route] -> {'PASS' if ok else 'FAIL'} {m}")
        fails += 0 if ok else 1

        # --- 3. array router -----------------------------------------
        m = _find(eps, "POST", "/api/refund", "RefundController")
        ok = (len(m) == 1 and m[0]["handler_resolved"]
              and m[0]["source"] == "array_router")
        print(f"[array_router] -> {'PASS' if ok else 'FAIL'} {m}")
        fails += 0 if ok else 1

        # --- 4. controller alias (2 rutas, mismo handler) ----------------
        alias_eps = [e for e in eps
                     if e["handler"] == "BookingController2::create"]
        paths = {e["path"] for e in alias_eps}
        ok = (len(alias_eps) == 2
              and paths == {"/api/book", "/v1/bookings"})
        print(f"[controller_alias] -> {'PASS' if ok else 'FAIL'} "
              f"paths={paths}")
        fails += 0 if ok else 1

        # --- 5. middleware chain ------------------------------------------
        m = _find(eps, "POST", "/api/secure", "SecureController")
        mdw_names = {x["name"] for x in m[0]["middleware"]} if m else set()
        ok = (len(m) == 1 and m[0]["handler"] == "SecureController::go"
              and {"AuthMiddleware", "RoleMiddleware"} <= mdw_names)
        print(f"[middleware_chain] -> {'PASS' if ok else 'FAIL'} "
              f"mdw={mdw_names}")
        fails += 0 if ok else 1

        # --- 6. unresolved handler (sigue siendo endpoint) ---------------
        m = _find(eps, "GET", "/api/ghost")
        ok = (len(m) == 1 and not m[0]["handler_resolved"])
        print(f"[unresolved_handler] -> {'PASS' if ok else 'FAIL'} {m}")
        fails += 0 if ok else 1

        # --- 7. false route (NO debe descubrirse) -------------------------
        fake1 = _find(eps, handler_substr="Logger")
        fake2 = [e for e in eps if e.get("path_raw") == "user_123"]
        ok = (len(fake1) == 0 and len(fake2) == 0)
        print(f"[false_route_rejected] -> {'PASS' if ok else 'FAIL'} "
              f"fake1={fake1} fake2={fake2}")
        fails += 0 if ok else 1

        # --- 8. dynamic route: LOW confidence, sin inventar path ---------
        dyn = [e for e in eps if e.get("path_raw")
               and "prefix" in str(e.get("path_raw"))]
        ok = (len(dyn) == 1 and dyn[0]["confidence"] == "LOW"
              and dyn[0]["state"] == "INFERRED"
              and dyn[0]["path"] == dyn[0]["path_raw"]
              and not dyn[0]["params"] == [{"name": "prefix",
                                            "kind": "ROUTE_PARAM"}])
        print(f"[dynamic_route] -> {'PASS' if ok else 'FAIL'} {dyn}")
        fails += 0 if ok else 1

        # --- 9. amelia-like: GATES no ve nada, UNIVERSAL si -------------
        gates_before = ga.audit(root)
        gates_handlers_before = len(gates_before.get("handlers", []))
        amelia_eps = _find(eps, "POST", "/bookings", "BookingApiController")
        amelia_cancel = [e for e in eps
                         if e["path"] == "/bookings/{bookingId}/cancel"]
        ok = (gates_handlers_before == 0  # GATES-AUDIT no entiende este router
              and len(amelia_eps) == 1 and amelia_eps[0]["handler_resolved"]
              and len(amelia_cancel) == 1
              and any(x["name"] == "AuthMiddleware"
                     for x in amelia_cancel[0]["middleware"]))
        print(f"[amelia_like_surface] -> {'PASS' if ok else 'FAIL'} "
              f"gates_before={gates_handlers_before} "
              f"create={amelia_eps} cancel={amelia_cancel}")
        fails += 0 if ok else 1

        # --- 10. dedup: misma (method,path,handler) de 2 fuentes ---------
        dup = _find(eps, "POST", "/api/dup", "DupController")
        ok = (len(dup) == 1
              and set(dup[0]["sources"]) == {"custom_router", "array_router"})
        print(f"[dedup_merges_sources] -> {'PASS' if ok else 'FAIL'} "
              f"n={len(dup)} sources={dup[0]['sources'] if dup else None}")
        fails += 0 if ok else 1

        # --- 11. GATES-AUDIT adaptador: formato compatible con FIN-LOGIC -
        gates_handlers = ue.to_gates_handlers(eps)
        ok = all("archivo_callback" in h and "linea_callback" in h
                for h in gates_handlers) and len(gates_handlers) > 0
        print(f"[gates_adapter_shape] -> {'PASS' if ok else 'FAIL'} "
              f"n={len(gates_handlers)}")
        fails += 0 if ok else 1

        # --- 12. FIN-LOGIC consume endpoints custom via la misma interfaz
        graph = fpg.build_graph(
            root, handlers=gates_handlers,
            extra_param_sources=ue.to_fin_param_sources(eps))
        amelia_nodes = [n for n in graph.get("nodes", [])
                        if isinstance(n, dict)
                        and n.get("file", "").endswith("amelia_like.php")]
        ok = len(amelia_nodes) > 0
        print(f"[fin_logic_consumes_custom_router] -> "
              f"{'PASS' if ok else 'FAIL'} nodos_amelia={len(amelia_nodes)}")
        fails += 0 if ok else 1

        # --- 13. metricas: surface before vs after -----------------------
        print(f"[metrics] {res['metrics']}")
        ok = (res["metrics"]["endpoints_deduplicated"] >= 8
              and res["metrics"]["handlers_unresolved"] >= 1)
        print(f"[metrics_sane] -> {'PASS' if ok else 'FAIL'}")
        fails += 0 if ok else 1

    finally:
        router_lab.cleanup_lab(root)

    # --- WP existente: GATES-AUDIT sigue intacto -------------------------
    wp_root = router_lab.build_lab()
    try:
        wp_fixture = os.path.join(wp_root, "wp_ajax_case.php")
        with open(wp_fixture, "w", encoding="utf-8") as fh:
            fh.write("""<?php
add_action('wp_ajax_do_thing', 'handle_do_thing');
function handle_do_thing() {
    $x = $_POST['id'];
    echo $x;
}
""")
        res_wp = ue.discover(wp_root)
        wp_eps = [e for e in res_wp["endpoints"]
                 if e["source"] == "wordpress_ajax"]
        ga_res = ga.audit(wp_root)
        ok = (len(ga_res.get("handlers", [])) == 1
              and len(wp_eps) == 1)
        print(f"[wp_existing_route_unbroken] -> {'PASS' if ok else 'FAIL'} "
              f"gates={len(ga_res.get('handlers', []))} universal={len(wp_eps)}")
        fails += 0 if ok else 1
    finally:
        router_lab.cleanup_lab(wp_root)

    print(f"\nUniversal Endpoint regress: {fails} fallo(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
