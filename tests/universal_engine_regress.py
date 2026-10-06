#!/usr/bin/env python3
# ============================================================
# codexRC - UNIVERSAL ENGINE INTEGRATION REGRESS (v0.99.0)
# ------------------------------------------------------------
# Cierra el pendiente declarado en el CHANGELOG de v0.98.0: montar
# UNIVERSAL ENDPOINT GRAPH dentro del orquestador real del Hunter
# (core/universal_engine.py), no solo probarlo aislado.
#
# Fixture REAL en labs/fixtures_real/mixed_surface_plugin.php: un
# plugin WP que mezcla un hook clasico wp_ajax (superficie que
# GATES-AUDIT ya ve) con un router custom Slim-style embebido en el
# mismo archivo (superficie que GATES-AUDIT NO entiende). Es la
# misma clase de arquitectura que motivo v0.98.0 (hallazgo Amelia
# Booking, v0.97.0).
#
# Verifica:
#   1. El hook wp_ajax sigue viendose igual que siempre (GATES-AUDIT
#      intacto, no se duplica ni se pierde).
#   2. El endpoint del router custom aparece ahora en la cobertura
#      del Hunter (antes invisible), vía merge no invasivo
#      (to_gates_handlers, v0.98.0) con dedup por
#      archivo_callback+linea_callback.
#   3. Dedup: si GATES-AUDIT y UNIVERSAL ya vieran el MISMO
#      archivo_callback/linea_callback, no se cuenta 2 veces.
# No toca el corpus certificado de core/regress.py.
# ============================================================
import os
import shutil
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core import universal_engine as eng


def run() -> int:
    fails = 0
    fixture_src = os.path.join(
        BASE, "labs", "fixtures_real", "mixed_surface_plugin.php")

    # --- 1/2/3: fixture mixto real -----------------------------------
    tmp = tempfile.mkdtemp(prefix="ue_engine_lab_")
    try:
        plugin_dir = os.path.join(
            tmp, "wp-content", "plugins", "mixed-plugin")
        os.makedirs(plugin_dir, exist_ok=True)
        shutil.copy(fixture_src,
                    os.path.join(plugin_dir, "mixed-plugin.php"))

        res = eng.run(tmp)
        cov = res["cobertura"]

        wp_h = cov.get("handler:wp_ajax_do_thing")
        ok_wp = bool(wp_h) and wp_h["estado"] == "ANALIZADO"
        print(f"[gates_audit_unbroken] -> {'PASS' if ok_wp else 'FAIL'} "
              f"{wp_h}")
        fails += 0 if ok_wp else 1

        custom_h = cov.get("handler:MixedController::show")
        ok_custom = (bool(custom_h)
                     and custom_h["estado"] == "DESCUBIERTO"
                     and custom_h["nota"] == "UNIVERSAL-UNVERIFIED")
        print(f"[custom_router_now_visible] -> "
              f"{'PASS' if ok_custom else 'FAIL'} {custom_h}")
        fails += 0 if ok_custom else 1

        usurf = cov.get("superficie:universal-endpoint")
        ok_merge = bool(usurf) and usurf["estado"] == "ANALIZADO"
        print(f"[merge_reported_in_ledger] -> "
              f"{'PASS' if ok_merge else 'FAIL'} {usurf}")
        fails += 0 if ok_merge else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- 4: dedup, mismo archivo_callback/linea_callback -------------
    tmp2 = tempfile.mkdtemp(prefix="ue_engine_dedup_")
    try:
        plugin_dir = os.path.join(
            tmp2, "wp-content", "plugins", "dedup-plugin")
        os.makedirs(plugin_dir, exist_ok=True)
        fixture = os.path.join(plugin_dir, "dedup-plugin.php")
        with open(fixture, "w", encoding="utf-8") as fh:
            fh.write(
                "<?php\n"
                "add_action('wp_ajax_do_thing', 'do_thing_handler');\n"
                "function do_thing_handler() {\n"
                "    $amount = $_POST['amount'];\n"
                "    echo 'ok';\n"
                "}\n")
        res2 = eng.run(tmp2)
        handlers2 = [k for k in res2["cobertura"]
                     if k.startswith("handler:")]
        ok_dedup = len(handlers2) == 1
        print(f"[no_double_count_same_handler] -> "
              f"{'PASS' if ok_dedup else 'FAIL'} {handlers2}")
        fails += 0 if ok_dedup else 1
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)

    print(f"\nUniversal Engine integration regress: {fails} fallo(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
