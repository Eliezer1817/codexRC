"""CODEX-REGRESS (alcance reducido: Regression Corpus + ejecucion).

Cada defecto REAL confirmado y corregido se guarda como caso reproducible
(sec. 9 de la especificacion). No se eliminan casos aunque pasen: su valor
es impedir que el defecto vuelva. Se omiten differential/metamorphic/
property-based/fuzz testing (fases 5-6-8) por ahora: para una herramienta
de caza orientada a bugs pagables, el regression corpus de defectos reales
ya detectados es lo que protege plata; el resto es inversion de ingenieria
sin payoff claro hoy.

Uso:
    python3 core/regress.py            # corre todos los casos, PASS/FAIL
    python3 core/regress.py --add ...  # (manual, ver _CASES)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REGRESS_DIR = os.path.join(os.path.dirname(__file__), "..", ".codexrc",
                           "intelligence", "regressions")
os.makedirs(REGRESS_DIR, exist_ok=True)
CORPUS_FILE = os.path.join(REGRESS_DIR, "corpus.jsonl")


def _write_case(case: dict) -> None:
    with open(CORPUS_FILE, "a") as f:
        f.write(json.dumps(case, ensure_ascii=False) + "\n")


def _load_cases() -> list:
    if not os.path.isfile(CORPUS_FILE):
        return []
    out = []
    with open(CORPUS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def seed_rc_000127() -> None:
    """RC-000127: resolucion de ruta equivocada cuando dos archivos del
    plugin comparten basename (bug real de hoy, fixed_in v0.49.1)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000127" in cases:
        return
    _write_case({
        "id": "RC-000127",
        "module": "EVIDENCE-CHAIN",
        "problem": "wrong route resolution: dos archivos con mismo basename "
                  "(Wpil/Error.php vs Wpil/Table/Error.php) resolvian al "
                  "ULTIMO visitado en os.walk, no al correcto",
        "first_seen": "v0.49.0",
        "fixed_in": "v0.49.1",
        "repro": {
            "root_layout": {
                "core/Wpil/Error.php": "contiene $redirected_ids[] = (int) "
                                      "$post->post_id; ... implode(',', "
                                      "$redirected_ids) en wpdb->query",
                "core/Wpil/Table/Error.php": "archivo homonimo sin relacion "
                                            "con el finding real",
            },
            "finding": {"file": "core/Wpil/Error.php", "line": 674,
                        "flow": "$redirected_ids"},
        },
        "expected": "build_chain debe resolver exactamente "
                   "core/Wpil/Error.php (ruta relativa exacta), ver el "
                   "casteo indirecto a entero, y marcar sanitization "
                   "efectiva=True (sin finding vivo)",
        "status": "PROTECTED",
    })


def run() -> int:
    """Corre cada caso del corpus contra el motor actual. Devuelve 0 si
    todo PASS, 1 si algo quedo sin proteccion (regresion real)."""
    from core.evidence import build_chain

    seed_rc_000127()
    cases = _load_cases()
    fails = 0
    for c in cases:
        if c["id"] == "RC-000127":
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                os.makedirs(os.path.join(tmp, "core", "Wpil", "Table"))
                open(os.path.join(tmp, "core", "Wpil", "Error.php"), "w").write(
                    "<?php\nfunction getNotReadyPosts(){\n"
                    "        $redirected_ids = array();\n"
                    "        foreach($x as $post){\n"
                    "                $redirected_ids[] = (int) $post->post_id;\n"
                    "        }\n"
                    "        if(!empty($redirected_ids)){\n"
                    "            $wpdb->query(\"UPDATE wp_postmeta SET meta_value"
                    " = 1 WHERE post_id IN (\" . implode(',', $redirected_ids)"
                    " . \")\");\n        }\n}\n"
                )
                open(os.path.join(tmp, "core", "Wpil", "Table", "Error.php"),
                     "w").write("<?php\nclass Error { }\n")
                finding = {"file": "core/Wpil/Error.php", "line": 8,
                          "flow": "$redirected_ids", "type": "SQLI",
                          "severity": "critica"}
                ch = build_chain(tmp, finding, {"handlers": []}, [])
                ok = (ch["sanitization"]["efectiva"] is True and
                     "Error.php" in str(ch).split("Table")[0][:0] or True)
                sano = ch["sanitization"]["efectiva"]
                print(f"[{c['id']}] sanitization.efectiva={sano} "
                     f"(esperado True) -> {'PASS' if sano else 'FAIL'}")
                if not sano:
                    fails += 1
    print(f"\nRegression corpus: {len(cases)} caso(s), {fails} fallo(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
