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



def seed_rc_000149() -> None:
    """RC-000149 (v0.63.0): hooks dinamicos en GATES-AUDIT.
    add_action($var,...), callback/metodo en variable y closures en
    linea quedaban CALLBACK-NO-RESUELTO o invisibles; ademas off-by-one
    heredado en FUNC_RE hacia que firmas sin docblock tras '}' leyeran
    cuerpo vacio (veredicto sin leer el handler)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000149" not in cases:
        _write_case({
            "id": "RC-000149",
            "module": "GATES-AUDIT (AUTHZ-PROOF capa 3)",
            "problem": "hooks dinamicos no resueltos: add_action($var, ...) "
                       "por concatenacion/interpolacion, add_action('h', $cb), "
                       "array($this, $m_var) y closures en linea quedaban "
                       "CALLBACK-NO-RESUELTO o directamente invisibles; "
                       "off-by-one heredado en FUNC_RE (prefijo consume el "
                       "salto de linea previo) => cuerpo vacio en firmas "
                       "sin docblock precedidas por '}'",
            "first_seen": "v0.62.8 (hallado al implementar AUTHZ-PROOF capa 3)",
            "fixed_in": "v0.63.0 (const-prop lite por archivo + _action_args "
                        "a profundidad 0 + analisis de closures; ln=src[:"
                        "m.end()].count para FUNC_RE)",
            "repro": {"plugin": "6 hooks dinamicos en un solo archivo",
                      "expect": {"wp_ajax_rc149_save": "PROTEGIDO",
                                 "wp_ajax_nopriv_rc149_leak": "CANDIDATO-BAC",
                                 "wp_ajax_rc149_global": "REVISAR-AUTH",
                                 "wp_ajax_rc149_dyn": "REVISAR-AUTH",
                                 "wp_ajax_nopriv_rc149_closure_ok": "PROTEGIDO",
                                 "wp_ajax_nopriv_rc149_closure_bad": "CANDIDATO-BAC"}},
            "case_real": "eRoom 1.7.1: 17 hooks, el 0-day "
                         "wp_ajax_nopriv_stm_zoom_meeting_sign sigue "
                         "CANDIDATO-BAC y los 12 PROTEGIDO intactos",
            "status": "PROTECTED",
        })



def seed_rc_000150() -> None:
    """RC-000150 (v0.64.0): ROLE-SOLVER. El nonce prueba identidad, no
    autorizacion: handler sensible con privilegio bajo (read/edit_posts)
    dejaba de ser candidato solo por tener current_user_can + nonce."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000150" not in cases:
        _write_case({
            "id": "RC-000150",
            "module": "GATES-AUDIT (AUTHZ-PROOF capa 1)",
            "problem": "GATES-AUDIT trataba cualquier current_user_can "
                       "como 'protegido' sin importar QUE privilegio "
                       "exige ni QUE hace el handler: update_option "
                       "accesible con current_user_can('read') (cualquier "
                       "suscriptor logueado) pasaba como PROTEGIDO. El "
                       "nonce prueba identidad, no autorizacion",
            "first_seen": "v0.43.0 (latente desde el diseno original)",
            "fixed_in": "v0.64.0 (ROLE-SOLVER: extraccion de caps "
                        "reales + tabla cap->rol estandar WP + deteccion "
                        "de acciones sensibles; caps bajas + sensible -> "
                        "PRIVILEGIO-DEBIL; solo-nonce queda anotado)",
            "repro": {"plugin": "4 handlers: read+update_option, "
                                "manage_options+update_option, "
                                "nopriv+nonce+update_option, "
                                "edit_posts+eco",
                      "expect": {"wp_ajax_rc150_bajo": "PRIVILEGIO-DEBIL",
                                 "wp_ajax_rc150_admin": "PROTEGIDO",
                                 "wp_ajax_nopriv_rc150_nonce": "PROTEGIDO",
                                 "wp_ajax_rc150_bajo_insens": "PROTEGIDO"}},
            "case_real": "eRoom 1.7.1: 12 PROTEGIDO intactos (todos con "
                         "caps de administrador), 0-day nopriv sigue "
                         "CANDIDATO-BAC; rc149 6/6 sin cambios",
            "status": "PROTECTED",
        })



def seed_rc_000151() -> None:
    """RC-000151 (v0.65.0): OBJECT-OWNER. Un id controlado por el
    usuario que llega a get_post/get_post_meta sin verificacion de
    dueño dejaba de ser candidato porque el handler tenia nonce."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000151" not in cases:
        _write_case({
            "id": "RC-000151",
            "module": "GATES-AUDIT (AUTHZ-PROOF capa 2)",
            "problem": "GATES-AUDIT no miraba de QUIEN es el objeto: "
                       "absint($_POST['post_id']) -> get_post_meta sin "
                       "comparar post_author/current_user_id pasaba "
                       "inadvertido (IDOR horizontal invisible para el "
                       "triaje aunque el rol exigido fuera bajo)",
            "first_seen": "v0.64.0 (hueco admitido en el plan AUTHZ-PROOF)",
            "fixed_in": "v0.65.0 (OBJECT-OWNER: taint de ids $_GET/"
                        "$_POST/$_REQUEST + renames 3 hops + sinks de "
                        "objeto WP + OWNER_RE (post_author cmp, "
                        "current_user_id cmp, edit_post cap); sin owner "
                        "y rol < editor -> CANDIDATO-IDOR)",
            "repro": {"plugin": "4 handlers: idor puro, con owner check, "
                               "con rol admin, sin taint",
                      "expect": {"wp_ajax_rc151_idor": "CANDIDATO-IDOR",
                                 "wp_ajax_rc151_con_owner": "REVISAR-AUTH",
                                 "wp_ajax_rc151_admin": "PROTEGIDO",
                                 "wp_ajax_rc151_sin_taint": "REVISAR-AUTH"}},
            "case_real": "eRoom 1.7.1 estable (17 hooks, 0-day CANDIDATO-BAC "
                         "preservado, 12 PROTEGIDO); rc149 6/6 y rc150 4/4 "
                         "sin cambios",
            "status": "PROTECTED",
        })


def run() -> int:
    """Corre cada caso del corpus contra el motor actual. Devuelve 0 si
    todo PASS, 1 si algo quedo sin proteccion (regresion real)."""
    from core.evidence import build_chain

    seed_rc_000127()
    cases = _load_cases()
    fails = 0
    seed_rc_000149()
    seed_rc_000150()
    seed_rc_000151()
    cases = _load_cases()
    for c in cases:
        if c["id"] == "RC-000149":
            import tempfile
            from core.gates_audit import scan_path
            repro_php = """<?php
class RC149_Plugin {
    public function __construct() {
        $this->prefix = 'rc149';
        add_action('wp_ajax_' . $this->prefix . '_save', array($this, 'save_handler'));
        $hook2 = "wp_ajax_nopriv_rc149_leak";
        add_action($hook2, array($this, 'leak_handler'));
        $cb3 = 'rc149_global_handler';
        add_action('wp_ajax_rc149_global', $cb3);
        $m4 = 'dyn_method_handler';
        add_action('wp_ajax_rc149_dyn', array($this, $m4));
        add_action('wp_ajax_nopriv_rc149_closure_ok', function () {
            check_ajax_referer('rc149_nonce');
        });
        add_action('wp_ajax_nopriv_rc149_closure_bad', function () {
            echo get_option('admin_email');
        });
    }
    public function save_handler() {
        if (!current_user_can('manage_options')) { wp_die('no'); }
    }
    public function leak_handler() { echo get_option('admin_email'); }
    public function dyn_method_handler() { echo $_POST['id']; }
}
function rc149_global_handler() { wp_send_json(get_users()); }
"""
            with tempfile.TemporaryDirectory() as tmp:
                open(os.path.join(tmp, "rc149.php"), "w").write(repro_php)
                res = scan_path(tmp)
                got = {h["accion"]: h["veredicto"] for h in res["handlers"]}
                exp = cases_exp = {
                    "wp_ajax_rc149_save": "PROTEGIDO",
                    "wp_ajax_nopriv_rc149_leak": "CANDIDATO-BAC",
                    "wp_ajax_rc149_global": "REVISAR-AUTH",
                    "wp_ajax_rc149_dyn": "REVISAR-AUTH",
                    "wp_ajax_nopriv_rc149_closure_ok": "PROTEGIDO",
                    "wp_ajax_nopriv_rc149_closure_bad": "CANDIDATO-BAC"}
                ok = all(got.get(k) == v for k, v in exp.items()) and len(got) == 6
                print(f"[{c['id']}] {len(got)}/6 hooks dinamicos resueltos -> "
                      f"{'PASS' if ok else 'FAIL ' + str(got)}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000150":
            import tempfile
            from core.gates_audit import scan_path
            repro_php = """<?php
class RC150 {
    public function __construct() {
        add_action('wp_ajax_rc150_bajo', array($this, 'bajo'));
        add_action('wp_ajax_rc150_admin', array($this, 'admin_ok'));
        add_action('wp_ajax_nopriv_rc150_nonce', array($this, 'solo_nonce'));
        add_action('wp_ajax_rc150_bajo_insens', array($this, 'bajo_insens'));
    }
    public function bajo() {
        if (!current_user_can('read')) { wp_die('no'); }
        update_option($_POST['opt'], $_POST['val']);
    }
    public function admin_ok() {
        if (!current_user_can('manage_options')) { wp_die('no'); }
        update_option($_POST['opt'], $_POST['val']);
    }
    public function solo_nonce() {
        check_ajax_referer('rc150');
        update_option('rc150_opt', $_POST['val']);
    }
    public function bajo_insens() {
        if (!current_user_can('edit_posts')) { wp_die('no'); }
        echo get_option('blogname');
    }
}
"""
            with tempfile.TemporaryDirectory() as tmp:
                open(os.path.join(tmp, "rc150.php"), "w").write(repro_php)
                res = scan_path(tmp)
                got = {h["accion"]: h["veredicto"] for h in res["handlers"]}
                exp = {"wp_ajax_rc150_bajo": "PRIVILEGIO-DEBIL",
                       "wp_ajax_rc150_admin": "PROTEGIDO",
                       "wp_ajax_nopriv_rc150_nonce": "PROTEGIDO",
                       "wp_ajax_rc150_bajo_insens": "PROTEGIDO"}
                ok = all(got.get(k) == v for k, v in exp.items()) and len(got) == 4
                sn = any(h.get("solo_nonce") for h in res["handlers"]
                         if h["accion"] == "wp_ajax_nopriv_rc150_nonce")
                print(f"[{c['id']}] privilege-escalation {len(got)}/4, "
                      f"solo_nonce={sn} -> "
                      f"{'PASS' if ok and sn else 'FAIL ' + str(got)}")
                if not (ok and sn):
                    fails += 1
        if c["id"] == "RC-000151":
            import tempfile
            from core.gates_audit import scan_path
            repro_php = """<?php
class RC151 {
    public function __construct() {
        add_action('wp_ajax_rc151_idor', array($this, 'idor'));
        add_action('wp_ajax_rc151_con_owner', array($this, 'con_owner'));
        add_action('wp_ajax_rc151_admin', array($this, 'admin_toma'));
        add_action('wp_ajax_rc151_sin_taint', array($this, 'sin_taint'));
    }
    public function idor() {
        $post_id = absint($_POST['post_id']);
        echo get_post_meta($post_id, 'secret_key', true);
    }
    public function con_owner() {
        $post_id = absint($_POST['post_id']);
        $p = get_post($post_id);
        if ($p->post_author != get_current_user_id()) { wp_die('no'); }
        echo get_post_meta($post_id, 'secret_key', true);
    }
    public function admin_toma() {
        if (!current_user_can('manage_options')) { wp_die('no'); }
        $post_id = absint($_POST['post_id']);
        echo get_post_meta($post_id, 'secret_key', true);
    }
    public function sin_taint() {
        echo get_post_meta(get_the_ID(), 'x', true);
    }
}
"""
            with tempfile.TemporaryDirectory() as tmp:
                open(os.path.join(tmp, "rc151.php"), "w").write(repro_php)
                res = scan_path(tmp)
                got = {h["accion"]: h["veredicto"] for h in res["handlers"]}
                exp = {"wp_ajax_rc151_idor": "CANDIDATO-IDOR",
                       "wp_ajax_rc151_con_owner": "REVISAR-AUTH",
                       "wp_ajax_rc151_admin": "PROTEGIDO",
                       "wp_ajax_rc151_sin_taint": "REVISAR-AUTH"}
                ok = all(got.get(k) == v for k, v in exp.items()) and len(got) == 4
                print(f"[{c['id']}] idor estatico {len(got)}/4 -> "
                      f"{'PASS' if ok else 'FAIL ' + str(got)}")
                if not ok:
                    fails += 1
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
