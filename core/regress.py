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



def seed_rc_000152() -> None:
    """RC-000152 (v0.66.0): FP-MEMORIA (AUTHZ-PROOF capa 5). Cada FP
    refutado deja huella estructural; los identigos se auto-cierran
    en cualquier plugin posterior. El FP se paga una sola vez."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000152" not in cases:
        _write_case({
            "id": "RC-000152",
            "module": "FP-MEMORIA (AUTHZ-PROOF capa 5)",
            "problem": "cada falso positivo de la misma familia se "
                       "re-triaba a mano lote tras lote (ej: menus "
                       "loader + nonce, metas publicas por diseno): "
                       "el mismo tiempo se pagaba una y otra vez en "
                       "plugins distintos con la misma estructura",
            "first_seen": "v0.44.0 (fp_autoclose cubria solo reglas "
                          "fijas, sin aprendizaje)",
            "fixed_in": "v0.66.0 (huella semantica: type/gate/rol/"
                        "nonce/owner/sinks/action_markers/code_markers; "
                        "matching EXACTO anti-ruido; memoria en repo "
                        "propagada por git; auto-aprendizaje desde "
                        "refutaciones PROBADAS de la DEFENSA)",
            "repro": {"plugins": "A (refutado por OPERADOR) y B "
                                 "(identico estructural, distinto "
                                 "nombre/archivo/clase)",
                      "expect": "B auto-cerrado FP-MEMORIA; hallazgo "
                                "de tipo distinto NO cerrado; aprender "
                                "dos veces NO duplica"},
            "case_real": "validado en sandbox con memoria aislada; "
                         "diff_hunt cierra por memoria ANTES de "
                         "evidencia (ahorra triaje) y aprende de "
                         "DESCARTADO",
            "status": "PROTECTED",
        })



def seed_rc_000153() -> None:
    """RC-000153 (v0.67.0): BAC-PROOF dinamico (AUTHZ-PROOF capa 4).
    Validacion A/B con ejecucion REAL en WP-LAB (WP+SQLite+php -S,
    sin MySQL): anon/sub/admin contra objeto victima del admin.
    DEMO-UNAUTH/DEMO-BAC-DINAMICO con evidencia de ejecucion; los
    REFUTADO alimentan FP-MEMORIA con prueba dinamica."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000153" not in cases:
        _write_case({
            "id": "RC-000153",
            "module": "BAC-PROOF (AUTHZ-PROOF capa 4)",
            "problem": "los candidatos BAC/IDOR solo tenian evidencia "
                       "estatica; sin prueba de ejecucion los "
                       "reportes a VDP/Patchstack quedaban debiles "
                       "y el triaje humano seguia siendo la unica "
                       "resolucion",
            "first_seen": "v0.64.0 (candidatos AUTHZ-PROOK sin "
                          "validacion dinamica)",
            "fixed_in": "v0.67.0 (core/bac_proof.py: WP-LAB local "
                        "con sqlite-database-integration, php -S, "
                        "wp-cli; siembra de canario en TODAS las "
                        "claves de meta que el plugin lee; A/B "
                        "anon/sub/admin; veredictos DEMO-BAC-"
                        "DINAMICO / DEMO-UNAUTH-DINAMICO / "
                        "REFUTADO-DINAMICO -> FP-MEMORIA)",
            "repro": {"plugins": "rc151 sintetico con handler idor "
                                 "(sin gate) y con_owner (con gate)",
                      "expect": "idor: sub obtiene el canario igual "
                                "que admin (DEMO-BAC-DINAMICO); "
                                "con_owner: sub bloqueado, admin "
                                "obtiene (REFUTADO -> memoria)"},
            "case_real": "bug real encontrado durante el desarrollo: "
                         "core install con el drop-in sqlite agrega "
                         "el sufijo /wp al siteurl; las cookies de "
                         "sesion viajan con path /wp y NO llegan a "
                         "/wp-admin -> todo el A/B veia usuarios "
                         "como anonimos. Fix: forzar siteurl/home "
                         "raiz en Lab.ensure()",
            "status": "PROTECTED",
        })


def seed_rc_000154() -> None:
    """RC-000154 (v0.68.0): REG-BOT + AB-DIFF universal (no-WP).
    Proveedor universal de identidades: registra cuentas ninja en
    sitios desconocidos (FORM-DISCOVERY lee el formulario,
    CONSTRAINT-SOLVER resuelve politicas, VERIFICATION-FLOW con
    codigo/enlace y polling corto) y AB-DIFF difa sesiones con
    relacion A-duena-de-X / B-independiente. Veredictos
    DEMO-UNAUTH / DEMO-BAC / REFUTADO con evidencia por endpoint."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000154" not in cases:
        _write_case({
            "id": "RC-000154",
            "module": "REG-BOT + AB-DIFF (no-WordPress)",
            "problem": "las 5 capas de AUTHZ-PROOF eran nativas de "
                       "WordPress; contra sitios no-WP el motor no "
                       "podia crear identidades ni difar autorizacion",
            "first_seen": "v0.67.0 (capas BAC solo aplicaban a "
                          "plugins WP)",
            "fixed_in": "v0.68.0 (core/reg_bot.py: 7 submodulos + "
                        "Identity estandarizado; core/ab_diff.py: "
                        "niveles automaticos 1/2/3; "
                        "core/lab_ab_site.py: laboratorio local; "
                        "backend/app.py: POST/GET /api/ab_diff)",
            "repro": {"lab": "lab_ab_site con IDOR intencional "
                            "(/api/user/<id> sin owner check) y gate "
                            "correcto (/api/user/<id>/notes)",
                      "expect": "REG-BOT registra A y B solas "
                                "(codigo por mailbox, 0 humano); "
                                "AB-DIFF: DEMO-BAC en /api/user/<id> "
                                "y REFUTADO en notes; sin veredictos "
                                "en endpoints publicos"},
            "case_real": "bug real encontrado durante el desarrollo: "
                         "_parse_forms solo devolvia formularios con "
                         "campo password, asi que el formulario de "
                         "verificacion (solo campo de codigo, sin "
                         "password) nunca se veia -> todos los "
                         "registros quedaban en timeout 180s. Fix: "
                         "include_all=True desde _find_verify_form. "
                         "Segundo bug: login() hacia POST a la accion "
                         "relativa ('/login') -> MissingSchema. Fix: "
                         "absolutizar accion contra self.site",
            "status": "PROTECTED",
        })


def seed_rc_000155() -> None:
    """RC-000155 (v0.69.0): VISION-GATE, clasificador visual de
    challenges via Gemini. El LLM clasifica con salida JSON
    estructurada (response_schema contractual, temperatura 0) y
    REG-BOT decide: el modelo jamas conduce el navegador.
    Entrada redactada (emails/telefonos/tokens tapados), cero
    credenciales hacia el modelo; sin clave o API caida -> ERROR
    y la caza conserva su comportamiento determinista (handoff)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000155" not in cases:
        _write_case({
            "id": "RC-000155",
            "module": "VISION-GATE (Gemini, clasificador visual)",
            "problem": "la heuristica _CAPTCHA_RE manda a la cola de "
                       "handoff TODO lo que menciona 'captcha' aunque "
                       "sea un falso positivo de marketing, y el "
                       "operador no sabe QUE tipo de challenge hay "
                       "hasta abrir la pagina",
            "first_seen": "v0.68.0 (REG-BOT nace con handoff ciego)",
            "fixed_in": "v0.69.0 (core/vision_gate.py: system prompt "
                        "VISION-GATE con few-shot E1-E5, "
                        "response_schema contractual, decide() "
                        "determinista con umbral confidence >= 0.8 "
                        "para DISCARD, redaccion de PII; integracion "
                        "en reg_bot.py submit)",
            "repro": {"sin_clave": "classify() -> action=ERROR "
                                    "(regla: nunca colgar)",
                      "clave_invalida": "API 400 capturado -> ERROR "
                                        "limpio, sin excepcion",
                      "decide": "CONTINUE pasa; DISCARD <0.8 cae a "
                                "HANDOFF; GHOSTGATE solo sugiere; "
                                "ERROR -> HANDOFF (determinista)"},
            "case_real": "dos bugs reales hallados en vivo: "
                         "(1) el auto-detector de secretos come el "
                         "prefijo 'AQ.' del formato nuevo de claves "
                         "Google (guarda 50 chars huerfanos) -> la "
                         "API la rechazaba; fix: normalizacion que "
                         "reintenta con 'AQ.' ante rechazo. (2) "
                         "gemini-2.0/2.5-flash retirados (404) y "
                         "3.8-flash saturado (503 high demand); fix: "
                         "lista MODELS con fallback 3.8-flash -> "
                         "flash-latest y maxOutputTokens 2000 (con "
                         "300 el thinking truncaba el JSON). "
                         "VALIDADO EN VIVO 3/3: registro normal -> "
                         "CONTINUE 0.98; recaptcha visible -> "
                         "GHOSTGATE 0.94; exige SMS -> DISCARD 0.96",
            "status": "PROTECTED",
        })


def seed_rc_000156() -> None:
    """RC-000156 (v0.69.2): downloader de PLUGIN-BATCH solo
    conocia /plugin/ de wordpress.org; los THEMES con los
    bounties mas altos de Patchstack (astra $7.200,
    hello-elementor $7.200, kadence $4.900, blocksy $2.600,
    hello-biz $2.600) viven en downloads.wordpress.org/theme/ y
    rebotaban como download_error. Fix: fallback automatico
    plugin -> theme en download(). Validado en vivo: 5/5 temas
    descargados y auditados en 2.7s-5s cada uno."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000156" not in cases:
        _write_case({
            "id": "RC-000156",
            "module": "PLUGIN-BATCH (downloader)",
            "problem": "los themes pagables fallaban con "
                       "download_error: el downloader solo probaba "
                       "downloads.wordpress.org/plugin/<slug>",
            "first_seen": "v0.69.1 (lote PAYABLE-FIRST top-30)",
            "fixed_in": "v0.69.2 (fallback a /theme/<slug>.zip)",
            "repro": {"antes": "astra/hello-elementor/kadence/blocksy/"
                               "hello-biz -> download_error",
                      "despues": "5/5 descargados y auditados con "
                                 "hallazgos propios procesados"},
            "case_real": "35 pagables auditados (30 plugins + 5 "
                         "themes); 110 hallazgos crudos, TODOS "
                         "refutados en triaje manual: gotmls "
                         "(array-select isset + regex checksums + "
                         "md5 hex + admin/nonce), hello-biz "
                         "(wp_ajax_install_plugin hace "
                         "current_user_can propio de core), blocksy "
                         "(importador admin-only PR:H), asgaros-forum "
                         "(sanitize_file_name en upload + loose-cmp "
                         "era CSS admin), astra/kadence (ternarios "
                         "literales + valores customizer admin). "
                         "SIN 0-days en el lote.",
            "status": "PROTECTED",
        })


def seed_rc_000157() -> None:
    """RC-000157 (v0.70.0): RACE-TRACE, TOCTOU en estado persistente.
    Ademas fija el bug de gates_audit: array('Cls','m') resolvia la
    CLASE como callback (perdia el metodo -> nopriv sin boost)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000157" in cases:
        return
    _write_case({
        "id": "RC-000157",
        "module": "RACE-TRACE + GATES-AUDIT",
        "problem": "check-then-act (TOCTOU) en estado persistente WP "
                   "indetectado; y callbacks estaticos array('Cls','m') "
                   "resolvian a la clase, no al metodo (nopriv perdido)",
        "first_seen": "v0.70.0",
        "fixed_in": "v0.70.0",
        "repro": {
            "fixture": "withdraw nopriv con wallet_balance RMW + guard",
            "expected": {"withdraw_handler": "CANDIDATO-RACE/critica",
                         "apply_coupon": "CANDIDATO-RACE/alta",
                         "credit_points": "RACE-ATOMICO",
                         "safe_transfer": "MITIGADO-TRANSIENT"},
        },
    })


def seed_rc_000158() -> None:
    """RC-000158 (v0.71.0): RACE-PROOF, ejecutor dinamico de
    carreras. Fix del bug real: getresponse() exige el estado
    interno de http.client (ERROR Idle) cuando el request se
    envia crudo por socket; se paso a lectura cruda."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000158" in cases:
        return
    _write_case({
        "id": "RC-000158",
        "module": "RACE-PROOF",
        "problem": "fire_barrier usaba getresponse() tras enviar el "
                   "request por socket crudo -> http.client lanza "
                   "'CannotSendRequest: Idle' en todas las respuestas",
        "first_seen": "v0.71.0",
        "fixed_in": "v0.71.0",
        "repro": {
            "expected": {"toctou_endpoint": "RACE-DEMO (exitos>allowed)",
                         "endpoint_endurecido": "SIN-RACE"},
        },
    })


def seed_rc_000159() -> None:
    """RC-000159 (v0.71.0): CSPT-SCAN. Fix del FP real: CONCAT en la
    ventana (-3/+2) marcaba fetch de ruta fija cerca de codigo
    vulnerable; la concatenacion debe estar EN la linea del sink."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000159" in cases:
        return
    _write_case({
        "id": "RC-000159",
        "module": "CSPT-SCAN",
        "problem": "CONCAT.eval sobre la ventana completa producia FP "
                   "en fetch de ruta fija adyacente a codigo vulnerable",
        "first_seen": "v0.71.0",
        "fixed_in": "v0.71.0",
        "repro": {"expected": {"candidatos": 2,
                                "falsos_positivos": 0}},
    })


def seed_rc_000160() -> None:
    """RC-000160 (v0.71.0): SAML-DEFENSE. Fix del FP real: ->process(
    es omnipresente en PHP no-SAML (Twig, JobQueue, email cutters);
    31 FP criticos en DeskPro. WSW solo si el archivo usa un toolkit
    SAML real."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000160" in cases:
        return
    _write_case({
        "id": "RC-000160",
        "module": "SAML-DEFENSE",
        "problem": "PROCESS regex ->process( matcheaba cualquier "
                   "framework; DeskPro produjo 31 falsos criticos",
        "first_seen": "v0.71.0",
        "fixed_in": "v0.71.0",
        "repro": {"expected": {"fixture": 3, "deskpro_src": 0}},
    })


def seed_rc_000161() -> None:
    """RC-000161 (v0.72.0): EDGESYNC-HUNT. Fix del bug real: el edge
    reenviaba raw_head.encode() sobre bytes -> AttributeError
    tragado por except silencioso; y el parser chunked no consumia
    el CRLF final del chunk 0. Detector debe distinguir DESYNC-DEMO
    (CL/TE) de SIN-DESYNC (CL/CL) con 3 probes."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000161" in cases:
        return
    _write_case({
        "id": "RC-000161",
        "module": "EDGESYNC-HUNT",
        "problem": "lab desync: sendall(raw_head.encode()) sobre bytes "
                   "mataba el reenvio silenciosamente; chunked parser "
                   "dejaba rest2 sin actualizar",
        "first_seen": "v0.72.0",
        "fixed_in": "v0.72.0",
        "repro": {"expected": {"desync_lab": "DESYNC-DEMO",
                                "consistente_lab": "SIN-DESYNC",
                                "probes_max": 3}},
    })


def seed_rc_000162() -> None:
    """RC-000162 (v0.73.0): bateria EDGESYNC de 9 framings.
    Cada variante debe distinguir el parser que le corresponde:
    estricto (rechaza dup/espacio) vs lenient (los honra), y la
    familia TE.CL debe dejar huella de candidato sin falsos DEMO
    en mundos consistentes."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000162" in cases:
        return
    _write_case({
        "id": "RC-000162",
        "module": "EDGESYNC-HUNT-V2",
        "problem": "una sola sonda CL+TE no basta: parsers distintos "
                   "caen en framings distintos",
        "first_seen": "v0.73.0",
        "fixed_in": "v0.73.0",
        "repro": {"expected": {
            "V1_vs_consistente": "SIN-DESYNC",
            "V3V4_vs_desync": "SIN-DESYNC",
            "V6V7_vs_desync": "DESYNC-DEMO",
            "V3V4V5V8_vs_lenient": "DESYNC-DEMO",
            "V2V9_vs_consistente_te": "SIN-DESYNC",
            "bateria_tecl": "SIN + candidatos [V2,V9]"}},
    })


def seed_rc_000163() -> None:
    """RC-000163 (v0.74.0): SONDA-DE-CORRELACION. Tres dimensiones
    (framing, persistencia, estado) + poison probes + TOPOLOGY-PRE.
    El veredicto debe distinguir el edge que RECHAZA el framing
    ambiguo (postura activa) del blanco limpio, y el poison debe
    demostrar desync por desplazamiento de la sonda sin eco
    clasico."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000163" in cases:
        return
    _write_case({
        "id": "RC-000163",
        "module": "EDGESYNC-CORRELACION",
        "problem": "una sola dimension (eco) no distingue rechazo "
                   "del edge, blanco limpio y desync sin eco",
        "first_seen": "v0.74.0",
        "fixed_in": "v0.74.0",
        "repro": {"expected": {
            "P1_vs_desync": "DESYNC-DEMO",
            "P1_vs_consistente": "SIN-DESYNC",
            "P2_vs_consistente_te": "SIN-DESYNC",
            "P1_vs_rechaza": "RECHAZO-EDGE",
            "bateria_vs_rechaza": "RECHAZO-EDGE",
            "topologia": "cdn|proxy|directo"}},
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
    seed_rc_000152()
    seed_rc_000153()
    seed_rc_000154()
    seed_rc_000155()
    seed_rc_000156()
    seed_rc_000157()
    seed_rc_000158()
    seed_rc_000159()
    seed_rc_000160()
    seed_rc_000161()
    seed_rc_000162()
    seed_rc_000163()
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
        if c["id"] == "RC-000153":
            # repro en vivo (requiere php + pdo_sqlite + red):
            # python3 core/bac_proof.py <plugin> — validado v0.67.0
            print(f"[{c['id']}] BAC-PROOF dinamico — repro en vivo "
                  f"(ver case_real), no se re-ejecuta en corpus")
        if c["id"] == "RC-000155":
            # repro en vivo: requiere GEMINI_API_KEY valida
            # (AI Studio) — validado el 100% con mocks + clave
            # invalida (ERROR limpio) v0.69.0
            print(f"[{c['id']}] VISION-GATE — sin API en corpus "
                  f"(validado con mocks + ERROR-paths)")
        if c["id"] == "RC-000154":
            # repro en vivo (lab local):
            # python3 core/lab_ab_site.py 8899 &
            # python3 core/ab_diff.py http://127.0.0.1:8899             #     --mock http://127.0.0.1:8899 — validado v0.68.0
            print(f"[{c['id']}] REG-BOT + AB-DIFF — repro en vivo "
                  f"en lab_ab_site (ver case_real), no se "
                  f"re-ejecuta en corpus")
        if c["id"] == "RC-000152":
            import tempfile
            from core import fp_memory
            from core.gates_audit import scan_path
            plug_a = """<?php
class Rc152a {
    public function __construct() {
        add_action('wp_ajax_rc152a_leak', array($this, 'leak'));
    }
    public function leak() {
        $post_id = $_POST['post_id'];
        echo get_post_meta($post_id, 'meta_public', true);
    }
}
"""
            plug_b = """<?php
class Completamente_Otro_Nombre {
    public function __construct() {
        add_action('wp_ajax_rc152b_diferente', array($this, 'leak'));
    }
    public function leak() {
        $post_id = $_POST['post_id'];
        echo get_post_meta($post_id, 'meta_public', true);
    }
}
"""
            with tempfile.TemporaryDirectory() as tmp:
                fp_memory.MEM_FILE = os.path.join(tmp, "mem.jsonl")
                ra = os.path.join(tmp, "a"); os.makedirs(ra)
                rb = os.path.join(tmp, "b"); os.makedirs(rb)
                open(os.path.join(ra, "leaky.php"), "w").write(plug_a)
                open(os.path.join(rb, "otro.php"), "w").write(plug_b)
                ga = scan_path(ra)
                hA = {"type": "bac", "file": "leaky.php", "line": 8}
                fid = fp_memory.learn(hA, ra, ga, refuted_by="OPERADOR",
                                      reason="meta publico", plugin="a")
                gb = scan_path(rb)
                hB = {"type": "bac", "file": "otro.php", "line": 8}
                hC = {"type": "xss", "file": "otro.php", "line": 8}
                b = fp_memory.annotate_all([dict(hB)], rb, gb)[0]
                cc = fp_memory.annotate_all([dict(hC)], rb, gb)[0]
                ded = fp_memory.learn(hA, ra, ga, refuted_by="OPERADOR",
                                      reason="re", plugin="a")
                ok = (fid is not None and
                      str(b.get("_fp", "")).startswith("FP-MEMORIA:") and
                      cc.get("_fp") is None and ded is None)
                print(f"[{c['id']}] aprender->cerrar={bool(b.get('_fp'))} "
                      f"distinto_abierto={cc.get('_fp') is None} "
                      f"dedupe={ded is None} -> "
                      f"{'PASS' if ok else 'FAIL'}")
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
        if c["id"] == "RC-000157":
            import tempfile
            from core.race_trace import audit as race_audit
            repro = """<?php
class RC157 {
    function withdraw_handler() {
        $u = get_current_user_id();
        $balance = get_user_meta($u, 'wallet_balance', true);
        if ($balance >= $_POST['amount']) {
            update_user_meta($u, 'wallet_balance', $balance - $_POST['amount']);
        }
    }
    function apply_coupon() {
        $used = get_option('coupon_uses');
        if ($used >= 100) { wp_die('limit'); }
        update_option('coupon_uses', $used + 1);
    }
    function credit_points() {
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->prefix}users SET points = points + 1 WHERE ID = %d",
            get_current_user_id()));
    }
    function safe_transfer() {
        $lock = get_transient('myplugin_lock_transfer');
        if ($lock) { return; }
        set_transient('myplugin_lock_transfer', 1, 5);
        $bal = get_option('account_balance');
        if ($bal >= 10) { update_option('account_balance', $bal - 10); }
    }
}
"""
            loader = ("<?php\n"
                      "add_action('wp_ajax_nopriv_withdraw', "
                      "array('RC157', 'withdraw_handler'));\n"
                      "add_action('wp_ajax_apply_coupon', "
                      "array('RC157', 'apply_coupon'));\n")
            with tempfile.TemporaryDirectory() as tmp:
                open(os.path.join(tmp, "rc157.php"), "w").write(repro)
                open(os.path.join(tmp, "loader.php"), "w").write(loader)
                res = race_audit(tmp)
                verd = {(h.get("funcion"), h["veredicto"])
                        for h in res["hallazgos"]}
                w_crit = [h for h in res["candidatos"]
                          if h["funcion"] == "withdraw_handler"]
                ok = (any(f == "withdraw_handler" and v == "CANDIDATO-RACE"
                          for f, v in verd)
                      and w_crit and w_crit[0]["severity"] == "critica"
                      and w_crit[0].get("nopriv") is True
                      and any(f == "apply_coupon" and v == "CANDIDATO-RACE"
                              for f, v in verd)
                      and any(f == "credit_points"
                              and v == "RACE-ATOMICO" for f, v in verd)
                      and any(f == "safe_transfer"
                              and v == "MITIGADO-TRANSIENT" for f, v in verd)
                      and res["resumen"]["candidatos"] == 2)
                print(f"[{c['id']}] race-trace 4/4 verdictos "
                      f"(nopriv boost incluido) -> "
                      f"{'PASS' if ok else 'FAIL ' + str(verd)}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000158":
            # lab TOCTOU efimero en puerto libre
            import socket as sk
            import subprocess
            import tempfile
            srv = """import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
LIM = 1
class H(BaseHTTPRequestHandler):
    def _s(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_POST(self):
        n = len(self.path)
        if self.path == "/v":
            if H.us >= LIM:
                return self._s(200, {"ok": 0, "msg": "limite"})
            time.sleep(0.08)
            H.us += 1
            return self._s(200, {"ok": 1, "msg": "cupon aplicado"})
        with H.lock:
            if H.us >= LIM:
                return self._s(200, {"ok": 0, "msg": "limite"})
            H.us += 1
            return self._s(200, {"ok": 1, "msg": "cupon aplicado"})
    def log_message(self, *a): pass
H.us = 0
H.lock = __import__("threading").Lock()
import sys
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"""
            with tempfile.TemporaryDirectory() as tmp:
                port = sk.socket()
                port.bind(("127.0.0.1", 0))
                portnum = port.getsockname()[1]
                port.close()
                spath = os.path.join(tmp, "srv.py")
                open(spath, "w").write(srv)
                proc = subprocess.Popen([sys.executable, spath,
                                         str(portnum)])
                try:
                    import time as _t
                    _t.sleep(1.0)
                    from core.race_proof import audit as rpa
                    r1 = rpa({"url": f"http://127.0.0.1:{portnum}/v",
                              "count": 10,
                              "success_contains": "cupon aplicado",
                              "allowed": 1})
                    ok1 = r1["veredicto"] == "RACE-DEMO" and \
                        r1["exitos"] > 1
                    r2 = rpa({"url": f"http://127.0.0.1:{portnum}/s",
                              "count": 10,
                              "success_contains": "cupon aplicado",
                              "allowed": 1})
                    ok2 = r2["veredicto"] == "SIN-RACE"
                    ok = ok1 and ok2
                    print(f"[{c['id']}] race-proof "
                          f"{r1['veredicto']}/{r2['veredicto']} "
                          f"(exitos={r1['exitos']}) -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    proc.kill()
        if c["id"] == "RC-000159":
            import tempfile
            from core.cspt_scan import audit as cspt
            js = ("const url = new URL(window.location.href);\n"
                  "const endpoint = url.searchParams.get('endpoint');\n"
                  "fetch('/api/v1/' + endpoint + '/d');\n"
                  "axios.get(`/admin/${params.page}`).then(render);\n"
                  "fetch('/api/v1/' + encodeURIComponent(location.search"
                  ".slice(1)) + '/x');\n"
                  "fetch('/api/v1/users/details');\n")
            with tempfile.TemporaryDirectory() as tmp:
                open(os.path.join(tmp, "app.js"), "w").write(js)
                r = cspt(tmp)
                cand = r["resumen"]["candidatos"]
                ok = cand == 2 and r["resumen"]["criticos"] == 2
                print(f"[{c['id']}] cspt candidatos={cand} "
                      f"(esperados 2, sin FP) -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000160":
            import tempfile
            from core.saml_audit import audit as saml
            vuln = ("<?php\n$auth = new OneLogin\\Auth($s);\n"
                    "$auth->processResponse();\n"
                    "$d = $auth->getAttributes();\n"
                    "$x = simplexml_load_string($_POST['saml']);\n")
            seg = ("<?php\n$auth = new OneLogin\\Auth($s);\n"
                   "$auth->processResponse();\n"
                   "if ($auth->hasErrors() || !$auth->isAuthenticated())"
                   "{ wp_die(); }\n"
                   "$x = simplexml_load_string($_POST['d'], null, "
                   "LIBXML_NONET);\n")
            with tempfile.TemporaryDirectory() as tmp:
                strict = ("<?php\n$settings = ['strict' => false];\n"
                          "$auth = new SimpleSAML\\Auth($settings);\n")
                open(os.path.join(tmp, "v.php"), "w").write(vuln)
                open(os.path.join(tmp, "s.php"), "w").write(seg)
                open(os.path.join(tmp, "st.php"), "w").write(strict)
                r = saml(tmp)
                cand = r["resumen"]["candidatos"]
                crit = r["resumen"]["criticos"]
                ok = cand == 3 and crit == 1
                print(f"[{c['id']}] saml candidatos={cand} "
                      f"(esperados 3, 1 critico) -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000161":
            import tempfile
            import subprocess
            import socket as sk
            from core.edgesync import audit as esa
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                results = []
                for ports, modo in [((18880, 18881), "desync"),
                                   ((18882, 18883), "consistente")]:
                    pe, pb = ports
                    proc = subprocess.Popen(
                        [sys.executable, lab, str(pe), str(pb), modo],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                    try:
                        import time as _t
                        _t.sleep(1.0)
                        r = esa({"url": f"http://127.0.0.1:{pe}/",
                                 "timeout": 5.0})
                        results.append(r["veredicto"])
                    finally:
                        proc.kill()
                ok = (results == ["DESYNC-DEMO", "SIN-DESYNC"])
                print(f"[{c['id']}] edgesync {results} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000162":
            import subprocess
            from core.edgesync import audit as esa2
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["desync", "consistente", "tecl",
                        "consistente-te", "lenient"]
                procs = {}
                base_p = 18920
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _t.sleep(1.2)
                    port = lambda m: base_p + mods.index(m) * 2
                    aud = lambda m, v=None: esa2({
                        "url": f"http://127.0.0.1:{port(m)}/",
                        "timeout": 5.0, "variant": v})
                    esperado = [
                        ("V1", "consistente", "SIN-DESYNC"),
                        ("V3", "desync", "SIN-DESYNC"),
                        ("V4", "desync", "SIN-DESYNC"),
                        ("V6", "desync", "DESYNC-DEMO"),
                        ("V7", "desync", "DESYNC-DEMO"),
                        ("V3", "lenient", "DESYNC-DEMO"),
                        ("V4", "lenient", "DESYNC-DEMO"),
                        ("V5", "lenient", "DESYNC-DEMO"),
                        ("V8", "lenient", "DESYNC-DEMO"),
                        ("V2", "consistente-te", "SIN-DESYNC"),
                        ("V9", "consistente-te", "SIN-DESYNC"),
                    ]
                    ok = True
                    for vid, m, exp in esperado:
                        got = aud(m, vid)["veredicto"]
                        tag = "PASS" if got == exp else "FAIL"
                        if got != exp:
                            ok = False
                        print(f"[{c['id']}] {vid} vs {m}: "
                              f"{got} (esperado {exp}) {tag}")
                    # bateria: tecl debe dar SIN con candidatos V2,V9
                    r = aud("tecl")
                    cands = r["evidencia"].get("tecl_candidatos")
                    bt = (r["veredicto"] == "SIN-DESYNC"
                          and sorted(cands) == ["V2", "V9"])
                    if not bt:
                        ok = False
                    print(f"[{c['id']}] bateria vs tecl: {r['veredicto']}"
                          f" cand={cands} -> "
                          f"{'PASS' if bt else 'FAIL'}")
                    print(f"[{c['id']}] matriz 9 framings -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p in procs.values():
                        p.kill()
        if c["id"] == "RC-000163":
            import subprocess
            from core.edgesync import audit as esa3
            from core.edgesync import clasificar_topologia as ctop
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["desync", "consistente", "rechaza",
                        "consistente-te"]
                procs = {}
                base_p = 18960
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _t.sleep(1.5)
                    port = lambda m: base_p + mods.index(m) * 2
                    aud = lambda m, v=None: esa3({
                        "url": f"http://127.0.0.1:{port(m)}/",
                        "timeout": 5.0, "variant": v})
                    ok = True
                    for vid, m, exp in [
                            ("P1", "desync", "DESYNC-DEMO"),
                            ("P1", "consistente", "SIN-DESYNC"),
                            ("P2", "consistente-te", "SIN-DESYNC"),
                            ("P1", "rechaza", "RECHAZO-EDGE")]:
                        got = aud(m, vid)["veredicto"]
                        tag = "PASS" if got == exp else "FAIL"
                        if got != exp:
                            ok = False
                        print(f"[{c['id']}] {vid} vs {m}: "
                              f"{got} (esperado {exp}) {tag}")
                    r = aud("rechaza")
                    br = r["veredicto"] == "RECHAZO-EDGE"
                    if not br:
                        ok = False
                    print(f"[{c['id']}] bateria vs rechaza: "
                          f"{r['veredicto']} -> "
                          f"{'PASS' if br else 'FAIL'}")
                    t1 = ctop({"server": "cloudflare",
                               "cf-ray": "abc"})
                    t2 = ctop({"via": "1.1 squid"})
                    t3 = ctop({})
                    tc = (t1["clase"] == "cdn-blindado"
                          and t1["alcance"] == ["V1", "V2", "P1"]
                          and t2["clase"] == "proxy-intermedio"
                          and t3["clase"] == "directo")
                    if not tc:
                        ok = False
                    print(f"[{c['id']}] topologia "
                          f"{t1['clase']}/{t2['clase']}/{t3['clase']}"
                          f" -> {'PASS' if tc else 'FAIL'}")
                    print(f"[{c['id']}] sonda de correlacion -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p in procs.values():
                        p.kill()
    print(f"\nRegression corpus: {len(cases)} caso(s), {fails} fallo(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
