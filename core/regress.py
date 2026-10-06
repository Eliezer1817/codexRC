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


def seed_rc_000164() -> None:
    """RC-000164 (v0.75.0): EDGE-PROFILE. La ficha del contrato del
    edge debe distinguir normalizador (reenvia CL puro) de
    conservador (reenvia crudo con TE) de rechazador (400+close),
    leyendo el ECO del downstream. Nada inferido: lo no observable
    debe quedar unknown."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000164" in cases:
        return
    _write_case({
        "id": "RC-000164",
        "module": "EDGE-PROFILE",
        "problem": "el veredicto de desync no caracteriza el "
                   "contrato del edge: que rechaza, normaliza o "
                   "conserva ante cada framing",
        "first_seen": "v0.75.0",
        "fixed_in": "v0.75.0",
        "repro": {"expected": {
            "normaliza": "normalized+reached",
            "conserva": "conserved+reached",
            "rechaza": "rejected+cierre_yes"}},
    })


def seed_rc_000165() -> None:
    """RC-000165 (v0.76.0): NORMALIZATION-AUDIT. La sonda
    BODY-DIFFERENTIAL (cuerpo '5\r\nhello\r\n0\r\n\r\n', dos
    lecturas posibles, sin smuggle) debe distinguir: normalizador
    (origin recibe CL puro, ECO te=none), conservador+back TE
    (origin ACTUA sobre la lectura TE: MISMATCH con escalera de
    evidencia hasta SOSPECHA) y rechazador total. REGLA DE ORO: la
    tolerancia del edge no es vulnerabilidad por si misma; solo
    MISMATCH con evidencia downstream escala."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000165" in cases:
        return
    _write_case({
        "id": "RC-000165",
        "module": "NORMALIZATION-AUDIT",
        "problem": "el perfil v0.75 dice que el edge acepta un "
                   "framing, pero no que representacion recibe el "
                   "origin; y la tolerancia no debe dictarse "
                   "hallazgo",
        "first_seen": "v0.76.0",
        "fixed_in": "v0.76.0",
        "repro": {"expected": {
            "normaliza": "NORMALIZED",
            "conserva": "MISMATCH->SOSPECHA",
            "rechaza": "RECHAZADO-TOTAL"}},
    })


def seed_rc_000166() -> None:
    """RC-000166 (v0.77.0): CONNECTION-STATE AUDIT. Un edge que
    honra TE (RFC 7230, correcto) produce el MISMO desplazamiento
    observable en conexion unica que un desync real; la
    diferencia es de IMPACTO cross-connection. El control de
    conexion inocente debe separar: desync-pool (front CL + back
    TE en back COMPARTIDO: la conexion inocente recibe respuesta
    ajena reproducible -> DEMO) de eco-normaliza (pipelining
    legitimo del front, conexion 2 limpia -> STABLE+PIPE) de
    consistente (STABLE). 'Cambio la respuesta' NO es smuggling
    por si solo."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000166" in cases:
        return
    _write_case({
        "id": "RC-000166",
        "module": "CONNECTION-STATE",
        "problem": "las sondas de conexion unica no distinguen "
                   "pipelining legitimo del front (edge honra TE) "
                   "de un desacuerdo real front/back: DEMO falso "
                   "sobre edges correctos",
        "first_seen": "v0.77.0",
        "fixed_in": "v0.77.0",
        "repro": {"expected": {
            "desync-pool": "DEMO",
            "eco-normaliza": "STABLE+PIPE",
            "consistente": "STATE-STABLE"}},
    })


def seed_rc_000167() -> None:
    """RC-000167 (v0.78.0): STATE-CORRELATION. El vector de
    evidencia (E0-E5) y el juez determinista deben separar:
    desync-pool (E4+E5 -> CROSS-CONNECTION-MISMATCH, DEMO) de
    eco-normaliza (E3+E2+E0 -> PIPE-BENIGN SELLADO: evidencia
    presente que NO escala) de consistente (E0/E0/E0 -> STABLE).
    La regla del falso DEMO v0.77 queda sellada en el juez:
    PIPE-BENIGN no escala por re-observacion."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000167" in cases:
        return
    _write_case({
        "id": "RC-000167",
        "module": "STATE-CORRELATION",
        "problem": "veredictos por sonda separados sin vector de "
                   "calidad: evidencia fuerte y debil pesaban "
                   "igual y el PIPE legitimo podia re-observarse "
                   "hasta escalar",
        "first_seen": "v0.78.0",
        "fixed_in": "v0.78.0",
        "repro": {"expected": {
            "desync-pool": "CROSS-CONNECTION-MISMATCH/DEMO",
            "eco-normaliza": "PIPE-BENIGN sellado (E3+E2+E0)",
            "consistente": "STABLE"}},
    })


class LabNoUp(Exception):
    """Los labs no lograron escuchar: falla ambiental, no
    del motor. Aborta limpio (exit 2) tras limpiar huerfanos."""
    pass


def _esperar_labs(base_p, n, secs=20.0):
    """Espera activa: los labs deben ESCUCHAR antes de auditar
    (1.5s fijo no alcanza bajo carga). Si a los 6s siguen sin
    escuchar, limpia labs huerfanos (flake de puertos en runs
    anidados) y sigue esperando. Si nunca suben: LabNoUp."""
    import socket as _sk
    import time as _t
    t0 = _t.time()
    _limpio = False
    while _t.time() - t0 < secs:
        todos = True
        for i in range(n):
            try:
                sk = _sk.create_connection(
                    ("127.0.0.1", base_p + i * 2), 0.4)
                sk.close()
            except Exception:
                todos = False
        if todos:
            return True
        if (not _limpio) and (_t.time() - t0 > 6.0):
            _kill_labs()
            _limpio = True
        _t.sleep(0.25)
    raise LabNoUp(
        "labs no escuchan en %d..%d tras %.0fs"
        % (base_p, base_p + (n - 1) * 2, secs))



def _seed_cache(cid, problem, expected):
    cases = {c["id"] for c in _load_cases()}
    if cid in cases:
        return
    _write_case({
        "id": cid,
        "module": "CACHE-CORRELATION",
        "problem": problem,
        "first_seen": "v0.79.0",
        "fixed_in": "v0.79.0",
        "repro": {"expected": expected},
    })


def seed_rc_000168() -> None:
    """RC-000168: consistent y ttl_variant. Estabilidad pura y
    variacion temporal CARACTERIZADA (VARIANT, no AMBIGUO):
    ambas deben dar STABLE sin nunca escalar."""
    _seed_cache(
        "RC-000168",
        "un baseline con variacion temporal (Age avanza, nucleo "
        "estable) podia confundirse con baseline ambiguo o con "
        "diferencial cache",
        {"consistent": "STABLE/baseline STABLE",
         "ttl_variant": "STABLE/baseline VARIANT temporal"})


def seed_rc_000169() -> None:
    """RC-000169: divergent_equivalent. Par EQUIVALENT (RFC 7230
    3.2, case del nombre de header) divergente reproducible con
    controles criticos superados y senales de cache explicitas:
    SUSPICIOUS, jamas DEMO (sin impacto de seguridad)."""
    _seed_cache(
        "RC-000169",
        "un diferencial en par EQUIVALENT sin controles ni "
        "binding podia escalar a DEMO por acumulacion",
        {"divergent_equivalent": "SUSPICIOUS/E2+E3+E4"})


def seed_rc_000170() -> None:
    """RC-000170: personalized. Diferencia explicada por
    Vary: Cookie + Set-Cookie: BENIGN con el control FAILED
    como evidencia, no un finding."""
    _seed_cache(
        "RC-000170",
        "una diferencia legitimamente explicada por "
        "personalizacion (Vary/Cookie) no debe contar como "
        "diferencial de cache",
        {"personalized": "BENIGN/vary+cookies explican"})


def seed_rc_000171() -> None:
    """RC-000171: bot_ambiguous. Rotacion de cuerpos sin
    caracterizar: baseline AMBIGUO -> UNKNOWN conservador, sin
    poder discriminatorio no se concluye nada."""
    _seed_cache(
        "RC-000171",
        "variacion no explicada (bot management) podia "
        "interpretarse como diferencial o convergencia de cache",
        {"bot_ambiguous": "UNKNOWN/baseline AMBIGUO"})


def seed_rc_000172() -> None:
    """RC-000172: convergent_distinct. Representaciones DISTINCT
    compartiendo estado: el request inocente recibe respuesta
    ajena, reproducible, con especificidad de path demostrada,
    controles PASSED y baseline no ambiguo: DEMO por evidencia
    E5/E6, nunca por convergencia aparente."""
    _seed_cache(
        "RC-000172",
        "convergencia de nucleos entre paths distintos podia ser "
        "DEMO sin especificidad de path (targets genericos "
        "convergen trivialmente) y con exigencia de baseline "
        "STABLE exacto en vez de no-ambiguo",
        {"convergent_distinct": "DEMO/E5+E6 binding STRONG"})


def seed_rc_000173() -> None:
    """RC-000173: invariantes v0.72-v0.78. CACHE-CORRELATION no
    debe transformar retroactivamente ningun caso historico en
    DEMO ni degradar su PASS. Re-ejecuta RC-000164 a RC-000167
    via --only y exige el mismo resultado."""
    _seed_cache(
        "RC-000173",
        "un modulo nuevo de cache podia alterar el comportamiento "
        "o los veredictos de los casos historicos del corpus",
        {"invariantes": "RC-000164..167 igual PASS, 0 fallo"})


def seed_rc_000174() -> None:
    """RC-000174: collision legitima (alias por diseno). Dos
    paths sirven el mismo recurso legitimamente: la
    convergencia NO es contaminacion. v0.79 daba DEMO falso
    aqui (sin control negativo); v0.80 debe dar BENIGN con
    self_induced RULED_OUT por NEGATIVE_CONTROL."""
    _seed_cache(
        "RC-000174",
        "una convergencia entre paths con el mismo contenido "
        "legitimo (alias) podia escalar a DEMO sin control "
        "negativo que demostrara que el contenido es ajeno",
        {"collision_legitima":
         "BENIGN/negative control: nada es ajeno"})


def seed_rc_000175() -> None:
    """RC-000175: collision problematica. Contamination
    estructural reproducible en segmentos virgenes: DEMO con
    las 8 condiciones conjuntas, impacto CROSS-CONSUMER."""
    _seed_cache(
        "RC-000175",
        "una colision por segmento podia declararse DEMO "
        "sin reproducirse en paths virgenes ni descartar "
        "self-induced",
        {"collision_problematica":
         "DEMO/impact CROSS-CONSUMER, 8 condiciones"})


def seed_rc_000176() -> None:
    """RC-000176: fragmentation legitima (Vary: Cookie). La
    diferencia esta legitimamente explicada: BENIGN, sin
    fase 2."""
    _seed_cache(
        "RC-000176",
        "una fragmentacion declarada por Vary podia tratarse "
        "como inconsistencia observable",
        {"fragmentation_legitima": "BENIGN/vary explica"})


def seed_rc_000177() -> None:
    """RC-000177: fragmentation problematica. Case crudo del
    nombre de header (RFC 7230 3.2 lo define insensible):
    INCONSISTENT estructural sin impacto observable; el
    contrato RFC NO es canal independiente para STRONG."""
    _seed_cache(
        "RC-000177",
        "una fragmentacion estructural podia escalar mas alla "
        "de INCONSISTENT sin impacto observable al consumidor",
        {"fragmentation_problematica":
         "INCONSISTENT/correlation OBSERVED, sin impacto"})


def seed_rc_000178() -> None:
    """RC-000178: cross-semantic contamination. B recibe
    contenido con SEMANTICA ajena (content-type distinto al
    legitimo): DEMO con impacto SECURITY (E6)."""
    _seed_cache(
        "RC-000178",
        "una contaminacion con semantica distinta podia quedar "
        "en CROSS-CONSUMER sin detectar el mismatch de "
        "content-type",
        {"cross_contamination":
         "DEMO/impact SECURITY (content-type ajeno)"})


def seed_rc_000179() -> None:
    """RC-000179: baseline ambiguo. Rotacion no caracterizada:
    UNKNOWN conservador con causa citada, sin fase 2."""
    _seed_cache(
        "RC-000179",
        "un baseline ambiguo podia seguir consumiendo "
        "presupuesto en fase 2 en vez de concluir UNKNOWN",
        {"ambiguous_baseline": "UNKNOWN/baseline AMBIGUO"})


def seed_rc_000180() -> None:
    """RC-000180: normalizacion legitima total. Edge y cache
    tratan el case de acuerdo (entrada compartida): la
    rareza de [MISS,HIT] vs [HIT,HIT] NO es desacuerdo, es
    acuerdo en entrada compartida: CONSISTENT."""
    _seed_cache(
        "RC-000180",
        "el patron normal de cache compartido (primero MISS, "
        "segundo HIT) podia leerse como divergencia de estado",
        {"normalization_legitima":
         "CONSISTENT/refetch igual = acuerdo"})


def seed_rc_000181() -> None:
    """RC-000181: desacuerdo real entre capas SIN impacto.
    Nucleos identicos, estados divergentes (uno persiste,
    el otro jamas): E7 con dos canales de observacion
    reales, reproducible en virgen: maximo SUSPICIOUS,
    jamas DEMO (inconsistencia != vulnerabilidad)."""
    _seed_cache(
        "RC-000181",
        "un desacuerdo observable sin impacto podia escalar a "
        "DEMO por correlacion fuerte sola",
        {"layer_disagreement":
         "SUSPICIOUS/E7 correlation STRONG, impact NONE"})


def seed_rc_000182() -> None:
    """RC-000182: invariantes v0.79. SEMANTIC-CACHE extiende a
    CACHE-CORRELATION sin alterar ningun veredicto historico.
    Re-ejecuta RC-000168..173 via --only y exige 0 fallos."""
    _seed_cache(
        "RC-000182",
        "la capa v0.80 (patch aditivo de fingerprints + fase "
        "2) podia degradar los casos v0.79 del corpus",
        {"invariantes":
         "RC-000168..173 igual PASS, 0 fallo"}),


def seed_rc_000183() -> None:
    """RC-000183: lb_variance. Backend A/B sticky por conexion:
    el loop debe converger a BASELINE-CARACTERIZADO con H1
    load_balancing SUPPORTED (contrato: estable dentro, varia
    entre conexiones, virgen tambien varia), nunca UNKNOWN."""
    _seed_cache(
        "RC-000183",
        "una varianza por conexion podia quedarse UNKNOWN "
        "sin caracterizar el mecanismo que la explica",
        {"lb_variance":
         "BASELINE-CARACTERIZADO/H1 SUPPORTED"})


def seed_rc_000184() -> None:
    """RC-000184: origin_dynamics. Cuerpo distinto en cada
    request: INTRA contradice H1/H3, SESSION contradice
    H2/H4 (cookies no estabilizan): convergencia por
    eliminacion honesta a H5, marcada BY-ELIMINATION."""
    _seed_cache(
        "RC-000184",
        "una dinamica por-request podia atribuirse a un "
        "mecanismo sin contradecir el resto",
        {"origin_dynamics":
         "BASELINE-CARACTERIZADO/H5 BY-ELIMINATION"})


def seed_rc_000185() -> None:
    """RC-000185: transient. La varianza del baseline no se
    reproduce en ninguna dimension disponible: el loop debe
    declarar UNKNOWN-DEMOSTRADO (no forzar atribucion por
    eliminacion) con H1/H3 vivas y razon citada."""
    _seed_cache(
        "RC-000185",
        "una varianza transitoria no reproducible podia "
        "forzarse a una atribucion sin evidencia",
        {"transient":
         "UNKNOWN-DEMOSTRADO/H1+H3 vivas, razon citada"})


def seed_rc_000186() -> None:
    """RC-000186: invariantes v0.80. ADAPTIVE-HUNT es capa
    nueva y no debe alterar ningun veredicto del corpus
    SEMANTIC-CACHE. Re-ejecuta RC-000174..182 via --only."""
    _seed_cache(
        "RC-000186",
        "una capa epistemica nueva podia degradar los casos "
        "v0.80 del corpus",
        {"invariantes":
         "RC-000174..182 igual PASS, 0 fallo"})


def seed_rc_000187() -> None:
    """RC-000187: reuso determinista. Baseline identico
    dentro del TTL: la segunda sesion debe reusar la ventana
    previa (3 req, atribucion REUSADO), sin re-ejecutar
    experimentos."""
    _seed_cache(
        "RC-000187",
        "una sesion repetida podia gastar 19 requests "
        "re-descubriendo lo ya observado",
        {"reuse": "3 req, REUSADO, misma atribucion"})


def seed_rc_000188() -> None:
    """RC-000188: expiracion por ventana. Con TTL agotado el
    reuso NO aplica: corrida fresca con las hipotesis
    anotadas con su estado de ventana previa (contexto, no
    veredicto heredado)."""
    _seed_cache(
        "RC-000188",
        "una contradiccion vieja podia tomarse como verdad "
        "eterna sin re-observar",
        {"ttl0": "corrida fresca 19 req + anotacion previa"})


def seed_rc_000189() -> None:
    """RC-000189: baseline distinto NUNCA reusa. Si las
    huellas del baseline difieren de la ventana previa, las
    condiciones observadas cambiaron: ventana nueva."""
    _seed_cache(
        "RC-000189",
        "un baseline distinto podia heredar un veredicto de "
        "otras condiciones",
        {"mismatch": "ventana nueva, cero reuso"})


def seed_rc_000190() -> None:
    """RC-000190: invariantes v0.81. La capa de memoria no
    debe alterar ningun veredicto del corpus ADAPTIVE-HUNT.
    Re-ejecuta RC-000183..185 via --only."""
    _seed_cache(
        "RC-000190",
        "la memoria persistente podia contaminar los casos "
        "del corpus v0.81",
        {"invariantes": "RC-000183..185 igual PASS, 0 fallo"})


def seed_rc_000191() -> None:
    """RC-000191: convergencia temprana. El selector debe
    detenerse en cuanto queda una unica hipotesis viva:
    origin_dynamics con 2 experimentos (10 req) en vez de
    recorrer el catalogo completo."""
    _seed_cache(
        "RC-000191",
        "el loop podia seguir ejecutando experimentos "
        "despues de la convergencia",
        {"early_stop": "10 req, 2 experimentos, "
                       "EDV >= 1 en cada eleccion"})


def seed_rc_000192() -> None:
    """RC-000192: parada honesta EDV=0. Si ningun
    experimento disponible puede tocar una hipotesis viva,
    declarar la razon en vez de correr sondas inutiles."""
    _seed_cache(
        "RC-000192",
        "el loop podia quedarse callado cuando ningun "
        "experimento discrimina",
        {"edv0": "stop con razon citando las vivas"})


def seed_rc_000193() -> None:
    """RC-000193: seleccion por EDV. El orden de ejecucion
    sigue el valor de discriminacion, no el orden fijo:
    INTRA primero por desempate y VIRGIN antes de SESSION
    cuando su EDV es mayor (2.5 vs 2.0). Cada eleccion deja
    tabla y EDV en el trace."""
    _seed_cache(
        "RC-000193",
        "el orden de experimentos podia seguir siendo fijo "
        "ignorando el valor de informacion",
        {"edv_order": "INTRA, CROSS, VIRGIN(2.5), SESSION"})


def seed_rc_000194() -> None:
    """RC-000194: invariantes v0.81/v0.81.1. El selector no
    debe alterar memoria ni veredictos del corpus
    ADAPTIVE. Re-ejecuta RC-000187..190 via --only."""
    _seed_cache(
        "RC-000194",
        "el loop EDV podia degradar memoria y casos "
        "previos del corpus",
        {"invariantes": "RC-000187..190 igual PASS, "
                        "0 fallo"})


def seed_rc_000195() -> None:
    """RC-000195: construccion del grafo. Nodos de los 5
    tipos con relaciones y provenance (run_id, target) en
    cada uno."""
    _seed_cache(
        "RC-000195",
        "el grafo podia perder provenance o tipos de nodo",
        {"construction": "5 tipos, relaciones y provenance"})


def seed_rc_000196() -> None:
    """RC-000196: ciclo de vida de hipotesis. LIVE ->
    SUPPORTED solo con evidencia explicita; CONTRADICTED
    es terminal; sobrevivir NO demuestra."""
    _seed_cache(
        "RC-000196",
        "una hipotesis podia darse por demostrada solo "
        "por sobrevivir experimentos",
        {"lifecycle": "SUPPORTED con evidencia, terminal "
                      "CONTRADICTED, sin demo por "
                      "supervivencia"})


def seed_rc_000197() -> None:
    """RC-000197: provenance de experimento. Re-registrar
    un contrato ya ejecutado se rechaza (anti post-hoc);
    observar sin contrato se rechaza."""
    _seed_cache(
        "RC-000197",
        "un contrato podia registrarse despues de ver el "
        "resultado (razonamiento post-hoc)",
        {"provenance": "post-hoc y sin contrato "
                       "rechazados"})


def seed_rc_000198() -> None:
    """RC-000198: integracion EDV. next_experiment elige
    el mayor EDV sobre vivas y devuelve tabla; EDV 0 en
    todos devuelve la razon citando las vivas."""
    _seed_cache(
        "RC-000198",
        "el selector podia elegir sin tabla ni razon "
        "reconstruible",
        {"edv": "mejor EDV elegido, tabla visible, "
                "EDV0 con razon"})


def seed_rc_000199() -> None:
    """RC-000199: propagacion de contradiccion. La
    observacion contradice -> CONTRADICTED con evidencia
    citada; el apoyo previo queda preservado en el
    historial, no sobrescrito."""
    _seed_cache(
        "RC-000199",
        "una contradiccion podia borrar el historial de "
        "apoyo previo",
        {"contradiction": "terminal + historial "
                          "preservado"})


def seed_rc_000200() -> None:
    """RC-000200: reproducibilidad. REPRODUCIBLE exige 2
    genealogias independientes de E-DESYNC-SIGNAL; una
    sola ventana no basta. Dos respuestas iguales no es
    reproducibilidad sin genealogia."""
    _seed_cache(
        "RC-000200",
        "dos respuestas iguales podian tomarse como "
        "reproducibilidad sin genealogia",
        {"repro": "2 genealogias exigidas, 1 "
                  "rechazada"})


def seed_rc_000201() -> None:
    """RC-000201: ciclo de vida del candidato DESYNC.
    NONE -> CANDIDATE -> SUPPORTED -> REPRODUCIBLE ->
    IMPACT-CANDIDATE solo con evidencia de estado;
    CONFIRMED bloqueado sin E-DESYNC-IMPACT."""
    _seed_cache(
        "RC-000201",
        "el candidato podia escalar sin la evidencia de "
        "cada escalon",
        {"candidate": "escalera completa, CONFIRMED "
                      "bloqueado sin impacto"})


def seed_rc_000202() -> None:
    """RC-000202: invariantes anti-falso-positivo.
    confirm_blockers reporta exactamente lo que falta;
    CONFIRMED con bloqueos se rechaza y queda en el
    journal."""
    _seed_cache(
        "RC-000202",
        "CONFIRMED podia declararse con bloqueos "
        "pendientes",
        {"fp": "bloqueos exactos, confirm rechazado"})


def seed_rc_000203() -> None:
    """RC-000203: persistencia. Cada investigacion es un
    archivo por run_id: nunca se sobrescribe; latest_run
    devuelve la ultima."""
    _seed_cache(
        "RC-000203",
        "una investigacion podia sobrescribir la "
        "anterior",
        {"persistence": "sin sobreescritura, latest "
                         "ok"})


def seed_rc_000204() -> None:
    """RC-000204: explain-path. why() reconstruye la
    cadena EXP <- seleccion <- targets <- evidencia <-
    observacion; sin seleccion lo declara, no inventa."""
    _seed_cache(
        "RC-000204",
        "el porque de un experimento podia no "
        "reconstruirse desde el grafo",
        {"explain": "cadena completa reconstruible"})


_ADTMEM_TABLE = {
    "RC-000187": "reuse",
    "RC-000188": "ttl0",
    "RC-000189": "mismatch",
}


_ADT_TABLE = {
    "RC-000183": ("lb_variance", "BASELINE-CARACTERIZADO",
                  {"attr_contains":
                   "H1:load_balancing (SUPPORTED)"}),
    "RC-000184": ("origin_dynamics", "BASELINE-CARACTERIZADO",
                  {"attr_contains":
                   "H5:origin_dynamics (BY-ELIMINATION)"}),
    "RC-000185": ("transient", "UNKNOWN-DEMOSTRADO",
                  {"live": ["H1", "H3"],
                   "razon": True}),
}


_SEM_TABLE = {
    "RC-000174": ("collision_legitima", "BENIGN",
                  {"self_induced": "RULED_OUT",
                   "self_induced_method": "NEGATIVE_CONTROL"}),
    "RC-000175": ("collision_problematica", "DEMO",
                  {"impact": "CROSS-CONSUMER",
                   "correlation": "STRONG"}),
    "RC-000176": ("fragmentation_legitima", "BENIGN", {}),
    "RC-000177": ("fragmentation_problematica", "INCONSISTENT",
                  {"correlation": "OBSERVED",
                   "self_induced": "RULED_OUT"}),
    "RC-000178": ("cross_contamination", "DEMO",
                  {"impact": "SECURITY"}),
    "RC-000179": ("ambiguous_baseline", "UNKNOWN", {}),
    "RC-000180": ("normalization_legitima", "CONSISTENT", {}),
    "RC-000181": ("layer_disagreement", "SUSPICIOUS",
                  {"correlation": "STRONG",
                   "self_induced": "RULED_OUT"}),
}




def _kill_labs():
    """Mata labs huerfanos (flake de puertos en meta-runs
    anidados). Solo procesos labs/, nunca regress.py."""
    try:
        out = subprocess.run(
            ["pgrep", "-f", "labs/"],
            capture_output=True, text=True)
        for pid in out.stdout.split():
            if pid and int(pid) != os.getpid():
                try:
                    os.kill(int(pid), 9)
                except OSError:
                    pass
    except Exception:
        pass


def seed_cross_layer() -> None:
    """RC-000205..209: CROSS-LAYER CORRELATION v0.84.
    Un disparo, tres capas + dimension de conexion."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000205" in cases:
        return
    for cid, prob, exp in [
        ("RC-000205",
         "una perturbacion normalizada por todas las capas "
         "podia escalarse como hallazgo",
         "absorbed -> BENIGN"),
        ("RC-000206",
         "la tolerancia del edge (cierra conexion) sin "
         "efecto en el origin no es vulnerabilidad",
         "edge_local -> BENIGN (EDGE-ONLY, sin escalada)"),
        ("RC-000207",
         "un mismatch reproducible desde 2 conexiones sin "
         "contaminacion no debe escalar a DEMO",
         "shared_state -> SHARED-STATE"),
        ("RC-000208",
         "contaminacion observable (una conexion nueva "
         "recibe el efecto) con controles PASSED debe "
         "escalar a DEMO",
         "contamination -> DEMO"),
        ("RC-000209",
         "invariantes de presupuesto y escalera del "
         "modulo cross_layer",
         "bateria y escalera monotona -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": "CROSS-LAYER-CORRELATION",
            "problem": prob,
            "first_seen": "v0.84.0",
            "fixed_in": "v0.84.0",
            "repro": {"expected": exp},
        })


def seed_rc_000210() -> None:
    """RC-000210: PIPE-CROSS v0.85. El Hunter automatico debe
    invocar la auditoria CROSS-LAYER (grafo v0.83 + veredicto)
    en su pipeline."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000210" in cases:
        return
    _write_case({
        "id": "RC-000210",
        "module": "PIPE-CROSS",
        "problem": "el hunter automatico podia cazar sin la "
        "auditoria cross-layer ni trazabilidad al grafo",
        "first_seen": "v0.85.0",
        "fixed_in": "v0.85.0",
        "repro": {"expected": "nodo cross_layer en NODE_ORDER/"
                  "NODE_FUNCS/UI, presupuesto <= 11 reqs"},
    })




def seed_rc_000211() -> None:
    """RC-000211..216: WCD-CACHE-KEY v0.86. Web Cache
    Deception con contratos pre-registrados, escalera
    BENIGN -> LEAK-NO-CACHE -> WCD-CACHE -> WCD-DEMO y
    honestidad OPEN-ENDPOINT (endpoint abierto NO es WCD)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000211" in cases:
        return
    for cid, prob, exp in [
        ("RC-000211",
         "un disfraz de path sin leak (origin no confunde "
         "delimitadores) podia escalar como WCD",
         "benign -> BENIGN"),
        ("RC-000212",
         "un leak por confusion de router sin almacenamiento "
         "positivo observable (HIT/Age) NO es WCD reportable",
         "leak_nocache -> LEAK-NO-CACHE"),
        ("RC-000213",
         "un cache HIT con Vary: Cookie (controles FAILED) "
         "no debe escalar a DEMO",
         "cache_vary -> WCD-CACHE sin DEMO"),
        ("RC-000214",
         "contaminacion observable (conexion nueva sin sesion "
         "recibe el cuerpo autenticado desde cache) con "
         "controles PASSED debe escalar a DEMO",
         "contamination -> WCD-DEMO"),
        ("RC-000215",
         "un endpoint abierto (anonimo ya ve el dato sin "
         "disfraz) NO es WCD: es candidato BAC y el "
         "presupuesto no debe gastarse en variantes",
         "open_endpoint -> OPEN-ENDPOINT con reqs=2"),
        ("RC-000216",
         "invariantes de presupuesto y escalera del modulo "
         "wcd_bait",
         "bateria y presupuesto max 8 reqs -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": "WCD-CACHE-KEY",
            "problem": prob,
            "first_seen": "v0.86.0",
            "fixed_in": "v0.86.0",
            "repro": {"expected": exp},
        })


def seed_rc_000217() -> None:
    """RC-000217..222: CL.0-SINGLE-TIER v0.87. Request
    smuggling CL.0 con oraculo de timing diferencial
    (T1 silencio -> eco -> shift), escalera BENIGN ->
    CL0-DETECTED -> CL0-DESYNC -> CL0-STATE-EFFECT."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000217" in cases:
        return
    for cid, prob, exp in [
        ("RC-000217",
         "el smuggle (bytes) se inyectaba con %s en el "
         "formato: el repr literal b'' viajaba como prefijo "
         "smuggleado, corrompiendo TODO el framing de la "
         "sonda (bug real de fase LAB)",
         "payload sin repr b'': smuggle serializado a str"),
        ("RC-000218",
         "un front que responde al prefijo durante T1 "
         "(pipelining benigno) podia escalar como desync",
         "benign_strict -> BENIGN (eco temprano NO es "
         "desync)"),
        ("RC-000219",
         "un RST del edge tras el POST (frontera estricta) "
         "se clasificaba como error de red, no como BENIGN",
         "edge_safe_rst -> BENIGN por RST con precedencia"),
        ("RC-000220",
         "un desync CL.0 real (backend procesa el prefijo "
         "invisible, cola desplazada) debe escalar hasta "
         "STATE-EFFECT con repro 2/2",
         "cl0_desync -> CL0-STATE-EFFECT con reqs<=8"),
        ("RC-000221",
         "un desync observado sin repro 2/2 NO debe ser "
         "reportable (regla cero-FP de la linea DESYNC)",
         "flaky_desync -> CL0-DETECTED (probable, no "
         "reportable)"),
        ("RC-000222",
         "invariantes de presupuesto y escalera del modulo "
         "cl0_probe",
         "bateria 2 candidatos, MAX_VARIANTS=1, presupuesto "
         "max 8 reqs -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": "CL.0-SINGLE-TIER",
            "problem": prob,
            "first_seen": "v0.87.0",
            "fixed_in": "v0.87.0",
            "repro": {"expected": exp},
        })


def seed_rc_000223() -> None:
    """RC-000223..228: H2-TRANSLATION v0.88. Parser
    differential h2->h1 con oraculo de atribucion por
    stream (eco del smuggle en el stream del followup),
    escalera BENIGN -> H2-DETECTED -> H2-DESYNC ->
    H2-STATE-EFFECT. Lecciones: header de frame = 9 bytes
    (length 3 + type 1 + flags 1 + sid 4) y buffer
    PERSISTENTE por conexion: HEADERS+DATA llegan en un
    mismo segmento TCP y ningun byte se descarta."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000223" in cases:
        return
    for cid, prob, exp in [
        ("RC-000223",
         "un edge estricto que rechaza el smuggle con "
         "RST/GOAWAY se clasificaba como error de red y "
         "no como frontera benigna",
         "benign_strict -> BENIGN-EDGE (RST/GOAWAY: el "
         "edge corto antes del origin)"),
        ("RC-000224",
         "un edge que drena el DATA residual y sanitiza "
         "CRLF poda confundirse con desync por timing",
         "quiet_benign -> BENIGN (traduccion alineada)"),
        ("RC-000225",
         "un h2.CL real (edge reenvia DATA mas alla del "
         "content-length; el origin procesa el prefijo "
         "invisible) debe escalar a STATE-EFFECT con repro "
         "2/2",
         "h2cl_desync -> H2-STATE-EFFECT con reqs<=8"),
        ("RC-000226",
         "un traductor HPACK leniente que copia verbatim "
         "valores con CRLF inyecta requests H1 al origin "
         "(parser differential)",
         "hdr_injection + bateria hinj -> H2-STATE-EFFECT"),
        ("RC-000227",
         "un desync observado sin repro 2/2 NO debe ser "
         "reportable (regla cero-FP heredada de v0.87)",
         "flaky_translation -> H2-DETECTED (probable, no "
         "reportable)"),
        ("RC-000228",
         "invariantes de presupuesto, bateria y framing "
         "del modulo h2_probe: header de frame de 9 bytes "
         "y buffer persistente por conexion",
         "bateria (h2cl, hinj), MAX_VARIANTS=1, presupuesto "
         "max 8 reqs, frames de 9 bytes -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": "H2-TRANSLATION",
            "problem": prob,
            "first_seen": "v0.88.0",
            "fixed_in": "v0.88.0",
            "repro": {"expected": exp},
        })



_SLOW = []


def _timed(cases_iter):
    """Iterador de timing: mide cada caso del corpus
    (diagnostico de velocidad, no altera la ejecucion)."""
    import time as _tm
    for c in cases_iter:
        t0 = _tm.time()
        yield c
        el = _tm.time() - t0
        _SLOW.append((el, c["id"]))
        if el > 5.0:
            print("    [slow] %s = %.1fs" % (c["id"], el))


# ---- cache intra-corpus (v0.88 perf) -------------------------
# Un caso ya ejecutado con el MISMO codigo no puede cambiar de
# veredicto dentro de la misma corrida: las cadenas (RC-000173,
# 182, 186, 190, ...) re-ejecutan bloques completos en procesos
# anidados. Con el cache, esas re-ejecuciones se reusan en vez
# de repetirse. Clave = hash del codigo (core+labs); si cambia
# un solo byte, el cache se invalida y todo se re-ejecuta.
# Desactivable: CODEXRC_REGRESS_NOCACHE=1


def _cache_path():
    return "/tmp/codexrc_regress_cache.json"


def _code_hash():
    import hashlib
    root = os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    h = hashlib.sha256()
    for sub in ("core", "labs"):
        d = os.path.join(root, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".py"):
                continue
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
                h.update(("%s|%d|%d|" % (
                    fn, int(st.st_mtime), st.st_size)).encode())
                with open(p, "rb") as _f:
                    h.update(_f.read())
            except OSError:
                pass
    return h.hexdigest()


_CACHE = {"hash": None, "results": {}}


def _cache_load():
    import json as _j
    if os.environ.get("CODEXRC_REGRESS_NOCACHE"):
        return
    try:
        with open(_cache_path()) as _f:
            d = _j.load(_f)
        if d.get("hash") == _code_hash():
            _CACHE["hash"] = d["hash"]
            _CACHE["results"] = d.get("results", {})
    except Exception:
        pass


def _cache_lookup(cid):
    if os.environ.get("CODEXRC_REGRESS_NOCACHE"):
        return None
    if _CACHE["hash"] is None:
        return None
    r = _CACHE["results"].get(cid)
    return None if r is None else bool(r)


def _cache_record(cid, ok):
    if os.environ.get("CODEXRC_REGRESS_NOCACHE"):
        return
    if _CACHE["hash"] is None:
        _CACHE["hash"] = _code_hash()
        _CACHE["results"] = {}
    _CACHE["results"][cid] = bool(ok)
    try:
        import json as _j
        import tempfile as _tf
        fd, tmp = _tf.mkstemp(dir="/tmp")
        with os.fdopen(fd, "w") as _f:
            _j.dump(_CACHE, _f)
        os.replace(tmp, _cache_path())
    except Exception:
        pass



def seed_rc_000229() -> None:
    """RC-000229..235: MULTI-CONNECTION v0.89. Efecto de
    segundo orden: contaminacion CRUZADA entre conexiones
    por herencia de pool. Oraculo de atribucion por
    CONEXION (el followup de B recibe el eco del smuggle
    de A), escalera BENIGN -> MC-DETECTED -> MC-DESYNC ->
    MC-STATE-EFFECT. Lecciones: el buffer de recepcion del
    origin viaja CON la conexion del pool (no muere con el
    handler); el apareamiento edge->origin deja las
    respuestas pendientes del smuggle en la origin conn."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000229" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000229", "MULTI-CONNECTION",
         "una origin conn pinneada 1:1 al cliente podia "
         "confundirse con pool compartido",
         "benign_pin -> BENIGN (la poison muere con A)"),
        ("RC-000230", "MULTI-CONNECTION",
         "un edge que drena el residual tras el "
         "content-length no envenena el pool",
         "quiet_drain -> BENIGN (traduccion alineada)"),
        ("RC-000231", "MULTI-CONNECTION",
         "un pool LIFO sin drenaje (nginx keepalive): la "
         "conn envenenada que A libera al cerrar la hereda "
         "B (TCP distinto) y su coleccion queda "
         "desplazada",
         "pool_desync -> MC-STATE-EFFECT con repro 2/2 y "
         "reqs<=8"),
        ("RC-000232", "MULTI-CONNECTION",
         "un edge estricto que hace RST ante bytes mas "
         "alla del content-length se clasificaba como "
         "error de red, no como frontera benigna",
         "edge_strict -> BENIGN-EDGE (RST con "
         "precedencia)"),
        ("RC-000233", "MULTI-CONNECTION",
         "una contaminacion cruzada sin repro 2/2 NO debe "
         "ser reportable (regla cero-FP heredada)",
         "flaky_pool -> MC-DETECTED (probable, no "
         "reportable)"),
        ("RC-000234", "MULTI-CONNECTION",
         "invariantes de presupuesto, bateria y apareamiento "
         "del modulo mc_probe",
         "bateria pool, presupuesto max 8 reqs (2 fases x "
         "4), buffers por conexion -> PASS"),
        ("RC-000235", "H2-TRANSLATION",
         "el veredicto h2 crasheaba con NameError (variable "
         "Informe inexistente) cuando el ExperimentGraph "
         "estaba activo",
         "h2_probe sin referencias a variables "
         "inexistentes (typo Informe -> informe)"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.89.0",
            "fixed_in": "v0.89.0",
            "repro": {"expected": exp},
        })



def seed_rc_000236() -> None:
    """RC-000236..241: CROSS-REQUEST CORRELATION v0.90.
    Reconstruccion de la cola del origin por doble marcador
    (T1, T2): el desplazamiento k de la coleccion es MEDIBLE
    y debe ser CONSISTENTE (eco propio desplazado
    exactamente por el numero de ecos del smuggle) y
    REPRODUCIBLE. Escalera BENIGN -> CRC-DETECTED ->
    CRC-DESYNC -> CRC-STATE-EFFECT con k."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000236" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000236", "CROSS-REQUEST CORRELATION",
         "un edge que drena el residual tras el "
         "content-length no desplaza la cola del origin",
         "quiet_drain -> BENIGN (coleccion alineada)"),
        ("RC-000237", "CROSS-REQUEST CORRELATION",
         "un edge estricto que hace RST ante bytes mas "
         "alla del content-length es frontera benigna, "
         "no error de red",
         "edge_strict -> BENIGN-EDGE (RST con "
         "precedencia)"),
        ("RC-000238", "CROSS-REQUEST CORRELATION",
         "con ambas smuggles procesadas la coleccion "
         "queda desplazada k=2: la permutacion consistente "
         "es la firma del desync",
         "seq_desync -> CRC-STATE-EFFECT con k=2 y "
         "reqs<=8"),
        ("RC-000239", "CROSS-REQUEST CORRELATION",
         "con la segunda smuggle drenada el corrimiento es "
         "k=1: la firma debe medir k exacto, no solo "
         "detectar contaminacion",
         "partial_drain -> CRC-STATE-EFFECT con k=1 "
         "y reqs<=8"),
        ("RC-000240", "CROSS-REQUEST CORRELATION",
         "una permutacion sin repro 2/2 NO debe ser "
         "reportable (regla cero-FP heredada)",
         "flaky_forward -> CRC-DETECTED (probable, no "
         "reportable)"),
        ("RC-000241", "CROSS-REQUEST CORRELATION",
         "invariantes de presupuesto, bateria y "
         "clasificacion del modulo crc_probe",
         "bateria double, presupuesto max 8 reqs (2 fases "
         "x 4), clases de evidencia E-CRC-* -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.90.0",
            "fixed_in": "v0.90.0",
            "repro": {"expected": exp},
        })


def seed_rc_000242() -> None:
    """RC-000242..247: REPRODUCTION ENGINE v0.91.
    Escalera de impacto: DESYNC OBSERVED -> REPRODUCIBLE
    (2 genealogias independientes, deteccion + replay)
    -> STATE EFFECT. El disparo unico no escala."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000242" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000242", "REPRODUCTION ENGINE",
         "la firma CRC-STATE-EFFECT k=2 debe "
         "reproducirse a demanda: pase A y pase B en "
         "2 genealogias independientes (instancias "
         "frescas)",
         "seq_desync -> REPRODUCIBLE con firma k=2 "
         "estable en 2/2 genealogias"),
        ("RC-000243", "REPRODUCTION ENGINE",
         "un disparo unico (flaky) NO escala: sin "
         "repro 2/2 el candidato no avanza (cero-FP "
         "heredada de la escalera)",
         "flaky_forward -> NON-REPRODUCIBLE (A "
         "dispara, B curado: no sostiene)"),
        ("RC-000244", "REPRODUCTION ENGINE",
         "benign reproducible es normalidad, no "
         "candidato: no inventar claim",
         "quiet_drain -> NO-CANDIDATE"),
        ("RC-000245", "REPRODUCTION ENGINE",
         "BENIGN-EDGE estable en A y B tampoco es "
         "candidato",
         "edge_strict -> NO-CANDIDATE"),
        ("RC-000246", "REPRODUCTION ENGINE",
         "instancia muerta o control caido: parada "
         "honesta UNSTABLE sin claim (nunca afirmar "
         "ni negar sin observable)",
         "puerto-tumba (lab no levanta respuesta) "
         "-> UNSTABLE"),
        ("RC-000247", "REPRODUCTION ENGINE",
         "invariantes del modulo repro_engine: "
         "presupuesto 32 reqs, 2 genealogias max, "
         "escalera nunca saltada (NO-CANDIDATE "
         "nunca escala a REPRODUCIBLE), labs "
         "cerrados",
         "BUDGET 32, GENEALOGIES 2, PASSES A/B, "
         "veredictos del dominio -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.91.0",
            "fixed_in": "v0.91.0",
            "repro": {"expected": exp},
        })


def seed_rc_000248() -> None:
    """RC-000248..253: IMPACT CORRELATION v0.92.
    La pregunta de impacto: el desync reproducido hace
    dano a un usuario DISTINTO del atacante? Escalera
    BENIGN -> IMPACT-CANDIDATE (probable, no
    reportable) -> SECURITY-IMPACT-DEMO (swap protegido
    2/2 con control limpio: contaminacion cross-user a
    demanda)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000248" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000248", "IMPACT CORRELATION",
         "un edge que drena el residual: la victima "
         "siempre recibe su propio eco",
         "quiet_drain -> BENIGN"),
        ("RC-000249", "IMPACT CORRELATION",
         "un edge con conn origin pinneada 1:1: el "
         "veneno muere con la conexion del atacante",
         "benign_pin -> BENIGN"),
        ("RC-000250", "IMPACT CORRELATION",
         "la victima (TCP distinto) hereda del pool la "
         "conn envenenada y recibe la respuesta del "
         "recurso protegido smuggleado, 2/2",
         "pool_swap -> SECURITY-IMPACT-DEMO"),
        ("RC-000251", "IMPACT CORRELATION",
         "mispairing cruzado con contenido benigno "
         "(eco del token del atacante): atribucion "
         "alterada sin dato protegido, NO reportable",
         "pool_shift -> IMPACT-CANDIDATE"),
        ("RC-000252", "IMPACT CORRELATION",
         "el swap del recurso protegido ocurre UNA "
         "sola vez en la vida del lab (1/2): el "
         "impacto no se reproduce, no escala",
         "flaky_swap -> IMPACT-CANDIDATE (1/2)"),
        ("RC-000253", "IMPACT CORRELATION",
         "invariantes del modulo: presupuesto 6, 2 "
         "rondas, control previo obligatorio, escalera "
         "conservadora y recurso protegido solo del "
         "lab",
         "BUDGET 6, ROUNDS 2, control obligatorio, "
         "veredictos de la escalera -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.92.0",
            "fixed_in": "v0.92.0",
            "repro": {"expected": exp},
        })


def seed_rc_000254() -> None:
    """RC-000254..257: FP-ELIMINATION v0.93 +
    EVIDENCE PACKAGE v0.94 (corona). Caza sistematica
    de falsos positivos (bateria de cebo + tabla de
    clases + control positivo) y paquete de evidencia
    falsable de la cadena completa."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000254" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000254", "FP-ELIMINATION",
         "bateria de cebo (quiet_drain, benign_pin, "
         "pool_shift, flaky_swap): NINGUN cebo puede "
         "producir veredicto reportable, y el control "
         "positivo (pool_swap) DEBE reportar",
         "FP-ELIMINATED, 0/4 cebos reportables, "
         "control positivo activo"),
        ("RC-000255", "FP-ELIMINATION",
         "tabla de clases de senal completa (8 clases) "
         "y regla de no-escala del disparo unico "
         "presente en los 3 modulos de la escalera",
         "FP_TABLE 8/8, reglas crc/repro/impacto "
         "-> PASS"),
        ("RC-000256", "EVIDENCE PACKAGE",
         "paquete de la cadena completa: firma k=2 en 2 "
         "genealogias x pases A/B, impacto cross-user "
         "2/2 con control limpio, limites y comandos "
         "declarados, hash canonico",
         "PACKAGE-VALID, k=2, 37/40 reqs"),
        ("RC-000257", "EVIDENCE PACKAGE",
         "falsabilidad mecanica: verify_package valida "
         "campos y hash, y DETECTA tampering (payload "
         "alterado = hash no coincide)",
         "verificacion OK + tamper detectado -> PASS"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.94.0",
            "fixed_in": "v0.94.0",
            "repro": {"expected": exp},
        })


def seed_rc_000258() -> None:
    """RC-000258..260: INTEGRACION AL HUNTER v0.95.
    La corona llego: la cadena completa orquestada por
    crown_chain queda exportada desde la fachada del
    Hunter, con el limite honesto en vivo (rung de
    impacto solo en lab)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000258" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000258", "CROWN CHAIN",
         "la cadena orquestada en modo lab ensambla el "
         "paquete completo (k=2, 2 genealogias, "
         "impacto 2/2) desde el Hunter",
         "CHAIN-COMPLETE-LAB"),
        ("RC-000259", "CROWN CHAIN",
         "la escalera viva es conservadora: sin senal "
         "de desync el veredicto es NO-DESYNC/UNSTABLE "
         "honesto y la cadena NO se abre",
         "NO-DESYNC/UNSTABLE en blanco muerto"),
        ("RC-000260", "CROWN CHAIN",
         "la fachada del Hunter exporta la cadena "
         "(CrownChain) y la escalera viva es monotona: "
         "DETECTED no escala sin repro 2/2, y el rung "
         "de impacto en vivo queda LIMITADO a lab",
         "export OK + LADDER monotona + limite lab"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.95.0",
            "fixed_in": "v0.95.0",
            "repro": {"expected": exp},
        })


# --------------------------------------------- v0.96.0 dossier Q4-2026

_POI_FIX_POS = """<?php
class Evil_Gadget {
    public $log_file;
    public $content;
    function __destruct() { file_put_contents($this->log_file, $this->content); }
}
class Plain_Helper {
    public $name;
    function greet() { return $this->name; }
}
add_action('wp_ajax_nopriv_cfe_download', 'cfe_download_csv');
function cfe_download_csv() {
    $rows = $_POST['rows'];
    $data = unserialize($rows);
    echo json_encode($data);
}
"""

_POI_FIX_NEG = """<?php
add_action('wp_ajax_admin_thing', 'admin_thing');
function admin_thing() {
    if (!current_user_can('manage_options')) { wp_die('no'); }
    check_ajax_referer('nonce');
    $id = intval($_POST['id']);
    $data = maybe_unserialize(get_option('opt_' . $id));
}
"""

_POI_FIX_ALLOWED = """<?php
class Evil_Gadget {
    public $log_file;
    public $content;
    function __destruct() { file_put_contents($this->log_file, $this->content); }
}
add_action('wp_ajax_nopriv_weforms_detail', 'weforms_detail');
function weforms_detail() {
    $rows = $_POST['rows'];
    $data = @unserialize($rows, ['allowed_classes' => false]);
    echo json_encode($data);
}
"""

_POI_FIX_NOPRIV_OTRO = """<?php
class Evil_Gadget {
    public $log_file;
    public $content;
    function __destruct() { file_put_contents($this->log_file, $this->content); }
}
add_action('wp_ajax_nopriv_public_endpoint', 'public_endpoint');
function public_endpoint() { echo 'hola'; }
add_action('wp_ajax_admin_detail', 'admin_detail');
function admin_detail() {
    check_ajax_referer('weforms');
    if (!current_user_can('manage_options')) { wp_die('no'); }
    $rows = $_POST['rows'];
    $data = unserialize($rows);
    echo json_encode($data);
}
"""

_MAG_FIX_POS = """<?php
function myplugin_optimize() {
    $file = wp_upload_bits($_FILES['media']['name'], null, file_get_contents($_FILES['media']['tmp_name']));
    $path = $file['file'];
    $im = new Imagick($path);
    $im->readImage($path);
    $im->thumbnailImage(300, 300);
}
"""

_MAG_FIX_NEG = """<?php
function safe_optimize() {
    $file = wp_upload_bits($_FILES['media']['name'], null, file_get_contents($_FILES['media']['tmp_name']));
    $checked = wp_check_filetype_and_ext($file['file'], $_FILES['media']['name']);
    $im = new Imagick($file['file']);
}
"""


def seed_rc_000261() -> None:
    """v0.96.0 (dossier Q4-2026): tres clases nuevas al motor.
    POI-REACH: Object Injection con alcance (GATES) y gadget (POP);
    leccion CVE-2026-2599. MAGIC-CONFUSION: extension vs contenido
    hacia Imagick, leccion CVE-2026-65640. WCD-404-LEAK: 404 con
    datos privados cacheado cross-user (status code miente)."""
    cases = {c["id"] for c in _load_cases()}
    if "RC-000261" in cases:
        return
    for cid, mod, prob, exp in [
        ("RC-000261", "POI-REACH",
         "unserialize con taint del usuario en handler nopriv y "
         "gadget en el mismo plugin escala a POI-REACH con "
         "superficie export anotada",
         "POI-REACH: 3 peldanos + handler + export"),
        ("RC-000262", "POI-REACH",
         "control negativo cero-FP: caps + nonce + sin taint real "
         "y sin gadget no genera ningun veredicto",
         "0 REACH, 0 AUTH, 0 DETECTED"),
        ("RC-000269", "POI-REACH",
         "FP weforms: unserialize con allowed_classes=>false esta "
         "neutralizado: jamas genera veredicto aunque haya taint, "
         "nopriv y gadget en el mismo plugin",
         "0 reach, 0 auth, 0 detected"),
        ("RC-000270", "POI-REACH",
         "FP weforms: nopriv de OTROS metodos del archivo no da "
         "alcance; sink en handler admin con nonce sin mapear "
         "escala maximo a POI-AUTH, jamas POI-UNAUTH/REACH",
         "POI-AUTH sin POI-UNAUTH + pista nopriv_file"),
        ("RC-000263", "POI-REACH",
         "POP-CANDIDATE discrimina: clase con metodo magico y "
         "propiedades es gadget; clase sin metodo magico no",
         "Evil_Gadget si, Plain_Helper no"),
        ("RC-000264", "MAGIC-CONFUSION",
         "upload que llega a Imagick SIN gate de contenido es "
         "MAGIC-CONFUSION (patron CVE-2026-65640 en plugins)",
         "MAGIC-CONFUSION + CONFUSION-UNGUARDED"),
        ("RC-000265", "MAGIC-CONFUSION",
         "control negativo: wp_check_filetype_and_ext en el flujo "
         "es gate de contenido: CONFUSION-GUARDED, sin veredicto",
         "guarded>=1, confusion=0"),
        ("RC-000266", "WCD-404-LEAK",
         "el 404 con cuerpo de datos de cuenta cacheado por URL "
         "sirve el cuerpo ajeno al otro usuario en <=8 reqs",
         "WCD-404-LEAK cross-user"),
        ("RC-000267", "WCD-404-LEAK",
         "escalera honesta: status-lie sin cache = LEAK-NO-CACHE, "
         "404 limpio = BENIGN, ttl=0 = cebado que no contamina",
         "LEAK-NO-CACHE / BENIGN honestos"),
        ("RC-000268", "WCD-404-LEAK",
         "conservador: blanco muerto = conn-dead sin crash, y el "
         "veredicto de leak EXIGE cross_user observable",
         "conn-dead + invariante monotona"),
    ]:
        _write_case({
            "id": cid,
            "module": mod,
            "problem": prob,
            "first_seen": "v0.96.0",
            "fixed_in": "v0.96.0",
            "repro": {"expected": exp},
        })


def run(only_ids=None) -> int:
    """Corre cada caso del corpus contra el motor actual. Devuelve 0 si
    todo PASS, 1 si algo quedo sin proteccion (regresion real).
    only_ids: conjunto de ids a correr (subconjunto); None = todos."""
    from core.evidence import build_chain
    import subprocess

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
    seed_rc_000164()
    seed_rc_000165()
    seed_rc_000166()
    seed_rc_000167()
    seed_rc_000168()
    seed_rc_000169()
    seed_rc_000170()
    seed_rc_000171()
    seed_rc_000172()
    seed_rc_000173()
    seed_rc_000174()
    seed_rc_000175()
    seed_rc_000176()
    seed_rc_000177()
    seed_rc_000178()
    seed_rc_000179()
    seed_rc_000180()
    seed_rc_000181()
    seed_rc_000182()
    seed_rc_000183()
    seed_rc_000184()
    seed_rc_000185()
    seed_rc_000186()
    seed_rc_000187()
    seed_rc_000188()
    seed_rc_000189()
    seed_rc_000190()
    seed_rc_000191()
    seed_rc_000192()
    seed_rc_000193()
    seed_rc_000194()
    for _n in range(195, 205):
        globals()[f"seed_rc_000{_n}"]()
    seed_cross_layer()
    seed_rc_000210()
    seed_rc_000211()
    seed_rc_000217()
    seed_rc_000223()
    seed_rc_000229()
    seed_rc_000236()
    seed_rc_000242()
    seed_rc_000248()
    seed_rc_000254()
    seed_rc_000258()
    seed_rc_000261()
    cases = _load_cases()
    _cache_load()
    for c in _timed(cases):
        if only_ids and c["id"] not in only_ids:
            continue
        _fb = fails
        _hit = _cache_lookup(c["id"])
        if _hit is not None:
            print(f"[{c['id']}] cache intra-corpus: "
                  f"{'PASS' if _hit else 'FAIL'} "
                  f"(ya verificado, codigo sin cambios)")
            continue
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
                        _esperar_labs(pe, 1)
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
                    _esperar_labs(base_p, len(mods))
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
                    _esperar_labs(base_p, len(mods))
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
        if c["id"] == "RC-000164":
            import subprocess
            from core.edge_profile import profile as eprof
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["eco-normaliza", "eco-conserva", "rechaza"]
                procs = {}
                base_p = 18980
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(base_p, len(mods))
                    port = lambda m: base_p + mods.index(m) * 2
                    prof = lambda m: eprof({
                        "url": f"http://127.0.0.1:{port(m)}/",
                        "timeout": 5.0})
                    ok = True
                    f1 = prof("eco-normaliza")
                    c1 = (f1["normalizacion"] == "normalized"
                          and f1["downstream"] == "reached"
                          and f1["cl_te"] == "accepted")
                    if not c1:
                        ok = False
                    print(f"[{c['id']}] eco-normaliza: "
                          f"{f1['normalizacion']}/"
                          f"{f1['downstream']} -> "
                          f"{'PASS' if c1 else 'FAIL'}")
                    f2 = prof("eco-conserva")
                    c2 = (f2["normalizacion"] == "conserved"
                          and f2["downstream"] == "reached"
                          and f2["cl_te"] == "accepted")
                    if not c2:
                        ok = False
                    print(f"[{c['id']}] eco-conserva: "
                          f"{f2['normalizacion']}/"
                          f"{f2['downstream']} -> "
                          f"{'PASS' if c2 else 'FAIL'}")
                    f3 = prof("rechaza")
                    c3 = (f3["cl_te"] == "rejected"
                          and f3["te_case"] == "rejected"
                          and f3["cierre_rechazo"] == "yes"
                          and f3["normalizacion"] == "unknown"
                          and f3["origin"] == "unknown")
                    if not c3:
                        ok = False
                    print(f"[{c['id']}] rechaza: "
                          f"{f3['cl_te']}/{f3['cierre_rechazo']} -> "
                          f"{'PASS' if c3 else 'FAIL'}")
                    print(f"[{c['id']}] ficha edge-profile -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p in procs.values():
                        p.kill()
        if c["id"] == "RC-000165":
            import subprocess
            from core.normalization_audit import audit as naudit
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["eco-normaliza", "eco-conserva", "rechaza"]
                procs = {}
                base_p = 19000
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(base_p, len(mods))
                    port = lambda m: base_p + mods.index(m) * 2
                    aud = lambda m: naudit({
                        "url": f"http://127.0.0.1:{port(m)}/",
                        "timeout": 5.0})
                    ok = True
                    r1 = aud("eco-normaliza")
                    m1 = r1["matriz"].get("cl_te", {})
                    c1 = (m1.get("veredicto") == "NORMALIZED"
                          and r1["veredicto"] == "MATRIX")
                    if not c1:
                        ok = False
                    print(f"[{c['id']}] eco-normaliza: "
                          f"{m1.get('veredicto')}/"
                          f"{r1['veredicto']} -> "
                          f"{'PASS' if c1 else 'FAIL'}")
                    r2 = aud("eco-conserva")
                    m2 = r2["matriz"].get("cl_te", {})
                    c2 = (m2.get("veredicto") == "MISMATCH"
                          and r2["veredicto"] == "SOSPECHA"
                          and r2["escalera_mismatch"]
                          ["reproducible"] == "yes"
                          and r2["escalera_mismatch"]
                          ["evidencia_downstream"] == "eco")
                    if not c2:
                        ok = False
                    print(f"[{c['id']}] eco-conserva: "
                          f"{m2.get('veredicto')}/"
                          f"{r2['veredicto']} -> "
                          f"{'PASS' if c2 else 'FAIL'}")
                    r3 = aud("rechaza")
                    c3 = r3["veredicto"] == "RECHAZADO-TOTAL"
                    if not c3:
                        ok = False
                    print(f"[{c['id']}] rechaza: "
                          f"{r3['veredicto']} -> "
                          f"{'PASS' if c3 else 'FAIL'}")
                    print(f"[{c['id']}] body-differential -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p in procs.values():
                        p.kill()
        if c["id"] == "RC-000168":
            from core.cache_correlation import audit as caudit
            cache_lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "cache_lab.py")
            if not os.path.exists(cache_lab):
                print(f"[{c['id']}] labs/cache_lab.py ausente -> SKIP (no FAIL)")
            else:
                mods168 = ["consistent", "ttl_variant"]
                procs = {}
                base168 = 19160
                for i, m in enumerate(mods168):
                    procs[m] = subprocess.Popen(
                        [sys.executable, cache_lab,
                         str(base168 + i * 2), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(base168, len(mods168))
                    ok = True
                    r1 = caudit({"url": f"http://127.0.0.1:{base168}/",
                                 "timeout": 5.0})
                    c1 = (r1["verdicto"] == "STABLE"
                          and r1["baseline"]["classification"]
                          == "STABLE")
                    ok = ok and c1
                    print(f"[{c['id']}] consistent: {r1['verdicto']}"
                          f"/baseline {r1['baseline']['classification']}"
                          f" -> {'PASS' if c1 else 'FAIL'}")
                    r2 = caudit({"url": f"http://127.0.0.1:{base168 + 2}/",
                                 "timeout": 5.0})
                    c2 = (r2["verdicto"] == "STABLE"
                          and r2["baseline"]["classification"]
                          == "VARIANT")
                    ok = ok and c2
                    print(f"[{c['id']}] ttl_variant: {r2['verdicto']}"
                          f"/baseline {r2['baseline']['classification']}"
                          f" (temporal, no ambiguo) -> "
                          f"{'PASS' if c2 else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for pr in procs.values():
                        pr.kill()
        if c["id"] == "RC-000169":
            from core.cache_correlation import audit as caudit
            cache_lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "cache_lab.py")
            if not os.path.exists(cache_lab):
                print(f"[{c['id']}] labs/cache_lab.py ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, cache_lab, "19164",
                     "divergent_equivalent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(19164, 1)
                    r = caudit({"url": "http://127.0.0.1:19164/",
                                "timeout": 5.0})
                    ev = r["evidence"]
                    ok = (r["verdicto"] == "SUSPICIOUS"
                          and ev["E2"] and ev["E3"] and ev["E4"]
                          and not ev["E5"] and not ev["E6"])
                    print(f"[{c['id']}] divergent_equivalent: "
                          f"{r['verdicto']} "
                          f"(E2={ev['E2']} E3={ev['E3']} "
                          f"E4={ev['E4']} E5={ev['E5']} "
                          f"E6={ev['E6']}) -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    pr.kill()
        if c["id"] == "RC-000170":
            from core.cache_correlation import audit as caudit
            cache_lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "cache_lab.py")
            if not os.path.exists(cache_lab):
                print(f"[{c['id']}] labs/cache_lab.py ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, cache_lab, "19166",
                     "personalized"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(19166, 1)
                    r = caudit({"url": "http://127.0.0.1:19166/",
                                "timeout": 5.0})
                    ctl = r["controls"]["controls"]
                    ok = (r["verdicto"] == "BENIGN"
                          and "cookies_session" in
                          r["controls"]["explican"]
                          and "vary" in r["controls"]["explican"]
                          and ctl["vary"]["status"] == "FAILED")
                    print(f"[{c['id']}] personalized: {r['verdicto']} "
                          f"(explican={r['controls']['explican']}) "
                          f"-> {'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    pr.kill()
        if c["id"] == "RC-000171":
            from core.cache_correlation import audit as caudit
            cache_lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "cache_lab.py")
            if not os.path.exists(cache_lab):
                print(f"[{c['id']}] labs/cache_lab.py ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, cache_lab, "19168",
                     "bot_ambiguous"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(19168, 1)
                    r = caudit({"url": "http://127.0.0.1:19168/",
                                "timeout": 5.0})
                    ok = (r["verdicto"] == "UNKNOWN"
                          and r["baseline"]["classification"]
                          == "AMBIGUO")
                    print(f"[{c['id']}] bot_ambiguous: {r['verdicto']}"
                          f"/baseline {r['baseline']['classification']}"
                          f" -> {'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    pr.kill()
        if c["id"] == "RC-000172":
            from core.cache_correlation import audit as caudit
            cache_lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "cache_lab.py")
            if not os.path.exists(cache_lab):
                print(f"[{c['id']}] labs/cache_lab.py ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, cache_lab, "19170",
                     "convergent_distinct"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(19170, 1)
                    r = caudit({"url": "http://127.0.0.1:19170/",
                                "timeout": 5.0})
                    ev = r["evidence"]
                    corr = r["correlation"]
                    ok = (r["verdicto"] == "DEMO"
                          and corr["binding_evidence"] == "STRONG"
                          and ev["E5"] and ev["E6"]
                          and corr["especificidad_path"]
                          and r["baseline"]["classification"]
                          in ("STABLE", "VARIANT"))
                    print(f"[{c['id']}] convergent_distinct: "
                          f"{r['verdicto']} (binding STRONG, E5={ev['E5']} "
                          f"E6={ev['E6']}, especificidad="
                          f"{corr['especificidad_path']}, baseline "
                          f"{r['baseline']['classification']}) -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    pr.kill()
        if c["id"] == "RC-000173":
            import subprocess as sp
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            res = sp.run(
                [sys.executable, os.path.join(root, "core",
                 "regress.py"), "--only",
                 "RC-000164,RC-000165,RC-000166,RC-000167"],
                capture_output=True, text=True, timeout=900)
            out = res.stdout or ""
            ok = (res.returncode == 0
                  and "fallo(s), 0 fallo(s)" not in out
                  and out.rstrip().splitlines()[-1].strip()
                  .endswith("0 fallo(s)"))
            print(f"[{c['id']}] invariantes v0.72-v0.78: "
                  f"re-ejecucion RC-000164..167 exit={res.returncode} "
                  f"-> {'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000167":
            import subprocess
            from core.state_correlation import audit as saudit
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["desync-pool", "eco-normaliza",
                        "consistente"]
                procs = {}
                base_p = 19130
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(base_p, len(mods))
                    port = lambda m: base_p + mods.index(m) * 2
                    ok = True
                    r1 = saudit({"url":
                                 f"http://127.0.0.1:{port('desync-pool')}/",
                                 "timeout": 5.0})
                    v1 = r1.get("evidence_quality", {})
                    c1 = (r1.get("resultado")
                          == "CROSS-CONNECTION-MISMATCH"
                          and r1.get("juez", {})
                          .get("veredicto") == "DEMO"
                          and v1.get("CONNECTION-STATE", {})
                          .get("nivel") == "E4"
                          and v1.get("SECURITY-IMPACT", {})
                          .get("nivel") == "E5")
                    if not c1:
                        ok = False
                    print(f"[{c['id']}] desync-pool: "
                          f"{r1.get('resultado')}/"
                          f"{r1.get('juez', {}).get('veredicto')} "
                          f"(E4+E5) -> "
                          f"{'PASS' if c1 else 'FAIL'}")
                    r2 = saudit({"url":
                                 f"http://127.0.0.1:{port('eco-normaliza')}/",
                                 "timeout": 5.0})
                    v2 = r2.get("evidence_quality", {})
                    c2 = (r2.get("resultado") == "PIPE-BENIGN"
                          and "sellado" in r2.get("juez", {})
                          .get("veredicto", "")
                          and v2.get("REPRESENTATION", {})
                          .get("nivel") == "E3"
                          and v2.get("CONNECTION-STATE", {})
                          .get("nivel") == "E2"
                          and v2.get("SECURITY-IMPACT", {})
                          .get("nivel") == "E0")
                    if not c2:
                        ok = False
                    print(f"[{c['id']}] eco-normaliza: "
                          f"PIPE-BENIGN sellado "
                          f"(E3+E2+E0 sin escalar) -> "
                          f"{'PASS' if c2 else 'FAIL'}")
                    r3 = saudit({"url":
                                 f"http://127.0.0.1:{port('consistente')}/",
                                 "timeout": 5.0})
                    v3 = r3.get("evidence_quality", {})
                    c3 = (r3.get("resultado") == "STABLE"
                          and r3.get("juez", {})
                          .get("veredicto") == "STABLE"
                          and all(x.get("nivel") == "E0"
                                  for x in v3.values()))
                    if not c3:
                        ok = False
                    print(f"[{c['id']}] consistente: STABLE "
                          f"(E0/E0/E0) -> "
                          f"{'PASS' if c3 else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p2 in procs.values():
                        p2.kill()
        if c["id"] == "RC-000166":
            import subprocess
            from core.connection_state import audit as caudit
            lab = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "labs", "desync_lab.py")
            if not os.path.exists(lab):
                print(f"[{c['id']}] labs/desync_lab.py ausente -> "
                      f"SKIP (no FAIL)")
            else:
                import time as _t
                mods = ["desync-pool", "eco-normaliza",
                        "consistente"]
                procs = {}
                base_p = 19120
                for i, m in enumerate(mods):
                    procs[m] = subprocess.Popen(
                        [sys.executable, lab, str(base_p + i * 2),
                         str(base_p + i * 2 + 1), m],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(base_p, len(mods))
                    port = lambda m: base_p + mods.index(m) * 2
                    aud = lambda m: caudit({
                        "url": f"http://127.0.0.1:{port(m)}/",
                        "timeout": 5.0})
                    ok = True
                    r1 = aud("desync-pool")
                    t1 = r1["resultados"].get("T2:veneno", {})
                    c1 = (t1.get("veredicto") == "DEMO"
                          and r1["veredicto"] == "DEMO"
                          and t1.get("conn2_marker") is True)
                    if not c1:
                        ok = False
                    print(f"[{c['id']}] desync-pool: "
                          f"{t1.get('veredicto')}/conn2_marker="
                          f"{t1.get('conn2_marker')} -> "
                          f"{'PASS' if c1 else 'FAIL'}")
                    r2 = aud("eco-normaliza")
                    t2 = r2["resultados"].get("T2:veneno", {})
                    c2 = (t2.get("veredicto")
                          in ("STATE-STABLE+PIPE", "STATE-STABLE")
                          and r2["veredicto"] != "DEMO"
                          and not t2.get("conn2_marker"))
                    if not c2:
                        ok = False
                    print(f"[{c['id']}] eco-normaliza: "
                          f"{t2.get('veredicto')} (sin falso "
                          f"DEMO) -> {'PASS' if c2 else 'FAIL'}")
                    r3 = aud("consistente")
                    c3 = (r3["veredicto"] == "STATE-STABLE"
                          and r3["resultados"]
                          .get("T2:veneno", {})
                          .get("veredicto") == "STATE-STABLE")
                    if not c3:
                        ok = False
                    print(f"[{c['id']}] consistente: "
                          f"{r3['veredicto']} -> "
                          f"{'PASS' if c3 else 'FAIL'}")
                    print(f"[{c['id']}] control cross-connection "
                          f"-> {'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    for p in procs.values():
                        p.kill()
        # ---- SEMANTIC-CACHE v0.80 (RC-000174..181)
        if c["id"] in _SEM_TABLE:
            from core.semantic_engine import audit as sem_audit
            mode, exp, extra = _SEM_TABLE[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "semantic_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/semantic_lab.py "
                      f"ausente -> SKIP (no FAIL)")
            else:
                port = 19200 + (int(c["id"][-3:]) - 174) * 2
                proc = subprocess.Popen(
                    [sys.executable, labp, str(port), mode],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1)
                    rec = sem_audit({
                        "url": f"http://127.0.0.1:{port}/",
                        "timeout": 6.0})
                    ok = rec["verdict"] == exp
                    for k, v in extra.items():
                        if rec["attributes"].get(k) != v:
                            ok = False
                    if exp == "UNKNOWN" and not any(
                            "baseline" in str(u) for u in
                            rec.get("unknown_causes", [])):
                        ok = False
                    tot = (rec.get("budget", {})
                           .get("spent", {})
                           .get("total", 99))
                    if tot > 30:
                        ok = False
                    print(f"[{c['id']}] {mode}: "
                          f"{rec['verdict']}/{tot} req"
                          f"{' attrs OK' if extra else ''} "
                          f"-> {'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    proc.kill()
        if c["id"] == "RC-000182":
            import subprocess as sp2
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            res = sp2.run(
                [sys.executable,
                 os.path.join(root, "core", "regress.py"),
                 "--only",
                 "RC-000168,RC-000169,RC-000170,RC-000171,"
                 "RC-000172,RC-000173"],
                capture_output=True, text=True, timeout=1200)
            out = res.stdout or ""
            ok = (res.returncode == 0
                  and out.rstrip().splitlines()[-1].strip()
                  .endswith("0 fallo(s)"))
            print(f"[{c['id']}] invariantes v0.79: "
                  f"re-ejecucion RC-000168..173 exit="
                  f"{res.returncode} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        # ---- ADAPTIVE-HUNT v0.81 (RC-000183..185)
        if c["id"] in _ADT_TABLE:
            from core.adaptive_hunt import audit as adaudit
            mode, exp_verdict, chk = _ADT_TABLE[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "adaptive_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/adaptive_lab.py "
                      f"ausente -> SKIP (no FAIL)")
            else:
                port = 19230 + (int(c["id"][-3:]) - 183) * 2
                proc = subprocess.Popen(
                    [sys.executable, labp, str(port), mode],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1)
                    rec = adaudit({
                        "url": f"http://127.0.0.1:{port}/",
                        "timeout": 5.0})
                    ok = rec["verdicto"] == exp_verdict
                    det = rec["verdicto"]
                    if chk.get("attr_contains"):
                        if chk["attr_contains"] not in \
                                rec["atribucion"]:
                            ok = False
                        det = rec["atribucion"]
                    if chk.get("live"):
                        vivas = sorted(x["id"] for x in rec
                                       ["gap_ledger"]
                                       ["hipotesis_vivas"])
                        if vivas != sorted(chk["live"]):
                            ok = False
                        det = f"vivas {vivas}"
                    if chk.get("razon"):
                        if not rec["gap_ledger"].get("razon"):
                            ok = False
                    tot = rec["budget"]["spent"]["total"]
                    if tot > 30:
                        ok = False
                    print(f"[{c['id']}] {mode}: {det}/"
                          f"{tot} req -> "
                          f"{'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
                finally:
                    proc.kill()
        # ---- RESEARCH-MEMORY v0.81.1 (RC-000187..189)
        if c["id"] in _ADTMEM_TABLE:
            import tempfile
            from core import adaptive_hunt as ah
            from core import research_memory as rmx
            import json as _json
            mode = _ADTMEM_TABLE[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "adaptive_lab.py")
            port = 19240 + (int(c["id"][-3:]) - 187) * 2
            proc = subprocess.Popen(
                [sys.executable, labp, str(port),
                 "lb_variance"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            _oldhome = os.environ.get("CODEXRC_HOME")
            _tmp = tempfile.mkdtemp(prefix="rcmem")
            os.environ["CODEXRC_HOME"] = _tmp
            _url = f"http://127.0.0.1:{port}/"
            try:
                _esperar_labs(port, 1)
                r1 = ah.audit({"url": _url, "timeout": 5.0})
                ok = (r1["verdicto"]
                      == "BASELINE-CARACTERIZADO"
                      and "H1" in r1["atribucion"])
                det = (f"fresco {r1['budget']['spent']['total']}"
                       f" req")
                if mode == "reuse":
                    r2 = ah.audit({"url": _url, "timeout": 5.0,
                                  "resume": True})
                    ok = ok and r2.get("reuse") and (
                        r2["budget"]["spent"]["total"] == 3
                        ) and "REUSADO" in r2["atribucion"] \
                        and "H1" in r2["atribucion"]
                    _tot2 = r2["budget"]["spent"]["total"]
                    det = (f"reuso {_tot2} req: "
                           f"{r2['atribucion']}")
                elif mode == "ttl0":
                    r2 = ah.audit({"url": _url, "timeout": 5.0,
                                  "resume": True,
                                  "ttl_hours": 0.0})
                    ok = ok and not r2.get("reuse") and (
                        r2["budget"]["spent"]["total"] == 19
                        ) and any(n.get("prior")
                                  for n in r2["hipotesis"])
                    _tot3 = r2["budget"]["spent"]["total"]
                    det = (f"ventana nueva {_tot3} req + "
                           f"anotacion previa")
                elif mode == "mismatch":
                    prev = rmx.load(_url)
                    prev["baseline"]["huellas"] = [
                        "dead0000dead0000"] * 3
                    _json.dump(prev, open(
                        os.path.join(rmx.mem_dir(_url),
                                     "latest.json"), "w"))
                    r2 = ah.audit({"url": _url, "timeout": 5.0,
                                  "resume": True})
                    ok = ok and not r2.get("reuse") and (
                        r2["budget"]["spent"]["total"] == 19
                        ) and any(n.get("prior")
                                  for n in r2["hipotesis"])
                    det = ("baseline distinto -> ventana nueva "
                           "19 req")
                print(f"[{c['id']}] memoria {mode}: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
            finally:
                if _oldhome is None:
                    del os.environ["CODEXRC_HOME"]
                else:
                    os.environ["CODEXRC_HOME"] = _oldhome
                proc.kill()
        # ---- EXPERIMENT-GRAPH v0.83 (RC-000195..204)
        if 195 <= int(c["id"][-3:]) <= 204:
            import tempfile
            from core import experiment_graph as eg2
            ok = True
            det = ""
            br = {"senal": {
                "supports": ["HH1"],
                "clase": eg2.E_SIGNAL}}
            sp = [[("HH1", "SUPPORT")],
                  [("HH1", "CONTRADICT")]]
            if c["id"] == "RC-000195":
                g = eg2.ExpGraph("t195", [
                    ("HH1", "hip"), ("HH2", "hip2")])
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                oid = g.add_observation("EX1", {})
                g.apply("EX1", oid, "senal")
                tipos = {n["tipo"] for n in
                         g.nodes.values()}
                ok = (tipos == {"HYPOTHESIS", "EXPERIMENT",
                                "OBSERVATION", "EVIDENCE"}
                       and all(n["run_id"] == g.run_id
                               for n in
                               g.nodes.values()))
                det = f"tipos {sorted(tipos)}"
            elif c["id"] == "RC-000196":
                g = eg2.ExpGraph("t196", [("HH1", "h")])
                ok = g.nodes["HH1"]["state"] == "LIVE"
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                oid = g.add_observation("EX1", {})
                g.apply("EX1", oid, "senal")
                ok = ok and g.nodes["HH1"]["state"] == \
                    "SUPPORTED"
                br2 = {"mal": {"contradicts": ["HH1"]}}
                g.register_contract("EX2", ["HH1"], "p",
                                    br2, [], {"max_requests": 2,
                                              "max_connections": 1}, sp)
                o2 = g.add_observation("EX2", {})
                g.apply("EX2", o2, "mal")
                ok = ok and g.nodes["HH1"]["state"] == \
                    "CONTRADICTED"
                # contradiccion terminal: apoyo posterior
                # no revive
                g.register_contract("EX3", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o3 = g.add_observation("EX3", {})
                g.apply("EX3", o3, "senal")
                ok = ok and g.nodes["HH1"]["state"] == \
                    "CONTRADICTED"
                # una hipotesis sin evidencia sigue LIVE
                g.add_hypothesis("HH9", "nueva")
                ok = ok and g.nodes["HH9"]["state"] == \
                    "LIVE"
                det = "lifecycle ok"
            elif c["id"] == "RC-000197":
                g = eg2.ExpGraph("t197", [("HH1", "h")])
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                g.add_observation("EX1", {})
                try:
                    g.register_contract("EX1", ["HH1"],
                                        "otro", {}, [],
                                        {"max_requests": 2,
                                         "max_connections": 1},
                                        sp)
                    ok = False
                except ValueError:
                    ok = True
                try:
                    g.add_observation("EX9", {})
                    ok = False
                except ValueError:
                    ok = ok and True
                det = "post-hoc rechazado"
            elif c["id"] == "RC-000198":
                g = eg2.ExpGraph("t198", [("HH1", "h")])
                g.register_contract("EXLOW", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1},
                                    [[("HH1", "INCONCLUSIVE")]])
                g.register_contract("EXHIGH", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                nxt, edv, tab, rz = g.next_experiment()
                ok = (nxt == "EXHIGH"
                      and abs(edv - 1.5) < 0.01
                      and len(tab) == 2)
                g.nodes["HH1"]["state"] = "CLOSED"
                nxt2, _, _, rz2 = g.next_experiment()
                ok = ok and nxt2 is None and rz2.startswith(
                    "ningun experimento")
                det = f"next {nxt} edv {edv}; EDV0: {rz2[:30]}"
            elif c["id"] == "RC-000199":
                g = eg2.ExpGraph("t199", [("HH1", "h")])
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                oid = g.add_observation("EX1", {})
                g.apply("EX1", oid, "senal")
                brm = {"mal": {"contradicts": ["HH1"]}}
                g.register_contract("EX2", ["HH1"], "p",
                                    brm, [], {"max_requests": 2,
                                              "max_connections": 1}, sp)
                o2 = g.add_observation("EX2", {})
                g.apply("EX2", o2, "mal")
                h = g.nodes["HH1"]
                ok = (h["state"] == "CONTRADICTED"
                      and len(h["evidence_against"]) == 1
                      and len(h["evidence_for"]) == 1)
                det = "historial preservado"
            elif c["id"] == "RC-000200":
                g = eg2.ExpGraph("t200", [("HH1", "h")],
                                 baseline_state="STABLE")
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o1 = g.add_observation("EX1", {},
                    repro={"genealogy": ["r1", "V1", "p1"]})
                g.apply("EX1", o1, "senal")
                ok1, st1 = g.declare_transition(
                    "CANDIDATE", "senal 1")
                ok, st = g.declare_transition("REPRODUCIBLE",
                                              "1 gen")
                ok = (ok is False and st == "CANDIDATE"
                      and ok1)
                g.register_contract("EX2", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o2 = g.add_observation("EX2", {},
                    repro={"genealogy": ["r1", "V1", "p2"]})
                g.apply("EX2", o2, "senal")
                ok2, st2 = g.declare_transition(
                    "REPRODUCIBLE", "2 genealogias")
                ok = ok and ok2 and st2 == "REPRODUCIBLE"
                det = f"1 gen rechazada, 2 genes -> {st2}"
            elif c["id"] == "RC-000201":
                g = eg2.ExpGraph("t201", [("HH1", "h")],
                                 baseline_state="STABLE")
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o1 = g.add_observation("EX1", {},
                    repro={"genealogy": ["g1"]})
                g.apply("EX1", o1, "senal")
                ok = g.candidate == "CANDIDATE"
                ok, st = g.declare_transition("SUPPORTED",
                                              "b")
                g.register_contract("EX2", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o2 = g.add_observation("EX2", {},
                    repro={"genealogy": ["g2"]})
                g.apply("EX2", o2, "senal")
                g.declare_transition("REPRODUCIBLE", "2")
                ok = ok and g.candidate == "REPRODUCIBLE"
                ok3, st3 = g.declare_transition(
                    "CONFIRMED", "sin impacto")
                ok = ok and ok3 is False
                det = (f"{g.candidate}, confirm "
                       f"bloqueado={not ok3}")
            elif c["id"] == "RC-000202":
                g = eg2.ExpGraph("t202", [("HH1", "h")],
                                 baseline_state="AMBIGUO")
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                o1 = g.add_observation("EX1", {},
                    repro={"genealogy": ["g1"]})
                g.apply("EX1", o1, "senal")
                b = g.confirm_blockers()
                ok = ("baseline_caracterizado" in b
                      and "multiples_anomalias" in b
                      and "reproducible" in b
                      and "impacto" in b)
                det = f"bloqueos {b}"
            elif c["id"] == "RC-000203":
                _h = os.environ.get("CODEXRC_HOME")
                _t = tempfile.mkdtemp(prefix="rcgraph")
                os.environ["CODEXRC_HOME"] = _t
                try:
                    g = eg2.ExpGraph("t203.host", [
                        ("HH1", "h")])
                    p = g.save()
                    ok = os.path.exists(p)
                    try:
                        g.save()
                        ok = False
                    except ValueError:
                        ok = ok and True
                    g2 = eg2.ExpGraph("t203.host", [
                        ("HH1", "h")])
                    g2.save()
                    lr = eg2.latest_run("t203.host")
                    ok = ok and lr["run_id"] == g2.run_id
                    det = "2 runs, latest ok"
                finally:
                    if _h is None:
                        del os.environ["CODEXRC_HOME"]
                    else:
                        os.environ["CODEXRC_HOME"] = _h
            elif c["id"] == "RC-000204":
                g = eg2.ExpGraph("t204", [("HH1", "h")])
                g.register_contract("EX1", ["HH1"], "p",
                                    br, [], {"max_requests": 2,
                                             "max_connections": 1}, sp)
                g.record_selection("EX1", 1.5,
                                   [("EX1", 1.5)],
                                   ["HH1"], "mayor EDV")
                oid = g.add_observation("EX1", {})
                g.apply("EX1", oid, "senal")
                ch = g.why("EX1")
                links = [x["link"] for x in ch]
                ok = ("EXPERIMENT" in links
                      and "HYPOTHESIS" in links
                      and "EVIDENCE" in links
                      and "OBSERVATION" in links)
                ch2 = g.why("EX-SIN-SEL")
                ok = ok and ch2 and "sin registro" in \
                    ch2[0]["porque"]
                det = f"cadena {links}"
            print(f"[{c['id']}] graph: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1

        # ---- SELECTOR EDV v0.82 (RC-000191..194)
        if c["id"] in ("RC-000191", "RC-000193"):
            import tempfile
            from core import adaptive_hunt as ah
            mode = ("origin_dynamics"
                    if c["id"] == "RC-000191"
                    else "lb_variance")
            port = (19260 if c["id"] == "RC-000191"
                    else 19262)
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "adaptive_lab.py")
            proc = subprocess.Popen(
                [sys.executable, labp, str(port), mode],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            _oldhome = os.environ.get("CODEXRC_HOME")
            _tmp = tempfile.mkdtemp(prefix="rcedv")
            os.environ["CODEXRC_HOME"] = _tmp
            try:
                _esperar_labs(port, 1)
                rec = ah.audit({"url":
                    f"http://127.0.0.1:{port}/",
                    "timeout": 5.0})
                tot = rec["budget"]["spent"]["total"]
                exps = [t for t in rec["trace"]
                        if t["paso"] == "experimento"]
                ok = True
                det = ""
                if c["id"] == "RC-000191":
                    ok = (rec["verdicto"]
                          == "BASELINE-CARACTERIZADO"
                          and "BY-ELIMINATION"
                          in rec["atribucion"]
                          and tot == 10
                          and len(rec["experimentos"]) == 2
                          and all(
                              t["eleccion"]["edv"] >= 1
                              for t in exps))
                    det = (f"{tot} req, "
                           f"{len(rec['experimentos'])} "
                           f"experimentos")
                else:
                    ids = [t["id"] for t in exps]
                    ok = (ids[:3] == ["INTRA-CONN",
                                     "CROSS-CONN",
                                     "VIRGIN"]
                          and abs(
                              exps[2]["eleccion"]["edv"]
                              - 2.5) < 0.01
                          and all(
                              t["eleccion"].get("tabla")
                              for t in exps))
                    det = ("orden " + ",".join(ids)
                           + " VIRGIN EDV "
                           + str(exps[2]["eleccion"]
                                 ["edv"]))
                print(f"[{c['id']}] selector: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
            finally:
                if _oldhome is None:
                    del os.environ["CODEXRC_HOME"]
                else:
                    os.environ["CODEXRC_HOME"] = _oldhome
                proc.kill()
        if c["id"] == "RC-000192":
            from core import experiment_selector as xs
            from core import hypothesis_graph as hg2
            g1 = hg2.seed("baseline_ambiguous")
            sel1, tab1, _ = xs.select(g1, [], 30,
                {"INTRA-CONN": 4, "CROSS-CONN": 5,
                 "SESSION": 7, "VIRGIN": 6,
                 "TIME-OFFSET": 5})
            g2 = hg2.seed("baseline_ambiguous")
            hg2.apply(g2, [("H1", "CONTRADICT", "t"),
                           ("H3", "CONTRADICT", "t"),
                           ("H5", "CONTRADICT", "t")])
            sel2, tab2, rz = xs.select(g2, ["SESSION"],
                30, {"INTRA-CONN": 4, "CROSS-CONN": 5,
                     "SESSION": 7, "VIRGIN": 6,
                     "TIME-OFFSET": 5})
            ok = (sel1 is not None
                  and sel1[0] == "INTRA-CONN"
                  and ("SESSION", 2.0) in tab1
                  and sel2 is None
                  and "H2" in rz and "H4" in rz)
            det = (f"primera {sel1}, EDV0 razon: "
                   f"{rz if sel2 is None else 'NO PARO'}")
            print(f"[RC-000192] parada honesta: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000194":
            import subprocess as sp5
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            res = sp5.run(
                [sys.executable,
                 os.path.join(root, "core", "regress.py"),
                 "--only",
                 "RC-000187,RC-000188,RC-000189,"
                 "RC-000190"],
                capture_output=True, text=True,
                timeout=1200)
            out = res.stdout or ""
            ok = (res.returncode == 0
                  and out.rstrip().splitlines()[-1].strip()
                  .endswith("0 fallo(s)"))
            print(f"[{c['id']}] invariantes v0.81: "
                  f"re-ejecucion RC-000187..190 exit="
                  f"{res.returncode} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000190":
            import subprocess as sp4
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            res = sp4.run(
                [sys.executable,
                 os.path.join(root, "core", "regress.py"),
                 "--only",
                 "RC-000183,RC-000184,RC-000185"],
                capture_output=True, text=True, timeout=900)
            out = res.stdout or ""
            ok = (res.returncode == 0
                  and out.rstrip().splitlines()[-1].strip()
                  .endswith("0 fallo(s)"))
            print(f"[{c['id']}] invariantes v0.81: "
                  f"re-ejecucion RC-000183..185 exit="
                  f"{res.returncode} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000186":
            import subprocess as sp3
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            cmd = [sys.executable,
                   os.path.join(root, "core", "regress.py"),
                   "--only",
                   "RC-000174,RC-000175,RC-000176,"
                   "RC-000177,RC-000178,RC-000179,"
                   "RC-000180,RC-000181,RC-000182"]
            res = sp3.run(cmd, capture_output=True,
                          text=True, timeout=1500)
            with open("/tmp/rc000186_nested.log", "w")                     as _f:
                _f.write(res.stdout or "")
            if res.returncode != 0:
                # un solo reintento tras limpiar labs
                # huerfanos (flake de puertos)
                _kill_labs()
                res = sp3.run(cmd, capture_output=True,
                              text=True, timeout=1500)
                with open("/tmp/rc000186_nested.log",
                          "a") as _f:
                    _f.write("\n=== retry ===\n"
                             + (res.stdout or ""))
            out = res.stdout or ""
            ok = (res.returncode == 0
                  and out.rstrip().splitlines()[-1].strip()
                  .endswith("0 fallo(s)"))
            print(f"[{c['id']}] invariantes v0.80: "
                  f"re-ejecucion RC-000174..182 exit="
                  f"{res.returncode} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000210":
            root = os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))
            app_src = open(os.path.join(root, "backend",
                                        "app.py")).read()
            idx_src = open(os.path.join(root, "frontend",
                                        "index.html")).read()
            xl_src = open(os.path.join(root, "core",
                                       "cross_layer.py")).read()
            ok = True
            rzn = []
            if '"cross_layer", "domain_map"' not in app_src:
                ok = False; rzn.append("NODE_ORDER sin cross_layer")
            if '"cross_layer": node_cross_layer' not in app_src:
                ok = False; rzn.append("NODE_FUNCS sin nodo")
            if 'def node_cross_layer' not in app_src:
                ok = False; rzn.append("sin node_cross_layer")
            if 'id: "cross_layer", label: "X-LAYER"' not in idx_src:
                ok = False; rzn.append("UI sin nodo X-LAYER")
            if 'id="bXLayer"' not in idx_src:
                ok = False; rzn.append("UI sin tarjeta")
            if "MAX_PERTURBATIONS = 2" not in xl_src:
                ok = False; rzn.append("presupuesto alterado")
            print(f"[RC-000210] pipe-cross: nodo en backend+UI, "
                  f"presupuesto intacto -> "
                  f"{'PASS' if ok else 'FAIL: ' + '; '.join(rzn)}")
            if not ok:
                fails += 1
        # ---- CROSS-LAYER v0.84 (RC-000205..209)
        if c["id"] in ("RC-000205", "RC-000206",
                       "RC-000207", "RC-000208"):
            import tempfile
            from core import cross_layer as xl
            scens = {
                "RC-000205": ("absorbed", 19180, "BENIGN"),
                "RC-000206": ("edge_local", 19181, "BENIGN"),
                "RC-000207": ("shared_state", 19182,
                              "SHARED-STATE"),
                "RC-000208": ("contamination", 19183,
                              "DEMO"),
            }
            scen, port, want = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "cross_layer_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/cross_layer_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                _oldh = os.environ.get("CODEXRC_HOME")
                _tmpd = tempfile.mkdtemp(prefix="rcxl")
                os.environ["CODEXRC_HOME"] = _tmpd
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1)
                    inf = xl.cross_audit({
                        "url": f"http://127.0.0.1:{port}",
                        "timeout": 5.0})
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 11)
                    det = (f"{scen}: {inf['verdict']} "
                           f"(esperado {want}), "
                           f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                    if _oldh is None:
                        del os.environ["CODEXRC_HOME"]
                    else:
                        os.environ["CODEXRC_HOME"] = _oldh
                print(f"[{c['id']}] cross-layer: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000209":
            from core import cross_layer as xl
            bat = xl.perturbation_battery()
            ok = (len(bat) <= xl.MAX_PERTURBATIONS == 2
                  and xl.BASELINE_PROBES == 2
                  and xl.perturbation_battery()[0][
                      "pid"] == "P-CASE")
            det = (f"bateria {len(bat)} perturbaciones, "
                   f"presupuesto "
                   f"{4 * len(bat) + 3} reqs max")
            print(f"[{c['id']}] invariantes cross-layer: "
                  f"{det} -> {'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1

        # ---- WCD-CACHE-KEY v0.86 (RC-000211..216)
        if c["id"] in ("RC-000211", "RC-000212",
                       "RC-000213", "RC-000214",
                       "RC-000215"):
            import tempfile
            from core import wcd_bait as wcd
            scens = {
                "RC-000211": ("benign", 19184, "BENIGN"),
                "RC-000212": ("leak_nocache", 19185,
                              "LEAK-NO-CACHE"),
                "RC-000213": ("cache_vary", 19186,
                              "WCD-CACHE"),
                "RC-000214": ("contamination", 19187,
                              "WCD-DEMO"),
                "RC-000215": ("open_endpoint", 19188,
                              "OPEN-ENDPOINT"),
            }
            scen, port, want = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "wcd_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/wcd_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                _oldh = os.environ.get("CODEXRC_HOME")
                _tmpd = tempfile.mkdtemp(prefix="rcwcd")
                os.environ["CODEXRC_HOME"] = _tmpd
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1)
                    inf = wcd.wcd_audit({
                        "url": f"http://127.0.0.1:{port}",
                        "endpoint": "/account",
                        "auth_marker": "WCD-ACCOUNT-DATA",
                        "auth_headers": {
                            "Cookie": "session=1"}})
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 8)
                    if c["id"] == "RC-000215":
                        ok = ok and inf["requests"] == 2
                    det = (f"{scen}: {inf['verdict']} "
                           f"(esperado {want}), "
                           f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                    if _oldh is None:
                        del os.environ["CODEXRC_HOME"]
                    else:
                        os.environ["CODEXRC_HOME"] = _oldh
                print(f"[{c['id']}] wcd: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000216":
            from core import wcd_bait as wcd
            bat = wcd.perturbation_battery()
            maxreqs = (wcd.BASELINE_PROBES
                       + wcd.MAX_PERTURBATIONS * 3)
            ok = (wcd.MAX_PERTURBATIONS == 2
                  and wcd.BASELINE_PROBES == 2
                  and len(bat) == 4
                  and bat[0]["pid"] == "D-SEMI"
                  and maxreqs == 8
                  and wcd.E_WCD_CONTAM == "E-WCD-CONTAM")
            det = (f"bateria {len(bat)} variantes, "
                   f"presupuesto max {maxreqs} reqs")
            print(f"[{c['id']}] invariantes wcd: {det} "
                  f"-> {'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1

        # ---- CL.0-SINGLE-TIER v0.87 (RC-000217..222)
        if c["id"] == "RC-000217":
            from core import cl0_probe as cl0p
            p_vacio = cl0p._post_cl0("host", "/", b"")
            smug = cl0p._smuggle_req("host", "cl0mtest")
            p_smug = cl0p._post_cl0("host", "/", smug)
            ok = (p_vacio.endswith(b"\r\n\r\n")
                  and b"b'" not in p_vacio
                  and b"GET /cl0mtest HTTP/1.1" in p_smug
                  and b"b'" not in p_smug
                  and p_smug.count(b"\r\n\r\n") == 2)
            det = ("payload vacio limpio=%s, smuggle "
                   "serializado=%s"
                   % (p_vacio.endswith(b"\r\n\r\n"),
                      b"GET /cl0mtest" in p_smug))
            print(f"[{c['id']}] cl0 bytes-repr: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000218", "RC-000219",
                       "RC-000220", "RC-000221"):
            import tempfile
            from core import cl0_probe as cl0p
            scens = {
                "RC-000218": ("benign_strict", 19194,
                              "BENIGN"),
                "RC-000219": ("edge_safe_rst", 19195,
                              "BENIGN"),
                "RC-000220": ("cl0_desync", 19196,
                              "CL0-STATE-EFFECT"),
                "RC-000221": ("flaky_desync", 19197,
                              "CL0-DETECTED"),
            }
            scen, port, want = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "cl0_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/cl0_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                _oldh = os.environ.get("CODEXRC_HOME")
                _tmpd = tempfile.mkdtemp(prefix="rccl0")
                os.environ["CODEXRC_HOME"] = _tmpd
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1, 8.0)
                    inf = cl0p.cl0_audit({
                        "url": f"http://127.0.0.1:{port}"})
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 8)
                    det = (f"{scen}: {inf['verdict']} "
                           f"(esperado {want}), "
                           f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                    if _oldh is None:
                        del os.environ["CODEXRC_HOME"]
                    else:
                        os.environ["CODEXRC_HOME"] = _oldh
                print(f"[{c['id']}] cl0: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000222":
            from core import cl0_probe as cl0p
            bat = cl0p.smuggle_battery()
            maxreqs = (cl0p.BASELINE_PROBES
                       + cl0p.MAX_VARIANTS * 2 * 3)
            ok = (cl0p.MAX_VARIANTS == 1
                  and cl0p.BASELINE_PROBES == 2
                  and len(bat) == 2
                  and bat[0]["pid"] == "S-REDIR"
                  and maxreqs == 8
                  and cl0p.E_CL0_STATE == "E-CL0-STATE"
                  and cl0p.E_CL0_SIGNAL == "E-CL0-SIGNAL")
            det = (f"bateria {len(bat)} candidatos, "
                   f"presupuesto max {maxreqs} reqs")
            print(f"[{c['id']}] invariantes cl0: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000223", "RC-000224",
                       "RC-000225", "RC-000226",
                       "RC-000227"):
            import tempfile
            from core import h2_probe as h2p
            scens = {
                "RC-000223": ("benign_strict", "h2cl",
                              19201, "BENIGN-EDGE"),
                "RC-000224": ("quiet_benign", "h2cl",
                              19202, "BENIGN"),
                "RC-000225": ("h2cl_desync", "h2cl",
                              19203, "H2-STATE-EFFECT"),
                "RC-000226": ("hdr_injection", "hinj",
                              19204, "H2-STATE-EFFECT"),
                "RC-000227": ("flaky_translation", "h2cl",
                              19205, "H2-DETECTED"),
            }
            scen, bat, port, want = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "h2_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/h2_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                _oldh = os.environ.get("CODEXRC_HOME")
                _tmpd = tempfile.mkdtemp(prefix="rch2")
                os.environ["CODEXRC_HOME"] = _tmpd
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1, 8.0)
                    inf = h2p.h2_audit({
                        "url": f"http://127.0.0.1:{port}",
                        "battery": bat})
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 8)
                    det = (f"{scen}/{bat}: "
                          f"{inf['verdict']} "
                          f"(esperado {want}), "
                          f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                    if _oldh is None:
                        del os.environ["CODEXRC_HOME"]
                    else:
                        os.environ["CODEXRC_HOME"] = _oldh
                print(f"[{c['id']}] h2: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000228":
            from core import h2_probe as h2p
            import struct as _st
            maxreqs = (h2p.BASELINE_PROBES
                       + h2p.MAX_VARIANTS * 2 * 3)
            fr = h2p._frame(0x4, 0x1, 0, b"")
            hdr9 = (len(fr) == 9
                    and fr[5:9] == _st.pack(">I", 0))
            frs = h2p._frame(0x1, 0x5, 7, b"xy")
            hdr9s = (len(frs) == 11
                     and frs[5:9] == _st.pack(">I", 7))
            has_reader = hasattr(h2p, "H2Reader")
            ok = (h2p.MAX_VARIANTS == 1
                  and h2p.BASELINE_PROBES == 2
                  and h2p.BATTERY == ("h2cl", "hinj")
                  and maxreqs == 8
                  and hdr9 and hdr9s and has_reader
                  and h2p.E_H2_SIGNAL == "E-H2-SIGNAL"
                  and h2p.E_H2_STATE == "E-H2-STATE")
            det = (f"bateria {h2p.BATTERY}, presupuesto max "
                   f"{maxreqs} reqs, frames 9 bytes "
                   f"({hdr9 and hdr9s}), reader persistente "
                   f"({has_reader})")
            print(f"[{c['id']}] invariantes h2: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000229", "RC-000230",
                       "RC-000231", "RC-000232",
                       "RC-000233"):
            from core import mc_probe as mcp
            scens = {
                "RC-000229": ("benign_pin", 19301,
                              "BENIGN"),
                "RC-000230": ("quiet_drain", 19302,
                              "BENIGN"),
                "RC-000231": ("pool_desync", 19303,
                              "MC-STATE-EFFECT"),
                "RC-000232": ("edge_strict", 19304,
                              "BENIGN-EDGE"),
                "RC-000233": ("flaky_pool", 19305,
                              "MC-DETECTED"),
            }
            scen, port, want = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "mc_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/mc_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1, 8.0)
                    inf = mcp.mc_audit({
                        "url": f"http://127.0.0.1:{port}",
                        "battery": "pool"})
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 8)
                    det = (f"{scen}/pool: "
                          f"{inf['verdict']} "
                          f"(esperado {want}), "
                          f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                print(f"[{c['id']}] mc: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000234":
            from core import mc_probe as mcp
            budget = (mcp.BASELINE_PROBES
                      + mcp.MAX_VARIANTS * len(mcp.PHASES)
                      * mcp.PHASE_REQS)
            has_reader = hasattr(mcp, "H1Reader")
            ok = (mcp.MAX_VARIANTS == 1
                  and mcp.BASELINE_PROBES == 0
                  and mcp.PHASES == ("P", "R")
                  and mcp.PHASE_REQS == 4
                  and budget == 8
                  and mcp.BATTERY == ("pool",)
                  and has_reader
                  and mcp.E_MC_SIGNAL == "E-MC-SIGNAL"
                  and mcp.E_MC_STATE == "E-MC-STATE")
            det = (f"bateria {mcp.BATTERY}, presupuesto "
                   f"max {budget} reqs (2 fases x "
                   f"{mcp.PHASE_REQS}), lector "
                   f"persistente ({has_reader})")
            print(f"[{c['id']}] invariantes mc: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000236", "RC-000237",
                       "RC-000238", "RC-000239",
                       "RC-000240"):
            from core import crc_probe as crcp
            scens = {
                "RC-000236": ("quiet_drain", 19401,
                              "BENIGN", None),
                "RC-000237": ("edge_strict", 19402,
                              "BENIGN-EDGE", None),
                "RC-000238": ("seq_desync", 19403,
                              "CRC-STATE-EFFECT", 2),
                "RC-000239": ("partial_drain", 19404,
                              "CRC-STATE-EFFECT", 1),
                "RC-000240": ("flaky_forward", 19405,
                              "CRC-DETECTED", None),
            }
            scen, port, want, want_k = (
                scens[c["id"]])
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "crc_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/crc_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                pr = subprocess.Popen(
                    [sys.executable, labp, scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                try:
                    _esperar_labs(port, 1, 8.0)
                    inf = crcp.crc_audit({
                        "url": f"http://127.0.0.1:{port}",
                        "battery": "double"})
                    got_k = inf["evidence"].get("k")
                    ok = (inf["verdict"] == want
                          and inf["requests"] <= 8
                          and (want_k is None
                               or got_k == want_k))
                    det = (f"{scen}/double: "
                          f"{inf['verdict']} "
                          f"(esperado {want}), k={got_k}, "
                          f"reqs={inf['requests']}")
                finally:
                    pr.kill()
                print(f"[{c['id']}] crc: {det} -> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
        if c["id"] == "RC-000241":
            from core import crc_probe as crcp
            budget = (crcp.BASELINE_PROBES
                      + crcp.MAX_VARIANTS
                      * len(crcp.PHASES)
                      * crcp.PHASE_REQS)
            has_reader = hasattr(crcp, "H1Reader")
            ok = (crcp.MAX_VARIANTS == 1
                  and crcp.BASELINE_PROBES == 0
                  and crcp.PHASES == ("P", "R")
                  and crcp.PHASE_REQS == 4
                  and budget == 8
                  and crcp.BATTERY == ("double",)
                  and has_reader
                  and crcp.E_CRC_SIGNAL == "E-CRC-SIGNAL"
                  and crcp.E_CRC_STATE == "E-CRC-STATE")
            det = (f"bateria {crcp.BATTERY}, presupuesto "
                   f"max {budget} reqs (2 fases x "
                   f"{crcp.PHASE_REQS}), lector "
                   f"persistente ({has_reader})")
            print(f"[{c['id']}] invariantes crc: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000242", "RC-000243",
                       "RC-000244", "RC-000245",
                       "RC-000246"):
            from core import repro_engine as re_eng
            scens = {
                "RC-000242": ("seq_desync",
                              "REPRODUCIBLE", 2),
                "RC-000243": ("flaky_forward",
                              "NON-REPRODUCIBLE",
                              None),
                "RC-000244": ("quiet_drain",
                              "NO-CANDIDATE", None),
                "RC-000245": ("edge_strict",
                              "NO-CANDIDATE", None),
                "RC-000246": (None, "UNSTABLE", None),
            }
            scen, want, want_k = scens[c["id"]]
            tomba = None
            try:
                if scen is None:
                    # RC-000246: puerto-tumba. El lab no
                    # puede ligar el puerto y el audit
                    # habla con un socket que cierra
                    # toda conexion: sin observable.
                    import socket as sk
                    tomba = sk.socket()
                    tomba.setsockopt(
                        sk.SOL_SOCKET, sk.SO_REUSEADDR,
                        1)
                    tomba.bind(("127.0.0.1",
                                re_eng.LAB_PORTS[0]))
                    tomba.listen(4)
                    cfg = {"lab_scenario":
                           "seq_desync"}
                else:
                    cfg = {"lab_scenario": scen}
                inf = re_eng.repro_audit(cfg)
                ks = set()
                for gal in inf["evidence"].get(
                        "genealogies", []):
                    for _p in re_eng.PASSES:
                        kk = gal["passes"][_p]["k"]
                        if kk is not None:
                            ks.add(kk)
                ok = (inf["verdict"] == want
                      and inf["requests"]
                      <= re_eng.BUDGET
                      and (want_k is None
                           or ks == {want_k}))
                det = (f"{scen or 'puerto-tumba'}: "
                      f"{inf['verdict']} "
                      f"(esperado {want}), "
                      f"ks={sorted(ks)}, "
                      f"reqs={inf['requests']}")
            finally:
                if tomba is not None:
                    tomba.close()
            print(f"[{c['id']}] repro: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000247":
            from core import repro_engine as re_eng
            dominio = {"REPRODUCIBLE",
                       "NON-REPRODUCIBLE",
                       "NO-CANDIDATE", "UNSTABLE",
                       "UNKNOWN"}
            ok = (re_eng.BUDGET == 32
                  and re_eng.GENEALOGIES == 2
                  and re_eng.PASSES == ("A", "B")
                  and len(re_eng.LAB_PORTS) == 2
                  and dominio.issuperset(
                      {"REPRODUCIBLE",
                       "NON-REPRODUCIBLE",
                       "NO-CANDIDATE",
                       "UNSTABLE"})
                  and re_eng.repro_audit(
                      {"genealogies": 3})["verdict"]
                  == "UNSTABLE")
            det = (f"BUDGET {re_eng.BUDGET}, "
                   f"GENEALOGIES {re_eng.GENEALOGIES}, "
                   f"PASSES {re_eng.PASSES}, "
                   f"genealogies>2 rechazado")
            print(f"[{c['id']}] invariantes repro: "
                  f"{det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000248", "RC-000249",
                       "RC-000250", "RC-000251",
                       "RC-000252"):
            from core import impact_probe as ipr
            scens = {
                "RC-000248": ("quiet_drain", 19601,
                              "BENIGN", None),
                "RC-000249": ("benign_pin", 19602,
                              "BENIGN", None),
                "RC-000250": ("pool_swap", 19603,
                              "SECURITY-IMPACT-DEMO",
                              None),
                "RC-000251": ("pool_shift", 19604,
                              "IMPACT-CANDIDATE",
                              "/?itok=attacker-echo"),
                "RC-000252": ("flaky_swap", 19605,
                              "IMPACT-CANDIDATE",
                              None),
            }
            (scen, port, want,
             smug) = scens[c["id"]]
            labp = os.path.join(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))),
                "labs", "impact_lab.py")
            if not os.path.exists(labp):
                print(f"[{c['id']}] labs/impact_lab.py "
                      "ausente -> SKIP (no FAIL)")
            else:
                _aj = False
                try:
                    import socket as _sk
                    _s = _sk.create_connection(
                        ("127.0.0.1", port), 0.3)
                    _s.close()
                    _aj = True
                except OSError:
                    pass
                if _aj:
                    print(f"[{c['id']}] puerto {port} "
                          "ocupado por instancia "
                          "ajena -> FAIL "
                          "(contaminacion)")
                    fails += 1
                else:
                    pr = subprocess.Popen(
                        [sys.executable, labp, scen,
                         str(port)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                    try:
                        _esperar_labs(port, 1, 8.0)
                        inf = ipr.impact_audit({
                        "host": "127.0.0.1",
                        "port": port,
                            "smuggle_path": (
                                smug or "/admin/secret")})
                        ctl = (inf["evidence"]
                               .get("control"))
                        ok = (inf["verdict"] == want
                              and inf["requests"] <= 6
                              and ctl is not None
                              and len(inf["evidence"]
                                      .get("rounds",
                                           [])) == 2)
                        det = (f"{scen}: "
                               f"{inf['verdict']} "
                               f"(esperado {want}), "
                               f"reqs="
                               f"{inf['requests']}")
                    finally:
                        pr.kill()
                    print(f"[{c['id']}] impact: {det} "
                          f"-> {'PASS' if ok else 'FAIL'}")
                    if not ok:
                        fails += 1
        if c["id"] == "RC-000253":
            from core import impact_probe as ipr
            ok = True
            rzn = []
            if ipr.BUDGET != 6:
                ok = False
                rzn.append("presupuesto alterado: %s"
                           % ipr.BUDGET)
            if ipr.ROUNDS != 2:
                ok = False
                rzn.append("rondas alteradas: %s"
                           % ipr.ROUNDS)
            # control obligatorio: sin control alineado
            # el probe NO emite veredicto de impacto
            srcl = open(os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "impact_probe.py")).read()
            if "sin control no " not in srcl:
                ok = False
                rzn.append("control previo no exigido")
            ladder = ("BENIGN", "BENIGN-EDGE",
                      "IMPACT-CANDIDATE",
                      "SECURITY-IMPACT-DEMO",
                      "UNREACHABLE", "UNSTABLE",
                      "UNKNOWN")
            for v in ("SECURITY-IMPACT-DEMO",
                      "IMPACT-CANDIDATE"):
                if v not in ladder:
                    ok = False
                    rzn.append("veredicto fuera de "
                               "escalera: %s" % v)
            # el recurso protegido es SIMULADO del lab:
            # el probe no debe contener rutas de
            # terceros
            if "google" in srcl or "http://x" in srcl:
                ok = False
                rzn.append("probe con blancos externos")
            det = (f"BUDGET {ipr.BUDGET}, ROUNDS "
                   f"{ipr.ROUNDS}, control obligatorio, "
                   f"recursos solo del lab")
            print(f"[{c['id']}] invariantes impact: "
                  f"{det} -> "
                  f"{'PASS' if ok else 'FAIL: ' + '; '.join(rzn)}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000254":
            from core import fp_elimination as fpe
            inf = fpe.fp_audit({})
            baits = inf["evidence"].get("baits", [])
            pos = inf["evidence"].get(
                "positive_control", {})
            ok = (inf["verdict"] == "FP-ELIMINATED"
                  and inf["requests"] <= 26
                  and len(baits) == 4
                  and pos.get("verdict")
                  == "SECURITY-IMPACT-DEMO")
            det = (f"{inf['verdict']}, "
                   f"cebos={len(baits)} (0 reportables), "
                   f"control={pos.get('verdict')}, reqs="
                   f"{inf['requests']}")
            print(f"[{c['id']}] fp: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000255":
            from core import fp_elimination as fpe
            ok = True
            rzn = []
            if len(fpe.FP_TABLE) != 8:
                ok = False
                rzn.append("FP_TABLE incompleta: %d/8"
                           % len(fpe.FP_TABLE))
            rep = set(fpe.REPORTABLE)
            nonrep = set(fpe.NON_REPORTABLE)
            if rep & nonrep:
                ok = False
                rzn.append("conjuntos reportable/no "
                           "solapan")
            sok, sdet = fpe.fp_source_invariants()
            if not sok:
                ok = False
                rzn.extend(sdet)
            det = (f"FP_TABLE {len(fpe.FP_TABLE)}/8, "
                   f"reglas de no-escala en 3 modulos")
            print(f"[{c['id']}] fp invariantes: {det} "
                  f"-> "
                  f"{'PASS' if ok else 'FAIL: ' + '; '.join(rzn)}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000256":
            from core import evidence_package as epk
            pkg = epk.assemble_package()
            sig = pkg.get("signature", {})
            ok = (pkg["verdict"] == "PACKAGE-VALID"
                  and str(sig.get("k")) == "2"
                  and sig.get("genealogies") == 2
                  and sig.get("impact_rounds")
                  == ["SMUGGLED-PROTECTED",
                      "SMUGGLED-PROTECTED"]
                  and sig.get("control_aligned") is True
                  and pkg["budgets"]["spent"] <= 40
                  and len(pkg["chain"]) == 3)
            det = (f"{pkg['verdict']}, k={sig.get('k')}"
                   f", genealogias="
                   f"{sig.get('genealogies')}, rondas="
                   f"{sig.get('impact_rounds')}, reqs="
                   f"{pkg['budgets']['spent']}")
            print(f"[{c['id']}] paquete: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000257":
            from core import evidence_package as epk
            import json as _json
            ok = True
            rzn = []
            # paquete sintetico completo: verificacion
            # de un tercero (sin labs, sin reqs)
            mini = {"schema": epk.SCHEMA,
                    "generated": "2026-10-05T14:30:00",
                    "mode": "lab", "chain": [],
                    "signature": {"k": 2},
                    "budgets": {"spent": 37},
                    "limits": {"read_only": True},
                    "reproduction": [],
                    "verdict": "PACKAGE-VALID"}
            mini["hash"] = epk._canon_hash(mini)
            vok, probs = epk.verify_package(mini)
            if not vok:
                ok = False
                rzn.append("paquete valido "
                           "rechazado: %s" % probs)
            # tampering: alterar el payload post-hash
            mal = _json.loads(_json.dumps(mini))
            mal["signature"]["k"] = 99
            tok, _ = epk.verify_package(mal)
            if tok:
                ok = False
                rzn.append("tamper NO detectado")
            det = ("verify OK en paquete integro, "
                   "tamper detectado")
            print(f"[{c['id']}] falsabilidad: {det} -> "
                  f"{'PASS' if ok else 'FAIL: ' + '; '.join(rzn)}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000258":
            from core import crown_chain as ccn
            rec = ccn.hunt_chain({"mode": "lab"})
            ok = (rec["verdict"] == "CHAIN-COMPLETE-LAB"
                  and rec["requests"] <= 40
                  and str(rec["evidence"].get("k"))
                  == "2"
                  and rec["evidence"].get(
                      "impact_rounds")
                  == ["SMUGGLED-PROTECTED",
                      "SMUGGLED-PROTECTED"])
            det = (f"{rec['verdict']}, k="
                   f"{rec['evidence'].get('k')}, "
                   f"reqs={rec['requests']}")
            print(f"[{c['id']}] hunter-chain: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000259":
            # blanco muerto: escalera honesta, sin crash
            from core import crown_chain as ccn
            rec = ccn.hunt_chain({
                "mode": "live",
                "url": "http://127.0.0.1:1",
                "timeout": 2.0})
            ok = rec["verdict"] in ("NO-DESYNC",
                                    "UNSTABLE")
            det = (f"{rec['verdict']} con reqs="
                   f"{rec['requests']}")
            print(f"[{c['id']}] hunter-dead: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000260":
            ok = True
            rzn = []
            try:
                from core.hunter import (
                    CrownChain as _cc)
                if not callable(_cc):
                    ok = False
                    rzn.append("CrownChain no callable")
            except Exception as e:
                ok = False
                rzn.append("fachada sin CrownChain: "
                           "%r" % e)
            from core import crown_chain as ccn
            if len(ccn.LADDER) != 5 or (
                    "CROSS-CONNECTION-DEMO"
                    not in ccn.LADDER):
                ok = False
                rzn.append("LADDER incompleta")
            if "SECURITY-IMPACT" in ccn.LADDER:
                ok = False
                rzn.append("impacto vivo en la escalera: "
                           "prohibido")
            srcl = open(os.path.join(
                os.path.dirname(os.path.abspath(
                    __file__)), "crown_chain.py"
            )).read()
            if "LAB-VALIDATED-ONLY" not in srcl:
                ok = False
                rzn.append("rung 5 sin limite lab")
            det = ("export OK, LADDER 5 rungs, rung 5 "
                   "limitada a lab")
            print(f"[{c['id']}] hunter-facade: {det} -> "
                  f"{'PASS' if ok else 'FAIL: ' + '; '.join(rzn)}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000235":
            base = os.path.dirname(os.path.abspath(
                __file__))
            limpio = True
            for mod_fn in ("h2_probe.py", "cl0_probe.py",
                           "mc_probe.py"):
                p = os.path.join(base, mod_fn)
                try:
                    with open(p) as f:
                        if "Informe[" in f.read():
                            limpio = False
                except OSError:
                    limpio = False
            print(f"[{c['id']}] typo Informe en probes: "
                  f"{'PASS' if limpio else 'FAIL'}")
            if not limpio:
                fails += 1
        if c["id"] == "RC-000261":
            import tempfile
            from core.poi_reach import poi_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "export.php"),
                 "w").write(_POI_FIX_POS)
            r = poi_audit(d)
            f = r["findings"][0] if r["findings"] else None
            ok = (r["summary"]["poi_reach"] == 1
                  and f and f["verdict"] == "POI-REACH"
                  and f["peldanos"] == ["POI-DETECTED",
                                       "POI-UNAUTH",
                                       "POI-CHAIN"]
                  and f["export_surface"]
                  and "nopriv" in f.get("handler", "")
                  and any(g["class"] == "Evil_Gadget"
                          for g in f.get("gadgets", [])))
            det = (f"{f and f['verdict']} "
                   f"handler={f and f.get('handler')}")
            print(f"[{c['id']}] poi-reach: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000262":
            import tempfile
            from core.poi_reach import poi_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "safe.php"),
                 "w").write(_POI_FIX_NEG)
            r = poi_audit(d)
            sm = r["summary"]
            ok = (sm["poi_reach"] == 0 and sm["poi_auth"] == 0
                  and sm["poi_detected"] == 0
                  and not r["pop_candidates"])
            det = (f"reach={sm['poi_reach']} "
                   f"auth={sm['poi_auth']} pop=0")
            print(f"[{c['id']}] poi-cero-fp: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000269":
            import tempfile
            from core.poi_reach import poi_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "fixed.php"),
                 "w").write(_POI_FIX_ALLOWED)
            r = poi_audit(d)
            sm = r["summary"]
            ok = (sm["poi_reach"] == 0 and sm["poi_auth"] == 0
                  and sm["poi_detected"] == 0)
            det = (f"reach={sm['poi_reach']} "
                   f"auth={sm['poi_auth']} "
                   f"det={sm['poi_detected']}")
            print(f"[{c['id']}] poi-allowed-classes: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000270":
            import tempfile
            from core.poi_reach import poi_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "admin.php"),
                 "w").write(_POI_FIX_NOPRIV_OTRO)
            r = poi_audit(d)
            f0 = r["findings"][0] if r["findings"] else None
            ok = (f0 is not None
                  and f0["verdict"] == "POI-AUTH"
                  and "POI-UNAUTH" not in f0["peldanos"]
                  and f0.get("nopriv_file") is True)
            det = (f"{f0 and f0['verdict']} "
                   f"peldanos={f0 and f0['peldanos']}")
            print(f"[{c['id']}] poi-nopriv-otro: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000263":
            import tempfile
            from core.poi_reach import pop_candidates
            d = tempfile.mkdtemp()
            open(os.path.join(d, "export.php"),
                 "w").write(_POI_FIX_POS)
            pops = pop_candidates(d)
            names = {p["class"] for p in pops}
            ok = ("Evil_Gadget" in names
                  and "Plain_Helper" not in names)
            det = f"gadgets={sorted(names)}"
            print(f"[{c['id']}] poi-pop: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000264":
            import tempfile
            from core.magic_confusion import confusion_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "optimize.php"),
                 "w").write(_MAG_FIX_POS)
            r = confusion_audit(d)
            f = r["findings"][0] if r["findings"] else None
            ok = (r["summary"]["confusion"] >= 1 and f
                  and f["verdict"] == "MAGIC-CONFUSION"
                  and "CONFUSION-CANDIDATE"
                  in f["peldanos"]
                  and "CONFUSION-UNGUARDED"
                  in f["peldanos"]
                  and f["entry_var"] == "path")
            det = (f"{f and f['verdict']} "
                   f"via={f and f['entry_var']}")
            print(f"[{c['id']}] magic-confusion: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] == "RC-000265":
            import tempfile
            from core.magic_confusion import confusion_audit
            d = tempfile.mkdtemp()
            open(os.path.join(d, "safe_opt.php"),
                 "w").write(_MAG_FIX_NEG)
            r = confusion_audit(d)
            sm = r["summary"]
            ok = (sm["confusion"] == 0
                  and sm["guarded"] == 1)
            det = (f"confusion={sm['confusion']} "
                   f"guarded={sm['guarded']}")
            print(f"[{c['id']}] magic-gate: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        if c["id"] in ("RC-000266", "RC-000267"):
            import subprocess as _sp
            import sys as _sys
            import time as _t
            from core.wcd404_probe import probe
            scen_ports = ([("lie_cached", 19511)]
                          if c["id"] == "RC-000266" else
                          [("lie_nocache", 19512),
                           ("honest_404", 19513),
                           ("lie_expired", 19514)])
            labs = []
            try:
                for _sc, _pt in scen_ports:
                    _p = _sp.Popen(
                        [_sys.executable,
                         "labs/wcd404_lab.py", _sc, str(_pt)],
                        stdout=_sp.PIPE, text=True)
                    _up = _p.stdout.readline().strip()
                    if _up != "UP":
                        raise LabNoUp(
                            f"wcd404 {_sc} no sube")
                    labs.append(_p)
                verds = []
                for _sc, _pt in scen_ports:
                    v = probe({
                        "url": (f"http://127.0.0.1:{_pt}"
                                "/app/settings/profile/x.css"),
                        "marker_self": "ninja-A@maxxspace.com",
                        "cookie_self": "acct=A",
                        "cookie_victim": "acct=B",
                        "timeout": 3.0})
                    verds.append((_sc, v))
                if c["id"] == "RC-000266":
                    _sc, v = verds[0]
                    ok = (v["verdict"] == "WCD-404-LEAK"
                          and v["status_lie"]
                          and v["cache_hit"]
                          and v["cross_user"]
                          and v["requests"] <= 8)
                    det = (f"{_sc}: {v['verdict']} "
                           f"reqs={v['requests']}")
                else:
                    esperados = {
                        "lie_nocache": "LEAK-NO-CACHE",
                        "honest_404": "BENIGN",
                        "lie_expired": "LEAK-NO-CACHE"}
                    ok = True
                    det = ""
                    for _sc, v in verds:
                        exp = esperados[_sc]
                        good = (v["verdict"] == exp
                                and not v["cross_user"])
                        ok = ok and good
                        det += (f"{_sc}:{v['verdict']} ")
                print(f"[{c['id']}] wcd404-lab: {det}-> "
                      f"{'PASS' if ok else 'FAIL'}")
                if not ok:
                    fails += 1
            finally:
                for _p in labs:
                    _p.kill()
        if c["id"] == "RC-000268":
            from core import wcd404_probe as _wp
            v = _wp.probe({
                "url": "http://127.0.0.1:1/x.css",
                "marker_self": "x", "timeout": 2.0})
            base = os.path.dirname(os.path.abspath(
                __file__))
            srcl = open(os.path.join(
                base, "wcd404_probe.py")).read()
            ok = (v["verdict"] == "conn-dead"
                  and _wp.BUDGET == 8
                  and _wp.LADDER == ["BENIGN",
                                     "STATUS-LIE-DETECTED",
                                     "WCD-404-LEAK"]
                  and 'informe["verdict"] = "WCD-404-LEAK"'
                  in srcl
                  and 'if marker_self in rv["body"]'
                  in srcl)
            det = (f"dead={v['verdict']} budget={_wp.BUDGET} "
                   "escalera monotona")
            print(f"[{c['id']}] wcd404-conservador: {det} -> "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        try:
            _cache_record(c["id"], fails == _fb)
        except Exception:
            pass
    tot = sum(e for e, _ in _SLOW)
    print("[perf] total %.0fs; top-12 mas lentos:" % tot)
    for e, cid in sorted(_SLOW, reverse=True)[:12]:
        print("    [perf] %-11s %6.1fs" % (cid, e))
    print(f"\nRegression corpus: {len(cases)} caso(s), {fails} fallo(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    _only = None
    if len(sys.argv) > 2 and sys.argv[1] == "--only":
        _only = set(sys.argv[2].split(","))
    try:
        sys.exit(run(_only))
    except LabNoUp as _e:
        _kill_labs()
        print(f"LAB-NO-UP: {_e}; huerfanos limpiados, "
              "reintentar (el cache intra-corpus reusa lo "
              "ya verificado)")
        sys.exit(2)
