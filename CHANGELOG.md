## v0.63.0 — AUTHZ-PROOF capa 3: resolucion de hooks dinamicos (RC-000149)

GATES-AUDIT dejaba CALLBACK-NO-RESUELTO (o directamente no veia)
los handlers registrados con nombre de hook o callback dinamico —
justo el patron que usan los plugins ofuscados o con loaders
complejos. Ahora se resuelven 6 clases:

- add_action($hook, ...) con $hook por constante, concatenacion
  ('wp_ajax_' . $this->prefix . '_save') o interpolacion
  ("wp_ajax_nopriv_x"): propagacion de constantes lite por archivo
  (vars + $this->props, ultima asignacion previa al uso).
- add_action('hook', $cb) con callback en variable.
- array($this, $m_var) con metodo en variable.
- Closures en linea: el cuerpo se analiza directamente (PROTEGIDO
  si tiene nonce/caps dentro del closure).
- _action_args corta comas SOLO a profundidad 0 (array($this,'m')
  ya no se rompe).
- 💥 BUG HEREDADO corregido en FUNC_RE: el prefijo consumia el
  salto de linea previo (off-by-one) y firmas de funciones SIN
  docblock precedidas por '}' devolvian cuerpo VACIO -> caps/nonce
  falsos -> veredictos sin haber leido el handler. Latente desde
  v0.43.0; invisible en plugins con docblocks (estandar WP) pero
  activo en codigo sucio (mid-band). Fix: ln = src[:m.end()].

Validacion: repro sintetico 6/6 (corpus RC-000149, regresion 20/20
PASS) + eRoom 1.7.1 real: 17 hooks, 0-day nopriv_stm_zoom_meeting_sign
sigue CANDIDATO-BAC, 12 PROTEGIDO intactos.

## v0.62.8 — FP-FILTER de reflejo en pagina de bloqueo WAF

Leccion greenlightdispensary (03/10): el Arsenal reporto 16
"XSS REFLEJADO MEDIA" que eran puro eco de la URL en el HTML de
bloqueo de Cloudflare (estados 403/429). El WAF eco la URL
completa (con el payload) en su pagina de "Access denied", y el
motor contaba eso como reflexion del sitio.

- Arsenal (frontend/arsenal.html): confirmo() descarta el
  reflejo si el estado es 403/429/503; log explicito
  "reflejo descartado: pagina de bloqueo WAF".
- core/hunter_xss.py (test_param, camino clasico): reflejo en
  403/429/503 = DESCARTADO con log.
- core/async_lane.py (SLIPSTREAM): mismo filtro; ademas
  _probe devuelve el OBJETO respuesta, asi el WafGuard.observe
  vuelve a ver status/headers (antes recibia solo .text y no
  detectaba NINGUN bloqueo en el carril async).

## v0.62.2 — capa UI/UX del pipeline y la navegacion

Presentacion unicamente; sin cambios en UNIVERSAL-ENGINE,
TAINT-TRACE, EVIDENCE-CHAIN ni ningun modulo de caza.

- Backend: helper _frontend_page con Cache-Control no-store
  para las TRES paginas (/, /hunter.html, /arsenal.html):
  Android ya no conserva un HTML viejo.
- Nav: activa por location.pathname en los tres HTML
  (initMobileNavigation), nunca mas hardcodeada; al navegar
  se cierra el menu movil (nav-open).
- Pipeline movil: el flex-wrap muere. Grid de 2 columnas
  minmax(0,1fr); los .conn no participan del layout; los
  nodos llenan su celda -> CVE/REPORT quedan alineados.
- Luces de esquina: running = ambar con pulso alterno
  (corner-pulse-a/b sobre ::before/::after); success = verde
  fija. Solo el nodo RUNNING se anima; los success quedan en
  luz estable (baratisimo en un telefono).
- #matrix oculto en movil (<=820px): cero trabajo constante
  de canvas en telefonos viejos.
- prefers-reduced-motion: animaciones y transiciones a
  0.001ms.

## v0.62.1 — HUNTER anonimo con potencia completa

- MODO SIN SESION: nueva bateria _descubrir_acceso_anon. Sin
  credenciales no hay contraste A->B con sesion, pero una ruta
  tipicamente PRIVADA (/dashboard, /admin, /wallet...) que
  responde 200 a un visitante anonimo ES un BAC directo: se
  reporta como hallazgo 'alta' y alimenta la arana como semilla.
- Fingerprint anti-shell corregido: los SPA reales sirven HTML
  byte-identico para toda ruta; la ventana fija de 120 bytes
  tragaba paginas privadas cortas (bug hallado con lab local,
  RC-000145). Ahora: comparacion byte-identica, tolerancia <10.
- Validado: lab con /dashboard + /admin anon -> 2 hallazgos y 2
  seeds; httpbin y vellius (SPA real) -> 0 falsos. Regresion
  18/18.

## v0.62.0 — DIFF-HUNT v2: la fuente cambio, el motor se adapta

- wp.org sello el historial de plugins (oct 2026): la API ya no
  sirve el mapa de versiones, los zips viejos dan 404 y los SVN
  tags estan vacios. El diff entre dos zips murio EN LA FUENTE
  (RC-000144).
- get_versions tolerante a dict y list.
- prepare() fallback FULL-CODE: sin historial -> descarga la
  version ACTUAL y audita todo el codigo vivo (dir_old=None).
- _senales_changelog(): el readme publico sigue diciendo QUE
  parchearon (XSS, SQLi, hardening...) y DONDE; cada corrida
  adjunta las senales de seguridad de las ultimas 3 versiones
  para guiar la caza del parche incompleto.
- Validado en vivo: cola de 29 blancos 29/29 OK en 24s, 37
  hallazgos crudos, 2 SQLi de swift-performance-lite pasaron a
  EVIDENCE-CHAIN -> PROBABLE 3/4 (uno con proof COMPLETE pero
  alcance admin sin resolver, otro INCOMPLETE honesto).

## v0.61.0 — Corpus fresco: VDP-FRESH + prioridad mid-band

PALANCA 1 (corpus fresco automatico):
- core/vdp_fresh.py: snapshots del mapa VDP (GOLDEN LIST) y diff
  semanal -> vdp_nuevos.json. Detecta ALTAS (VDP recien agregado:
  blanco sin competencia, se caza ya), BOUNTY-NUEVOS (sube
  prioridad) y BAJAS (dejar de cazar).
- hunt_wide.py --vdp-nuevos: las altas+ounty entran a la cola sin
  filtro de 90 dias ni corpus (incluso slugs fuera de >=5k) y se
  ordenan al tope con etiqueta NUEVO-VDP.

PALANCA 2 (mid-band 5k-50k):
- Orden de cola: (1) VDP-FRESH, (2) pagables, (3) banda 5k-50k
  (medianos: menos blindaje y competencia que los top), (4) resto
  por installs. Configurable --band, visible en --dry-run.
- --dry-run: imprime la cola ordenada sin cazar.

Razon: DIFF-HUNT mostro que el codigo nuevo de los TOP sale
endurecido; los medianos y los VDP recien agregados son donde la
ventana de ser primeros sigue abierta. Regresion 16/16.

## v0.60.0 — SSA consume la evidencia: FISCAL exige prueba def-use

- ssa.py: def_use_proof() — prueba estructurada {proof, value,
  lineage, source, unknown_ancestors, transformations}. SSA no
  dictamina vulnerabilidad: entrega genealogia del valor.
  Estados: DEF_USE_COMPLETE / INCOMPLETE / NO_SOURCE / UNRESOLVED.
- evidence.py: build_chain adjunta chain['def_use'].
  FISCAL: "taint alcanza el sink" ya no es probado=True incondicional;
  exige DEF_USE_COMPLETE (o fuente directa en el sink).
  DEFENSA: DEF_USE_NO_SOURCE = refutacion fuerte demostrada.
  JUEZ: DEF_USE_INCOMPLETE (ancestros desconocidos) nunca sostiene
  DEMOSTRADO-ESTATICO (cap a PROBABLE, como INTEGRITY).
- RC-000142 (hallado por muestreo antes de concluir seguridad): la
  refutacion NO_SOURCE era inservida con asignaciones condicionales
  (la limpia dentro de un if no mata la version con $_REQUEST en el
  merge). Ahora exige dominancia CFG sobre el sink. Y el pipeline
  crudo filtraba mal las vars sin version.
- Medicion (5 plugins): DESCARTADO 34->37, PROBABLE 115->92,
  CONTESTADO 0->20; 60/149 proofs COMPLETE. Pipeline 231 taint:
  4 refutados con dominancia, 225 con cadena. Regresion 15/15.

## v0.59.0 — Fase 1.5: SSA-lite en TAINT-TRACE

- core/ssa.py: grafo de versiones def-use intra-funcion. Cada
  asignacion crea una version (kind: SOURCE/SANITIZED/PREPARED/
  CONCAT/COPY/CONST/UNKNOWN-FN/UNKNOWN-VAR) con padres y linea.
- El sink ya no reporta "$q aparece cerca": reporta la CADENA
  ($sql <- COPY <- $term <- SOURCE @L11), evidencia directa para la
  capa FISCAL/JUEZ.
- Refutacion conservadora (SSA-REFUTADO): solo cuando el BFS sobre
  TODOS los padres prueba que ninguna version alcanzable trae
  fuente, taint ni valor desconocido. Llamadas no resueltas y vars
  sin version BLOQUEAN la refutacion (jsst SSRF vuelve a vivo).
- Bugs de solidez encontrados y corregidos por muestreo real:
  .= no matcheaba la regex de asignacion; vars interpoladas sin
  version contaban como limpias; refutacion caminaba solo el primer
  padre del DAG.
- Integrado en plugin_batch.py y diff_hunt.py (refutados filtrados,
  cadenas en el output).
- Medicion N1-VDP: 231 taint -> 10 refutados, 219 con cadena, 2 sin
  vars resueltas. Regresion 14/14.

## v0.58.3 — Triage de los 29 cerrado: 0 candidatos, 2 clases semanticas nuevas

- RC-000139 (cmp_router): comparacion dominada POR un gate = corre
  solo tras autenticar = logica interna, no control de acceso.
  js-support-ticket 28 -> 0 (canaddfile x28: form_request router
  dentro de rama nonce-verificada, copiado en 28 controllers).
- RC-000140: comparacion sin sinks dependientes + operando no
  credencial = router de display. Sinks escapados (esc_html/esc_attr/
  wp_kses/sanitize_) no cuentan como efecto sensible. revisionary
  admin notices 1 -> 0 (el "contexto AUTH" venia del texto HTML del
  aviso, no del codigo).
- Credenciales (password/token/session/...) quedan SIEMPRE fuera de
  estas reglas: 6875 sigue vivo.
- Triage congelado en hechos/triage_loosecmp_v0583.json: 29 -> 0
  candidatos reales. La cola vuelve a cero y SSA-lite arranca con el
  corpus limpio.
- Regresion 12/12 PASS.

## v0.58.2 — SEMANTIC CORE: RC-000132 resuelto en el patron BAC

- cfg.py: all_protected(gate_rx, sens_rx) — True/False/None: ¿todos
  los sinks estan dominados por un gate?
- pattern_match.finalize: el handler nopriv resuelto ya NO se descarta
  por "gate visible": el gate limpia solo si DOMINA todas las
  escrituras. Si una rama publica alcanza la escritura sin pasar por
  el gate, el hallazgo se conserva con anotacion RC-000132 (candidato
  real). Fallback a la regla anterior si el CFG no parsea.
- La pregunta abierta de la auditoria ("rama publica por diseno vs
  alcanzable por salto de flujo") queda respondida: dominancia.
- Mediciones: pods FP muerto con prueba de dominancia; N1-VDP 0 BAC
  recuperados y 0 FP resucitados; regresion 11/11.
- Hallazgo colateral: 28 loose-cmp vivos NO TRIADOS en js-support-
  ticket (vivos ya en v0.58.1; nuevos para la cola de triaje).

## v0.58.1 — SEMANTIC CORE Fase 1: CFG + dominancia en produccion

- core/cfg.py (Python puro, ~650 lineas): tokenizer PHP-lite
  (strings/comentarios/heredoc), parser de statements (if/elseif/else
  encadenados, if sin llaves, alt-syntax : ... endif, loops, switch,
  try, HTML embebido ?> ... <?php), CFG intra-funcion y dominadores
  iterativos.
- Consultas: gate_dominates_sink (el gate protege el sink?),
  cmp_router (la comparacion solo rotea hacia region protegida?),
  router_noise.
- Integrado en loose-auth-cmp (RC-000137): la AUTORIDAD es el CFG;
  las ventanas de texto quedan como fallback si el parseo falla.
  Credenciales en operando exigen capability gate (nonce no salva
  un == sobre password).
- Medicion: SNAP 8/8 loose-cmp muertos por dominancia (incluidos los
  2 residuos a 2-3 lineas que la ventana +-1 no veia). Gate a 30+
  lineas detectado en lab. N1-VDP: 48 -> 1 vivo (familia distinta,
  ya cerrada a mano en RC-000134). Lab 6875 SIGUE VIVO.
- Caches por src (funciones y CFG): timeout 300s -> 1.2s en SNAP.
- Regresion: 10/10 PASS.

## v0.58.0 — SEMANTIC CORE (nivel 0): identidad canonica + integridad

Inicio del Semantic Core (recomendacion experta: el motor pasa de
decidir por proximidad textual a decidir por propiedad del programa).

- core/semantic_core.py: FileId = root canonico + ruta relativa
  normalizada. El basename NO es identidad:
  - match por ruta exacta -> INTEGRITY OK (hash sha256-16 de testigo)
  - match solo por basename con UNA coincidencia -> AMBIGUO
  - basename con varias coincidencias (Wpil/Error.php vs
    Wpil/Table/Error.php) -> INTEGRITY FAILURE: NO se elige ninguno
    (antes el bug tomaba el ultimo del os.walk)
- EVIDENCE-CHAIN: build_chain resuelve via semantic_core y expone
  chain.file {file_id, content_hash, integrity}; el JUEZ bloquea
  DEMOSTRADO-ESTATICO si integrity != OK (invariante RC-000127:
  evidencia de archivo equivocado nunca alcanza veredicto alto).
- Cache de indice por root (200 resoluciones: 0.10s).
- Regresion: 10/10 PASS con el nuevo modulo integrado.
- Lab: caso Wpil duplicado resuelto por FAILURE (no elige ninguno),
  hash equivocado -> INTEGRITY FAILURE, veredicto alto bloqueado.

Proxima fase: CFG intra-funcion + dominancia (gate_dominates_sink)
para RC-000132 y cierre de raiz de RC-000136.

## v0.57.10 — RC-000136: gate adyacente mata el loose-cmp

- _GATE_ADJ generalizado (sin hardcodear funciones de plugin):
  current_user_can | user_can( | is_user_logged_in | _can_access
  | wp_die | die( | exit en la misma linea o la anterior a la
  comparacion senalada => esa llamada es el control de acceso
  real; el loose-cmp es router/filtro detras del gate.
- Se evalua ANTES que los tokens AUTH de RC-000135 (los 6 de SNAP
  volvian por el token 'auth' del operando sin pasar por el gate).
- Medicion: los 6 vivos de RC-000135 (todos
  $_GET['auth']==$ntInfo['lcode'] en SNAP) MUEREN. Lab 6875 real
  (== sobre password, sin gate adyacente) SIGUE VIVO.
- Familia loose-cmp N1∩VDP: 29 -> 0 vivos. Cerrada.

## v0.57.9 — RC-000135: loose-cmp exige contexto de AUTORIZACION

- El patron loose-auth-cmp ya no dispara con cualquier == sobre input:
  exige tokens AUTH en el snippet de la comparacion senalada (+-80
  chars) o contexto +-5 lineas.
  - tokens fuertes (password/passwd/user_pass/nonce/capability/
    current_user_can/login/role/privilege/cookie/manage_options):
    valen en snippet O contexto.
  - tokens debiles (auth/token/secret): solo en el snippet, con
    lookbehind anti-'author' (queries de posts usan author).
  - comentarios despojados: 'nonce was verified' en un comentario
    no autoriza nada.
  - snippet tomado de la LINEA SENALADA, no del primer == del cuerpo
    (FP jsst-hooks: checkbox == 1 dentro de funcion de registro).
- Lab: caso real 6875 (== sobre password) SIGUE VIVO; filtros de
  term_id/checkbox/code!='' MUEREN.
- Medicion sobre el N1∩VDP: 23/29 loose-cmp mueren solos. 6 vivos,
  todos la misma clase ($_GET['auth']==$ntInfo['lcode'] en SNAP:
  router de flujo OAuth, admin-gateado por nxs_snap_user_can_access
  en la misma linea).

## v0.57.8 — TRIAJE de los 2 sobrevivientes no-loose-cmp: ambos MUERTOS

- simple-floating-menu (BAC 1177/1214): MUERTO. Cero hooks nopriv/REST
  en el plugin; los handlers imex cuelgan de admin_init con nonce
  dedicado + manage_options. Era RC-000133 puro.
- wc-multivendor-membership (pago degradable 57): MUERTO.
  is_valid_member_id exige member_id == usuario actual; paymode contra
  allow-list doble estricta (enabled ∩ offline); online solo via IPN
  (vendor ya parcheo CVE-2026-12967). RC-000134 al corpus.
- FIX del analisis del re-run: el match por ubicacion confundia TIPOS
  de finding distintos en la misma linea. Sobrevivientes reales del
  N1∩VDP: los 15 loose-cmp, nada mas.

## v0.57.7 — PATRON BAC MIRA EL CUERPO DEL HANDLER (RC-000131/133)

- finalize() postergado: los hallazgos bac-ajax-nopriv esperan a tener el
  mapa de TODAS las funciones escaneadas, resuelven el callback del hook
  ('fn', "fn", array($this|'Cls','method')) y escanean el cuerpo del
  HANDLER en busca de gates (nonce/caps/is_user_logged_in). Handler
  gateado = FP descartado (pods admin_ajax: 20 sinks -> 0).
- Se exige el hook nopriv EN el cuerpo (RC-000133): el patron no dispara
  solo por escribe+input+bonus nonce publico (FP pods admin_save, gate
  en el caller I18n.php:123).
- Lab: vulnerable con nonce publico DISPARA, control gateado MUERE,
  pods y ad-inserter 0 BAC.
- RE-RUN N1∩VDP (12 plugins, $48 hallazgos): 31 mueren solos, 17
  sobreviven (15 loose-cmp + 1 BAC simple-floating-menu + 1 verificacion
  de pago wcfmvm).

## v0.57.6 — TRIAJE BAC N1: pods y ad-inserter, ambos MUERTOS

TRIAJE MANUAL (protocolo BAC: handler -> gate -> impacto):
- pods 3.3.9.2 (PodsAdmin.php:62, $2.600 VDP): MUERTO. nopriv_pods_admin es
  intencional (forms front-end publicos). Gate interno completo: whitelist
  de metodos, nonce pods-method, pods_is_admin para priv, y process_form
  con nonce NUEVO en 3.3.9.2 vinculado a (pod, id, fields, uri, uid) que
  solo se acuna al renderizar un form ya autorizado. No retargeteable.
- ad-inserter 2.8.19 ($2.600 VDP): MUERTO como BAC. nopriv_ai_ajax solo
  expone features publicas (iframe de bloques de ads, ads.txt publico);
  ramas sensibles gated por REMOTE_DEBUGGING default OFF; el write real
  (adsense-client-id) esta en ai_ajax_backend con nonce + manage_options.
  Nota informativa: remote-ads-txt expone ABSPATH/paths a nopriv
  (divulgacion de rutas, severidad baja, tipicamente no pagable).

REGRESS: RC-000131, RC-000132 (clase: nopriv intencional con gate interno,
disparada por el HOOK sin mirar el cuerpo del handler).

## v0.57.5 — TRIAJE SQLI N1: 11/11 FALSOS POSITIVOS, 3 CLASES DE FP ELIMINADAS

TRIAJE MANUAL (backlog wide, SQLi en plugins con VDP pagable):
- unlimited-elements (3/3), js-support-ticket (7/7), revisionary (1/1):
  TODOS MUERTOS. Ningun SQLi explotable. Ningun reporte.

MOTOR (core/taint_trace.py) — 3 clases de FP erradicadas:
- WP-WRAPPER GUARD: ->query()/get_results() sobre WP_Query/WP_Term_Query/
  WP_User_Query/WP_Comment_Query/WP_Site_Query/WP_Network_Query (new o
  global $wp_query) ya no es sink SQLI: core sanitiza internamente.
- PREPARE MULTILINEA: $q = $wpdb->prepare($q, $args) limpia el taint y
  marca la var PREPARADA (sobrevive a acumulaciones .= posteriores).
  Formato con $wpdb->prefix tolerado; placeholder visible en cualquier
  literal del format, no solo el primero.
- SCOPE POR FUNCION: cada function con nombre resetea el taint (semantica
  PHP real); antes una var local no-SQL en otra funcion contaminaba todo
  el archivo. Las closures sin nombre NO resetean (patron add_action).

VALIDACION: unlimited-elements 0 SQLI (antes 3 criticas), revisionary 0
(antes 1), js-support-ticket 0 (antes 20), lab 4/4 (vulnerable sigue
disparando, saneado/wrapper no, $wpdb crudo no se pierde).
NOTA FN aceptada: formato de prepare con input crudo DENTRO del string
+ args aparte (raro) no lo ve taint nivel 1; lo cubre SINK-SCAN/Semgrep.
REGRESS: RC-000128, RC-000129, RC-000130 con repros minimos.

## v0.57.4 — AUDITORIA DE SEGURIDAD DEL PROPIO PROYECTO

AUDITADO (sin cambios necesarios):
- Arsenal: fire/resume/report/extreme exigian token de sesion (30 min) con
  401/403 y log de auditoria con IP de origen. OK.
- log_event: descarta claves password/token/cookies. safe_url: redacta query
  params. safe_auth_info: Authorization [redacted], cookies solo NOMBRES.
- Job dicts: guardan solo opts booleanos, nunca credenciales.
- login_debug: pasos con nombres/conteos/codigos, jamas valores de credenciales.
- field_adapt: registra el NOMBRE del campo requerido, no su valor.

CORREGIDO:
- Server escuchaba en 0.0.0.0: todo el WiFi veia jobs, informes y el Arsenal.
  Ahora 127.0.0.1 por defecto; LAN solo con CODEXRC_LAN=1 (con aviso impreso).
- /api/auth_token devolvia el header Authorization (token de sesion vivo) sin
  autenticacion. Ahora rechaza peticiones no-loopback (403) con log del intento;
  override explicito CODEXRC_LAN_TOKENS=1 para quien lo necesite.
- Aviso al arrancar si ARSENAL_PASSWORD queda en la default 'extremo'.

## v0.57.3 — HIGIENE DE DEPENDENCIAS (Termux-first)

- requirements.txt reescrito: 100% instalable en Termux armv7l. Fuera `rich`
  (declarado pero jamas importado), adentro `websocket-client` (COV-BAIT) y
  `fpdf2` (export PDF) que se usaban sin estar declarados.
- NUEVO requirements-pc.txt: `curl_cffi` sale del requirements base porque
  NO compila en Termux y rompia `pip install -r requirements.txt` completo.
  En PC: `pip install -r requirements-pc.txt`.
- Chromium: `_find_browser()` ahora tambien mira `$PREFIX/bin/*` de Termux
  (repo termux-x11) antes de darse por vencido.
- `/api/status` devuelve `deps`: salud de cada dependencia opcional con su
  fallback documentado (httpx→hilos, websocket→WS off, fpdf→TXT/JSON,
  chromium→fpdf2). Verificar una instalacion de Termux = 1 request.
- Validado: `pip install -r requirements.txt` resuelve limpio (7/7 OK).

## v0.50.0 — CODEX-OBSERVE + CODEX-REGRESS, alcance reducido (2026-10-02)

El usuario comparti una segunda especificacion tecnica: CODEX-OBSERVE (observabilidad)
+ CODEX-INTEL (diagnostico de anomalias) + CODEX-REGRESS (regresion), 8 fases completas
(event collector, anomaly engine, differential/metamorphic/property-based/fuzz testing,
regression corpus, quality gates, IA diagnostica).

Decision de alcance: implementar SOLO lo que protege plata real hoy. Para una herramienta
de caza de bugs pagables, el motor de anomalias/fuzzing/metamorphic testing es inversion de
ingenieria sin payoff claro (no encuentra bugs mas rapido, no cobra bounties). Lo que SI
tiene valor inmediato es no repetir un bug ya corregido.

Implementado:
- `core/observe.py` (CODEX-OBSERVE, Fase 1 reducida): un evento VERDICT_CREATED por cada
  cadena de evidencia resuelta (file, line, verdict, evidence_hash, module_version,
  git_commit, run_id). JSONL en `.codexrc/intelligence/events/<fecha>.jsonl` (gitignored,
  son logs operativos, no conocimiento versionado). Best-effort: si observe falla, la caza
  sigue (nunca bloquea).
- `core/regress.py` (CODEX-REGRESS, Regression Corpus solamente): casos de defectos reales
  confirmados en `.codexrc/intelligence/regressions/corpus.jsonl` (SI versionado en git,
  es conocimiento permanente). Semilla: RC-000127 = el bug de resolucion de rutas de v0.49.0
  (archivos homonimos resolvian al archivo equivocado), fixed_in v0.49.1. `python3
  core/regress.py` reproduce el caso con un root sintetico (Error.php real + Table/Error.php
  homonimo) y falla si el motor vuelve a resolver mal.
- Hook en `evidence.annotate`: cada veredicto generado dispara `log_verdict` automaticamente.

Fuera de alcance (documentado, no implementado): Anomaly Engine (contradicciones, verdict
instability), Differential testing entre versiones, Metamorphic testing, Property-based/fuzz
testing interno, CODEX-INTEL (correlacion/diagnostico asistido por IA), Quality Gates de
release. Se revisara si en el futuro aparecen inconsistencias reales de verdict entre corridas
que justifiquen construir el Anomaly Engine.

## v0.49.1 — EVIDENCE-CHAIN hardening: bug de resolucion de rutas (2026-10-02)

El usuario compartio una especificacion tecnica de Evidence Chain (principios de evidencia, veredictos no monotonicos, reachability honesta). Al contrastarla contra la implementacion v0.47.0, surgio un bug real durante la revision manual de un hallazgo del dia (link-whisper).

- **FIX CRITICO `core/evidence.py build_chain`:** la resolucion de ruta por fallback (cuando `root + basename` no existe) recorria `os.walk` SIN romper el loop externo tras encontrar un candidato por nombre. Si dos archivos comparten basename (ej. `core/Wpil/Error.php` y `core/Wpil/Table/Error.php`), el motor terminaba analizando el ULTIMO archivo visitado, no el correcto. Fix: match por ruta relativa EXACTA primero; fallback a basename solo si no hay match exacto, tomando el PRIMERO (no el ultimo).
- **Saneo indirecto:** `_sanitization_evidence` ahora detecta `$v[] = (int)...` / `absint(...)` / `intval(...)` antes de que `$v` llegue al sink (ej. `implode(',', $v)` dentro de un `$wpdb->query`). Antes solo veia el casteo si envolvia la variable DIRECTAMENTE en la linea del sink.
- **Trazabilidad (`verdict_history` + `evidence_hash`):** cada cadena guarda un hash determinista de su evidencia normalizada y un historial minimo del veredicto emitido, siguiendo la recomendacion de la especificacion de no sobrescribir silenciosamente decisiones.
- **Caso real que lo disparo:** link-whisper (`core/Wpil/Error.php:674`) salia DEMOSTRADO-ESTATICO por el bug de ruta (analizaba `Table/Error.php` en vez de `Error.php`) Y porque no veia el casteo indirecto. Tras el fix: 0 hallazgos vivos (correcto, el dato real se castea a entero antes del `implode`).
- **Regresion:** 4/4 plugins previamente validados limpios (akismet, google-site-kit, wpforms-lite, woocommerce) siguen en 0 hallazgos tras el fix.
- **Nota:** este bug pudo afectar cualquier chain previa donde el archivo del finding tuviera un homonimo en otra carpeta del mismo plugin; alcance exacto no cuantificado (no se re-corrio todo el historico).

## v0.48.0 — WIDE-HUNT: el corpus se multiplica (2026-10-02)

Con los abogados cerrando los falsos positivos solos (v0.47.0), limitar la caza a los VDP de Patchstack dejó de tener sentido técnico: el VDP no decide a quien cazamos, solo a quien reportamos.

- **`core/wide_corpus.py`** — corpus completo de wordpress.org vía API pública (browse=popular, umbral configurable, por defecto ≥5k installs): **3.260 blancos** (2.186 con ≥10k, 466 con ≥100k) en ~16 segundos, refrescable con `--refresh`.
- **`vdp_mapa.json`** — mapa de pagabilidad refrescado de `vdp.patchstack.com/api/database/vdp` (52 páginas): **1.298 VDP únicos, 710 con bounty individual** (de $100 a $14.400).
- **`core/hunt_wide.py`** — runner: cola = corpus ∩ updates frescos (`--dias 90`) menos los ya auditados (`hechos/hunt_wide_done.txt`), DIFF-HUNT en paralelo (`--workers`), y cada hallazgo sale marcado con `vdp` y `paga`. Modo `--solo-pagables` para priorizar. Con `--limit N` para tandas cortas.
- **Fix v0.47.1:** la cadena de evidencia ya no embebe el finding vivo (referencia circular al exportar JSON); guarda copia plana.
- **Validación:** smoke 4/4 (akismet, google-site-kit, wpforms-lite, woocommerce limpios); cola real detectada: 2.108 plugins con updates ≤90 días, 417 pagables.

## v0.47.0 — EVIDENCE-CHAIN + ABOGADOS: razonamiento de evidencia (2026-10-02)

Cambio de filosofía inspirado en RacerD/Infer/Pysa: no preguntar "¿podría ser vulnerable?" sino "¿qué evidencia tengo para afirmar que lo es?". Nuevo `core/evidence.py`:

- **Cadena de evidencia por finding:** SOURCE (¿input controlable por el atacante? con clasificación: superglobal/cookie/header-semi), FLOW (vars tainteadas y saltos), AUTH (compuertas: nonce/caps/nopriv + entrada resuelta por BFS de callers hasta 3 niveles: hook → callers → función del sink), SANITIZATION (sanitizadores en la ruta, incluida la línea del sink), SINK (tipo/línea/severidad), CORRELATION (qué analizadores lo vieron), DYNAMIC (slot para evidencia dinámica futura).
- **Abogados deterministas (el LLM nunca es juez):** FISCAL debe probar los 4 requisitos del ataque (source controlado, taint al sink, sin sanitización efectiva, alcance sin privilegios); DEFENSA busca refutaciones fuertes (gate protegido, sanitizador en ruta, prepare con placeholders, contexto solo-admin, alcance no resuelto) y débiles (media); JUEZ pesa con reglas fijas.
- **Veredictos en escala RacerD (se reporta solo lo demostrable):** CONFIRMED (estática completa + dinámica reproducida), DEMOSTRADO-ESTATICO (prueba estática completa), PROBABLE (flujo probado, alcance sin resolver), CONTESTADO (refutación parcial), DESCARTADO (refutación fuerte). Los DESCARTADO se filtran de los hallazgos vivos de DIFF-HUNT y se contabilizan en `descartados_defensa`.
- **GATES-AUDIT v0.43.1:** parsea hooks registrados vía loader propio (`$this->loader->add_action('wp_ajax_nopriv_x', $obj, 'metodo')`) y deduplica contra HOOK_RE clásico.
- **TAINT-TRACE:** nuevo sink `fsockopen` (red) en la familia SSRF.
- **Validación:** (1) lab 3/3 — handler nopriv sin sanitizar → DEMOSTRADO-ESTATICO (fiscal 4/4), handler con nonce+caps → DESCARTADO por gate, sanitizado con absint → ni genera finding; (2) sobre RegistrationMagic real: los 4 candidatos del admin caen DESCARTADO (nonce+manage_options), el XSS de paypal.php cae DESCARTADO (esc_url en el sink), y el 0-day real del IPN downgrade (`test_ipn`) queda DEMOSTRADO-ESTATICO con alcance SIN AUTENTICACION y salto resuelto `validate_ipn -> callback -> paypal_ipn (wp_ajax_nopriv)`.
- **Integración:** DIFF-HUNT adjunta `_chain` y `_verdict` a cada hallazgo vivo, ordena por veredicto y expone `descartados_defensa`. CLI: `python3 core/evidence.py <plugin_root>` (cadenas de todos los findings taint, ordenadas por veredicto).

## v0.46.0 — VDP-1300: directorio completo de Patchstack (2026-10-02)

- Extracción del directorio publico de VDP activos de patchstack.com/database/vdp
  (1.300 productos con bounty) via navegador real (GHOSTGATE): el endpoint /api/database/vdp
  solo responde con sesion de la app y la WP API (wp.patchstack.com) rechaza IPs no autorizadas.
- Cruce automatico con api.wordpress.org: slug, version, installs, last_updated.
- Lista maestra: cz_hunt/vdp/vdp_full.json (producto, installs, bounty USD, vendor, axp).
- Motivacion: el GOLDEN LIST tenia 76 plugins y el lote 90-dias completo (69 plugins) dio
  0 bugs pagables; el directorio real es 17x mas grande y esta lleno de medianos (1k-100k)
  con bounty ($250-$2,600) poco cazados.

## v0.45.1 — DIFF-HUNT paralelo (2026-10-02)

- core/diff_hunt.py: ThreadPoolExecutor (--workers, default 4); cada slug se diffea y
  escanea en paralelo, reporte de progreso en vivo con flush.
- Uso: python3 core/diff_hunt.py --workers 6 --targets lista.txt

# Changelog de codexRC

Historial completo de versiones, de la más reciente a la más antigua.
Los parches menores (x.y.z) también viven aquí; el README solo lista los hitos.

## v0.45.0 — DIFF-HUNT

Pivote de estrategia: en vez de auditar plugins enteros (los top estan blindados),
caza SOLO el codigo nuevo. `core/diff_hunt.py`: descarga version actual + anterior de
cada slug (API wp.org), calcula diff de lineas agregadas/modificadas en .php propios
(sin vendor/assets), y corre TAINT-TRACE + CVE-MATCH + GATES-AUDIT + FP-AUTO-CLOSE
restringido a esas lineas nuevas. Logica: lo recien escrito no paso por ningun auditor
ni por los bots de los demas hunters. Flujo de operacion: filtrar GOLDEN LIST por
`last_updated <= 21 dias` e `installs >= 10k` (API en paralelo), cazar los diffs de
todos. Validado en vivo: 37 plugins VDP frescos diffeados; cartflows resulto ser un
parche de seguridad (FP), captcha-code-authentication heredo una comparacion floja
solo en registro (categoria no pagada).

## v0.44.0 — FP-AUTO-CLOSE

Nuevo modulo `core/fp_autoclose.py`: segunda capa de verificacion tras GATES-AUDIT.
Reconoce los patrones de falso positivo que se repiten lote tras lote y los dictamina
solo, para que la consola muestre solo hallazgos vivos:
- FP-GATE-PROTEGIDO: el hallazgo cae en un handler con caps y/o nonce.
- FP-SQLI-PREPARE / FP-SQLI-CAST: prepare con placeholders o absint/intval en el flujo.
- FP-XSS-ESCAPED: la linea del sink aplica esc_*/wp_kses/sanitize_*.
- FP-UPLOAD-WHITELIST: la subida valida mime y/o extension (magic bytes incluidos).
- FP-STRICT-IN_ARRAY: in_array con strict=true (sin type juggling).
- FP-GATE-NOPRIV-LOGIN: handler nopriv cuyo callback exige sesion (dispatcher global).
PLUGIN-BATCH: contador `fp-auto=N` por plugin, `criticos` cuenta solo hallazgos vivos,
los autocerrados se muestran solo con `--verbose`, y las acciones publicas por diseno
(notices, reviews, dismiss, formularios de visitantes) ya no cuentan como 💥.
Validado contra los lotes reales del dia: 34 hallazgos autocerrados en 3 plugins que
antes se descartaban a mano, cero vivos perdidos.

## v0.43.0 — GATES-AUDIT — GATES-AUDIT

Nuevo modulo `core/gates_audit.py`: dictamina automaticamente si los handlers de un
plugin estan protegidos. Mapea hooks `wp_ajax` / `wp_ajax_nopriv` / `wc_ajax` y rutas
REST (`permission_callback __return_true`) a su callback, y busca compuertas
(`current_user_can`, `wp_verify_nonce`, `check_ajax_referer`). Veredictos:
CANDIDATO-BAC (anonimo sin caps ni nonce), REVISAR-AUTH (logueado sin caps ni nonce),
PROTEGIDO, REST-ABIERTO. Integrado en PLUGIN-BATCH: cada hallazgo llega anotado con
el veredicto del handler donde cae, y los candidatos van arriba. Parche en TAINT-TRACE:
`implode(array_fill(...%d...))` (placeholders internos) ya no se taintea (FP de prepare).

## v0.42.0 — PLUGIN-BATCH (modo agente)

Un solo comando caza plugins WordPress por slugs: descarga la última versión estable,
corre TAINT-TRACE + CVE-MATCH, filtra ruido de librerías de terceros (vendor, plugin-fw,
assets, codemirror...) y deja solo hallazgos en código propio, marcados con 💥. El flag
`--vdp` anota los plugins con programa VDP activo en Patchstack y `--out` guarda el JSON
completo. ~1-13s por plugin. Uso:

```bash
python3 core/plugin_batch.py slug1 slug2 --vdp vdp_matches.json --out resultados.json
```

## v0.41.0 — VENDOR-FARM

Descubrimiento de familias de vendors WordPress con instalaciones en rango pagable
(10k-200k) vía la API pública de wordpress.org, exclusión de slugs ya auditados y
estimación de paga Patchstack integrada. CLI + POST /api/vendor_farm.

## v0.40.0 — VERIFICACIÓN DEL SISTEMA

El sistema verifica los hallazgos automáticamente (contraste anónimo A→B, doble
petición, CACHE-BAIT contra falsos positivos de cache como `no-store`+`BYPASS`) y los
informes TXT/JSON/PDF exponen solo veredictos automáticos del sistema, sin guías de
verificación manual para el operador.

Lo nuevo de cada entrega, de la más reciente a la más antigua:

- **v0.39.2 — SCHEME-PROBE:** la verificación de sesión ya no depende de leer el JS del sitio (que Cloudflare puede bloquear). Si el token heredado no pasa con el scheme descubierto/default, se prueban EN VIVO `Session`, `Bearer`, `Token`, `JWT`, token plano y cookies (`session_key`, `sessionid`, `session`, `token`); el primero que responde 200 queda instalado en la sesión para todo el escaneo y se registra en el debug. Validado en lab sin JS (peor caso): login → 401 con Bearer → probe detecta `Session` → `api_authenticated` con perfil.
- **v0.39.1 — TOKEN-INHERIT:** SPAs sin cookies (bitevolut, apps React con localStorage) ya no pierden la sesión tras loguear. El Hunter (1) descubre el scheme de autorización leyendo el JS (`Authorization: Session ${a}`, Bearer, Token, JWT), (2) extrae el token del JSON de respuesta del login (`session_key`, `access_token`, `sessionid`...), y (3) lo inyecta en el header `Authorization` para toda la sesión. Antes: login exitoso + verificación 401 (`api_unauthorized_or_error`). Validado en lab: login → token heredado → `/api/auth/me/` 200 con perfil del usuario.
- **v0.39.0 — SPA-DISCOVERY v2:** el descubridor de login en apps JavaScript ya no queda ciego con apps modernas. (1) Extrae endpoints estilo `fetch` (strings sueltos `/api/...`) además de axios `.post()`; (2) rastrea chunks Vite/esbuild con hash (`assets/Login-BBdKUnr1.js`) además de webpack; (3) si Cloudflare bloquea la descarga de JS (403), reintenta con la sesión del escaneo (cloudscraper/GHOSTGATE-LITE hereda el pase); (4) escalera de rutas de login estándar (`/api/auth/login/`, `/api/login/`, `/api/v1/auth/login/`, etc.) cuando el auto-descubrimiento no encuentra nada, en vez de rendirse postean­do a la página HTML (el 405 clásico); (5) descarta un endpoint al primer 404/405 sin quemar los 3 payloads de campo. Validado en lab con estructura Vite+fetch real: descubre login, cuenta y wallet, filtra impersonate/captcha.
- **v0.38.4 — diagnóstico transparente de auth:** cuando el auto-descubrimiento falla por bloqueos de WAF (Cloudflare 403) o el servidor rechaza el POST (405), la UI ahora muestra la razón real (`rechazo_servidor_HTTP_405`, `api_rechazo_credenciales`) en vez del confuso `no_auth_method`.
- **v0.38.3 — guardia blindado en Termux (`auto_update.sh`):** instancia única por lock con PID (dos watchers nunca pelean), resurrección del servidor ante muerte (OOM/Android/crash) con volcado de las últimas 15 líneas de `server.log` como diagnóstico, anti-cuelgue (proceso vivo pero `/health` mudo 3 ciclos → reinicio), anti-bucle (5 caídas seguidas → backoff progresivo 30/60/90/120s en vez de martillar el teléfono), liberación del puerto 8000 por PID con fallbacks `fuser`→`ss`→`lsof` (nunca `pkill -f`), rotación de `auto_update.log` (>512KB conserva 200 líneas), wake-lock automático con aviso si falta Termux:API. Validado en vivo: server muerto a propósito → detectado, diagnosticado y revivido solo; segundo watcher rechazado por el lock. Nota honesta: si Android mata Termux COMPLETO, ningún script interno revive; el ajuste "Batería → Sin restricciones" sigue siendo obligatorio.
- **v0.38.2 — severidad honesta en cadenas XSS:** una cadena XSS+CSP débil o XSS+panel admin solo es CRÍTICA si alguna pieza XSS ejecutó en navegador real (`verificado` por VERITAS/kit PoC). Sin confirmación queda en ALTA "teórica" con la razón visible. Lección del lab real (vellius, 02/10): el sink `location.hash → innerHTML` nunca ejecutó pese al CSP ausente — el Hunter ya no grita CRÍTICA por piezas no confirmadas.
- **v0.38.1 — parche de honestidad en ESCALADA:** si la petición con sesión no devuelve `Set-Cookie` (sesión ya activa, lo normal tras el login), el playbook ya NO afirma "cookies con HttpOnly": indica revisar la cookie a mano en DevTools (columna HttpOnly) para decidir el techo real (hijack vs. lectura en sesión).
- **v0.38.0 — ESCALADA: qué hacer DESPUÉS del aviso crítico.** El CHAIN decía "tenés una cadena crítica" y ahí se quedaba. Ahora, ante cada cadena crítica/alta, el Hunter sigue SOLO hasta el techo con 4 pasos deterministas: (A) **VERITAS dirigido** — re-verifica en navegador real SOLO las piezas XSS de la cadena; para piezas DOM (`location.hash → innerHTML`) arma el canario correcto (`<img onerror>`, porque por innerHTML los `<script>` no ejecutan) y lo mete en el fragmento de la URL; (B) **techo de impacto** — pide el blanco con la sesión heredada y revisa las flags de cookies: una cookie de sesión SIN `HttpOnly` + XSS ejecutable = camino a HIJACK de sesión (el techo), y sube el veredicto; (C) **kit PoC local** — genera `poc/poc_<host>.html`: página atacante local con iframe del blanco + link con hash canario + envío de canario inerte por `postMessage` en varias formas; el operador la abre EN SU MÁQUINA con su sesión y VE si el banner CANARY aterriza dentro del sitio (canario inerte: nada sale del equipo, cero exfiltración); (D) **PLAYBOOK** — pasos ordenados de lo que falta según las piezas (persistencia → XSS almacenado, canal sin click vía postMessage, destino del informe). Todo con aislamiento de fallos: un paso que falla no tumba la caza. Nodo `escalada` en el pipeline tras `chain`, sección ESCALADA en el informe TXT/PDF con el playbook, y `escalaciones` en el resumen. Validado contra el lab real (vellius.com): VERITAS cargó la shell Angular sin bloqueo de CF; sin sesión la lógica del account no corre (por eso el kit PoC es la vía), cookies y veredicto reportados honestos, PoC generado y verificado.
- **v0.37.1 — DECOMPILE en producción (parche de topes).** Probado sobre un APK real de 12MB (F-Droid, 3 DEX, ~30,000 métodos): los topes de muestreo (20,000 strings/métodos, pensados para la araña) dejaban los nombres como "?" en apps grandes. El loader de DECOMPILE ahora levanta hasta 150,000 strings/métodos y 30,000 tipos; el APK completo desensambla en ~3 segundos con todos los nombres resueltos. Nota de caza: apps compiladas con R8 renombran la mayoría de los métodos a a/b/c — `--all` es el modo útil en blancos ofuscados; el filtro sensible brilla en apps sin ofuscar.
- **v0.37.0 — DECOMPILE: DESCOMPILACIÓN PARCIAL (bytecode → pseudocódigo).** Nivel 3 de ingeniería inversa: abre el code_item de cada método del DEX y desensambla sus instrucciones dalvik REALES resolviendo lo que referencian — `v0 = "AKIA..."` (strings), `invoke-static Lic;->verify(v0)` (métodos por clase y nombre), saltos y retornos. El resultado se lee como fuente: el flujo completo de `decryptCard` sin ejecutar nada y sin JRE/dex2jar (que no existen para armv7l). Por defecto descompila solo los MÉTODOS DE LÓGICA SENSIBLE (decrypt/license/sign/verify/auth/checkout); `--all` baja todo. Un secret que aparece como `const-string` dentro del flujo se reporta como crítico "SECRET EN EJECUCIÓN" (está en el camino del código, no en una string suelta). Subset honesto de ~45 opcodes (constantes, strings, fields, invokes, saltos, retornos); un opcode fuera del subset se marca y el método se corta ahí. Contenedores recursivos (APK con varios .dex). CLI: `python3 core/decompile.py <apk|dex> [--all]`. API: `POST /api/decompile`. Validado: DEX sintético con código real decompilado completo (`const-string` + `invoke-static` + `return-void`), secret AKIA detectado en el flujo, dentro de APK.
- **v0.36.0 — REVERSE: INGENIERÍA INVERSA (nivel 2).** Va más allá de la superficie de BIN-AUDIT y lee la ESTRUCTURA interna del artefacto. **DEX (APK):** parse real del formato (string_ids/type_ids/method_ids/class_defs con uleb128) — lista clases, métodos y todas las strings del bytecode; sobre ellas corre el detector de secrets y endpoints (una API key dentro del bytecode DEX es un secret que nadie mira). Detecta app **OFUSCADA** (nombres a/b/c estilo ProGuard/R8) y **métodos de lógica sensible** (decrypt/license/sign/verify/auth/checkout). **CLASS (JAR):** parse del constant pool CAFEBABE — clase, superclase y constantes Utf8 con secrets. **ELF:** tabla de símbolos **interna** (.symtab, no solo la pública .dynsym) — funciones estáticas que revelan la organización (verify_*, decrypt_*), detección de binario **STRIPPED**, secciones `.debug_*` sin limpiar y **entropía por sección** (>7.2 bits/byte = empaquetado/ofuscado UPX-like). Contenedores recursivos: zip/apk/jar anidados se abren y se auditan por dentro. Nivel honesto: parse de formatos + símbolos + entropía (el desensamblado de instrucciones queda como etapa futura). CLI: `python3 core/re_engine.py <path>`. API: `POST /api/re`. Validado: DEX sintético válido parseado completo (4 clases, 2 métodos, 12 strings, secret AKIA y endpoint staging desde el bytecode), .class con sk_live y connection string del constant pool, objeto compilado con `decrypt_card, verify_license` en su .symtab, y detección de STRIPPED en binarios reales del sistema.
- **v0.35.0 — BIN-AUDIT: ANÁLISIS BINARIO/NATIVO.** Va más allá del navegador y del código PHP: abre cualquier artefacto distribuido por un vendor y extrae lo que paga. **Secrets hardcodeados** (crítica; Patchstack paga por "BAC sobre objetos sensibles: API keys, secrets"): claves AWS `AKIA...`, Google `AIza...`, Stripe live `sk_live_...`, GitHub PAT, Slack, JWT embebidos, claves privadas PEM, connection strings con credenciales (`mysql://user:pass@...`), pares `api_key/secret/password = valor`. **Endpoints internos** en el binario (admin/staging/debug = alta). **Imports peligrosos** de la tabla dinámica real de ELF (`system/execve/popen/dlopen/fork`, parse propio de `.dynsym`, 32/64 bits, LE/BE). **Fingerprint**: ELF/PE/Mach-O/zip/jar/apk/gzip, arquitectura y bitness; contenedores zip/apk/jar se abren RECURSIVO (audita cada `.so`/`.dex`/config anidado). Nivel 1 honesto: recon estático (strings, símbolos, secretos, endpoints); desensamblado completo fuera de alcance Python puro. CLI: `python3 core/bin_audit.py <path>`. API: `POST /api/bin`. Validado: SDK sintético con 5 secretos dentro de un zip anidado (5/5), `/bin/sh` real con `execve, fork` en su dynsym (correcto), `.so` limpio = 0 hallazgos.
- **v0.34.0 — CVE-MATCH: APRENDIZAJE DE PATRONES GLOBALES.** Identifica fallos conocidos SIN firmas fijas: cada patrón es una combinación de señales estructurales débiles (hook `wp_ajax_nopriv` +3, escritura +3, input de usuario +2, protección presente −4, nonce impreso público +2 que cancela el veto) que juntas recrean el fallo histórico; al disparar cita la familia: "coincide con CVE-2023-6875 / 0-day AFFI (CZ-HUNT 2026)". 6 familias reales: BAC ajax sin auth (AFFI), type juggling en control de acceso (CVE-2023-6875, con lookbehind para no confundir `===`), IPN downgrade (CVE-2026-9242), SSRF de request, upload sin validación, rol desde request (PrivEsc). **Línea base global:** `--baseline` mide sobre todo el corpus descargado (73,401 archivos PHP) qué % de funciones parecidas SÍ se protege; cada hallazgo anota el outlier ("68% de 1,408 handlers parecidos protegen esto; este NO"). Validación honesta: replicó los 4 patrones del lab, 0 falsos positivos en controles protegidos, y **redescubrió solo el 0-day real de RegistrationMagic** (`validate_ipn` en paypal.php:193) solo por el patrón. CLI: `python3 core/pattern_match.py <path> [--top N] [--json]`. API: `POST /api/patterns`.
- **v0.33.0 — TAINT-TRACE: ANÁLISIS DE FLUJO DE DATOS.** Sigue el valor de un parámetro desde la FUENTE (`$_GET/$_POST/$_REQUEST/$_COOKIE/php://input/$_SERVER`) a través de asignaciones y concatenaciones hasta el SINK peligroso: base de datos (`$wpdb->query/get_var/get_row/get_results`, `mysql_query`), navegador (`echo/print/printf` = XSS), `unserialize` (object injection), `include/require` y funciones de archivos (LFI), `system/exec/eval` (RCE) y `wp_remote_*/curl` (SSRF). Encuentra la vulnerabilidad aunque la respuesta HTTP no muestre nada: **SQLi ciego, XSS en otra página, object injection diferido**. Sanitizadores que cortan el flujo: `intval/absint/sanitize_*/esc_sql/esc_attr/esc_html/esc_url/wp_kses`; `$wpdb->prepare` con placeholders y el dato SOLO en los valores = seguro (detecta además la inyección de cadena de formato). Motor por punto fijo intra-archivo, Python puro, cero dependencias (Termux OK). CLI: `python3 core/taint_trace.py <archivo_o_carpeta> [--json] [--top N]`. API: `POST /api/taint {"path": "...", "top": 20}`. Validado: 3/3 flujos en lab vulnerable (SQLi ciego, XSS, unserialize) y 0 falsos positivos en el control sanitizado; sobre plugins reales endurecidos con `prepare` también da 0 (correcto).
- **v0.32.0 — COV-BAIT (etapa 2): MOTOR DE MUTACIÓN CON FEEDBACK.** Fuzzing guiado por cobertura, estilo XBOW, 100% determinista. (1) **Pistas del código:** antes de mutar, el motor descarga los scripts de la app (los mismos URLs que la cobertura registró) y extrae los nombres de parámetros que el código lee (`URLSearchParams.get(...)`, `getParameter`) — el propio JS dice dónde mirar. (2) **Expansión estructurada (fase A):** BFS sobre el corpus de inputs: cada parámetro pista se sondea con valores canónicos sobre los padres más profundos; si una sonda EJECUTA rangos nuevos, el input entra al corpus y se profundiza desde ahí (hill-climbing). (3) **Mutación aleatoria (fase B):** con el presupuesto restante, añade/muta/quita parámetros con anti-bucles (hash de inputs probados) y freno por estancamiento (12 sondas sin ganancia). Presupuesto fijo de 36 sondas por caza. Reporta las COMBINACIONES que desbloquean funciones escondidas con los nombres de las funciones ejecutadas. Validado en lab: la etapa 1 encontró `secretInit` con `adminmode=1`; la etapa 2, guiada por las pistas `['level','adminmode']`, desbloqueó `secretDeep` con la combinación `adminmode=1&level=x` en la sonda 2. Chrome en modo bajo consumo (banderas de ahorro de RAM para entornos límite).
- **v0.31.0 — COV-BAIT (etapa 1): caza guiada por COBERTURA DE CÓDIGO.** El salto de calidad del arsenal: se enchufa al navegador real vía CDP (protocolo de depuración, cliente websocket propio en Python puro) y mide **QUÉ funciones de JavaScript ejecuta cada sonda** con `Profiler.startPreciseCoverage`. Flujo: (1) baseline — cobertura "pública" de la app al navegar la semilla; (2) sondas de parámetros ocultos (adminmode, debug, role...) — si un parámetro ejecuta rangos de JS que la app NUNCA ejecutó antes, hay un **camino escondido** y se reporta con los nombres de las funciones; (3) páginas descubiertas — mapea qué páginas traen lógica propia nueva. Un parámetro oculto que EJECUTA código es señal mucho más fuerte que una reacción de tamaño/status. Toggle `opt_cov` (apagado por defecto, pesado: levanta Chrome). Sin navegador: se salta con aviso y la caza sigue. Etapa 2: mutación de inputs para maximizar cobertura nueva (fuzzing con feedback) — implementada en v0.32.0.
- **v0.30.0 — BATERÍAS DEDICADAS:** las técnicas de superficie oculta se separan en baterías propias con toggle individual y cobertura expandida: **PATH-BAIT** (LFI/traversal con wrappers php://filter para wp-config y .env, firmas passwd/win.ini/id_rsa, sondas genéricas en parámetros de alto valor; LFI paga en la tabla), **SSTI-BAIT** (fingerprint del motor de plantillas: Jinja2 confirmado con {{7*'7'}}→7777777, Twig, FreeMarker, Velocity, ERB, Smarty; SSTI = RCE en potencia), **CACHE-BAIT** (8 cabeceras unkeyed probadas en múltiples páginas + **web cache deception**: rutas privadas con sufijo .css que sirven los mismos datos privados con content-type cacheable; 100% pasivo, no envenena nada), **GRAPHQL** (descubrimiento por POST y GET, introspección con mapa de tipos = mapa de IDORs, field suggestions cuando la introspección está cerrada, detección de batching con lote inerte de 2). STEALTH-BAIT queda con parámetros ocultos + CRLF + method tampering. Validado 9/10 en laboratorio (el 10° es el camino alternativo de GraphQL con introspección cerrada).
- **v0.29.0 — STEALTH-BAIT (caza de superficie oculta):** 7 técnicas nuevas para blancos blindados, todas en modo lectura A→B con canarios inertes: (1) **parámetros ocultos** — sondea secretos que el frontend nunca muestra (debug, is_admin, role, internal...) y detecta si el backend reacciona; (2) **PATH-BAIT / LFI** — path traversal en parámetros file/path/tpl/lang con firma de detección (passwd, wp-config), LFI paga en la tabla de recompensas; (3) **SSTI-BAIT** — canario de plantillas {{7*7}}: si la respuesta contiene 49 el servidor COMPUTA (RCE en potencia); (4) **CRLF-BAIT** — inyección de cabeceras verificada solo en headers de respuesta; (5) **method tampering** — X-HTTP-Method-Override y verbos alternativos; (6) **CACHE-BAIT** — detección PASIVA de entradas unkeyed (X-Forwarded-Host reflejado), candidatas a cache poisoning sin envenenar nada; (7) **GraphQL** — introspección abierta (mapa completo de la API = mapa de IDORs). Toggle `STEALTH-BAIT` activado por defecto. Validado 7/7 en laboratorio.
- **v0.28.0 — ENCADENAR HALLAZGOS + AUTOCORRECCIÓN:** el valor real está en las **cadenas**, no en piezas sueltas. Nuevo nodo `chain` tras VERITAS: conecta hallazgos ya verificados y calcula el impacto combinado (XSS + CSP débil = ejecutable y sesiones robables; XSS o SQLi + panel admin mapeado = captura de sesión admin / toma de control; IDOR en varias identidades = filtración masiva; datos privados + endpoint de settings/token = camino a account takeover). Las cadenas van arriba en los informes TXT/PDF/JSON con su severidad combinada, listas para justificar la recompensa. Nuevo nodo `self_tune` + memoria persistente `tune_state.json` (no se committea): el Hunter registra qué parámetros produjeron hallazgos (por nombre y por tipo de blanco) y en la caza siguiente sube su presupuesto de sondas (x1.2 con 1 hallazgo, x1.5 con 2+), sin bajar el de los nuevos. La caza N aprende de la N-1, 100% determinista.
- **v0.27.0 — CEREBRO (inteligencia determinista):** nueva capa de análisis previo al gasto de sondas. **Fingerprint del blanco:** detecta WordPress (+ plugins y theme vía `wp-content`), frameworks (Angular, React, Next.js, Vue, Laravel, jQuery) y servidor por headers; si identifica un plugin de vendor con historial de CVEs (VillaTheme, WPSwings, YITH, Elementor...), lo marca como pista de vendor-farming. **Priorización de la caza:** puntúa cada objetivo (endpoint + parámetro) por palabras clave de valor (`admin-ajax`, `upload`, `user_id`, `settings`...) contra un diccionario de pesos, descarta la basura de tracking (`utm_*`, `fbclid`, assets) y ordena la cola de caza por valor. Cada objetivo recibe un **presupuesto de sondas proporcional** a su puntaje (SQLI-BAIT ya lo respeta). 100% determinista: mismo blanco, mismas decisiones; costo cero y sin dependencias.
- **v0.26.0 — SQLI-BAIT (inyección SQL avanzada):** nueva batería con 4 tiers de detección sobre los parámetros mapeados y cabeceras clásicas (`X-Forwarded-For`, `User-Agent`, `Referer`): **error-based** (rompe la sintaxis y captura el error del motor en la respuesta, con fingerprint de MySQL/MariaDB, PostgreSQL, MSSQL, SQLite y Oracle), **boolean-based** (diferencial clásico `AND 1=1` / `AND 1=2` contra el baseline con medición de similitud), **time-based blind** (`SLEEP(4)` / `pg_sleep(4)` / `WAITFOR DELAY`, confirmación repetida 2 veces para descartar jitter de red) y **stacked queries**. Controles anti-falso-positivo: el error debe ser nuevo respecto al baseline y el control parametrizado no dispara. Presupuesto de sondas por parámetro para no martillar el blanco. Solo para blancos autorizados.
- **v0.25.2 — CAZA EN LOTE + reportes exportables:** `/api/hunt_batch` recibe una cola de blancos y los caza en serie con la misma configuración: un blanco que falla no tumba el lote, progreso en vivo por blanco (`/api/batch/<id>`) y resumen agregado al final. Cada informe se descarga en TXT (informe plano con filtraciones arriba), JSON (dump completo con leaks separados) y PDF estilizado: documento profesional impreso con el navegador real en headless (tarjetas de resumen, sección roja de filtraciones primero, hallazgos técnicos por severidad con sellos de verificado/falso positivo). Sin navegador, fallback a fpdf2 (`pip install fpdf2`, python puro, funciona en Termux).
- **v0.25.1 — Robustez por aislamiento:** cada batería corre encapsulada: si un módulo explota en plena caza, el nodo se marca en error, el fallo se reporta en el log vivo con su causa y el pipeline CONTINUA con las demás baterías. Probado con fallo inyectado a propósito: caza terminada en finished con hallazgos y VERITAS activo. VERITAS además ahora detecta el navegador en cualquier plataforma: Linux (Chrome/Chromium), Windows (chrome.exe/msedge.exe, incluidas rutas de Program Files y LOCALAPPDATA) y macOS (Google Chrome.app, Chromium.app, Edge.app). Sin navegador, la caza sigue y los hallazgos quedan como reflexiones sin verificar.
- **v0.25.0 — VERITAS:** verificación de XSS con navegador real (Chrome headless): canario inerte document.title, veredicto por ejecución, falsos positivos descartados automáticamente, blindaje para hallazgos sin datos de caracteres crudos (nunca descarta a ciegas).
- **v0.24.0 — GHOST-SHIELD:** evasión WAF con memoria: jitter por sonda, detección de bloqueo (firmas de challenge y rate-limit), cooldown exponencial por origen persistido en disco, origen quemado tras 4 bloqueos (sondas saltadas al instante, purga de 1h) y rehabilitación automática si el origen vuelve a responder sano. Toggle en la UI; el carril async comparte la misma memoria.
- **v0.23.0 — SLIPSTREAM:** carril async para la batería GET (I/O asíncrono, hasta 64 sondas en vuelo por event loop, sesión heredada intacta). Benchmark: 219 sondas/s en el lab, 35x frente al secuencial, mismos hallazgos. Fallback automático a hilos si falta httpx.
- **v0.22.0 — OVERDRIVE + PIPE-HUNT:** sondas en paralelo (hasta 8 workers) en las baterías GET/forms y en los módulos de sonda de XSS-PRO (dangling, base tag, redirect); 5.4x más rápido con 8 workers. Modo tubería `hunt_pipe.py`: URLs desde stdin (`waybackurls sitio | python3 hunt_pipe.py --xsspro --workers 8`), vigilancia de jobs y resumen final.
- **v0.21.1 — parche de estabilidad:** índice de jobs con lock y poda, watchdog para cuelgues, recuperación de jobs al reiniciar (estado "interrupted"), sesión heredada por origen, errorhandler global JSON, `auto_update.sh` con verificación de salud.
- **v0.21.0 — XSS-PRO 2:** arsenal completo de 20 vectores XSS: DOM clobbering, prototype pollution, iframe srcdoc, base tag injection, open redirect y `javascript:` en Location, path reflection, fingerprint de sanitizadores, self-XSS escalable, sink de document.cookie.
- **v0.20.0 — XSS-PRO + GHOSTHOOK:** seis vectores avanzados (postMessage, carga dinámica de script, mXSS, dangling markup, stored, CSP bypass) y colector propio de blind XSS en Cloudflare Workers (KV, panel privado, beacon a prueba de CSP).
- **v0.19.0 — escalada de chunks:** descarga recursiva de chunks lazy de Angular para extraer la API real del sitio (`apiUrl`), IDOR con soporte POST, batería BLIND opt-in, listeners de postMessage, evaluación de CSP.

- **Estabilidad:** el índice de jobs está protegido con lock (dos cazas simultáneas nunca pisan el estado de la otra), con tope de 40 jobs en memoria y log vivo limitado. Un job que supera 45 minutos es marcado como colgado por el watchdog (la UI nunca queda en "running" eterno). Al reiniciar el servidor, los jobs se recuperan del disco y una caza interrumpida aparece como "interrupted" con su explicación. La sesión heredada se guarda por origen: cazas contra sitios distintos nunca se cruzan credenciales. Cualquier error no manejado responde JSON sin tumbar el proceso, y `auto_update.sh` verifica `/health` tras cada reinicio y resucita al servidor si cayó.
- **Diagnóstico:** cada respuesta incluye `connection` y `diagnostics` (backend respondió, objetivo alcanzable, sesión verificada, usuario detectado).

## v0.51.0 — RETRO-HUNT + ABILITY-SCAN (2026-10-02)
- **RETRO-HUNT (core/retro_hunt.py)**: caza PRE-COOLDOWN. Cola = plugins >=5k installs cuya ultima actualizacion es anterior al gate de revision IA de WP.org (jun 2026); ese codigo distribuido nunca paso el escaneo automatico. Auditoria FULL-CODE (todo el plugin, no solo diff), orden: pagables por monto -> installs. Incremental crash-safe (hechos/retro_done.txt + retro_results.json.jsonl).
- **ABILITY-SCAN** integrado en GATES-AUDIT: detecta wp_register_ability() (Abilities API, WP 6.9+); permission_callback __return_true o ausente = ABILITY-ABIERTA. Superficie 2026 sin escanear.
- Fix: import de la cadena de evidencia en retro_hunt (gates_audit -> audit), los veredictos FISCAL/DEFENSA/JUEZ ahora anotan.
- Fix: filtro _fp en retro_hunt para que "vivo" = realmente vivo.

## v0.52.0 — UNIVERSAL-ENGINE (2026-10-02)
- **UNIVERSAL-ENGINE (core/universal_engine.py)**: orquestador. Descubre que es el blanco (fingerprint fuente o URL viva), modela superficie, elige analizadores segun perfil (no corre 500 pruebas siempre) y ejecuta kernel: TAINT-TRACE + CVE-MATCH + GATES-AUDIT + ABILITY-SCAN + FP-AUTO-CLOSE + EVIDENCE-CHAIN como componentes.
- **Ledger de cobertura** (clase Ledger): todo item de superficie con estado ANALIZADO / DESCUBIERTO / NO ACCESIBLE / VERIFICADO. Nada se reporta sin estado; los estados solo escalan hacia evidencia mas fuerte.
- **UNIVERSAL-RECON**: perfil de fuente (PHP/JS/Python/Java/Go/Ruby, WP plugin/tema, Laravel, Django, Flask, Express, React, Android) y de URL viva (framework, Cloudflare, rutas tipicas).
- **WP-LAB**: laboratorio WordPress local (PHP 8.2 + SQLite, sin MySQL) para AUTH-DIFF dinamico en sitio propio. Declarado como fase en el ledger; ejecucion a pedido (costo alto).
- BROWSER-INTEL / UNIVERSAL-API / STATE-MACHINE / POLYGLOT-TRACE(js,python): fases declaradas en el perfil; el kernel las activa por tipo de blanco.

## v0.53.0 — UI-RENAISSANCE (2026-10-02)
- **Dashboard renovado con la identidad del logo**: paleta verde oliva militar extraida del banner (verde #9fce54 / logo puro #71983f / paneles #0d140a), marca "CodexRC" en el header (codex en verde, RC en blanco) con el banner como logo. Hunter con la misma identidad.
- **Responsive real iOS/Android/PC**: sidebar deslizable en movil (menu hamburguesa), touch targets de 44px, font-size 16px en inputs (evita el zoom de iOS), safe-area insets para notch, meta theme-color + apple-mobile-web-app.
- **Nuevo panel MOTOR DE CAZA en el dashboard**: progreso vivo de WIDE-HUNT y RETRO-HUNT (barras + ultimas lineas, refresco cada 30s) y runner de UNIVERSAL-ENGINE (input path o URL, muestra perfil, analizadores elegidos, ledger de cobertura ANALIZADO/DESCUBIERTO/NO ACCESIBLE/VERIFICADO y hallazgos con veredicto).
- **Backend**: GET /api/hunt_status (progreso de cazas desde hechos/) y POST /api/universal (corre el motor sobre path o URL). VERSION 0.53.0.

## v0.53.1 — fix UI movil real (2026-10-02)
- **Logo roto (404)**: `/assets/banner.jpg` no cargaba porque Flask solo servia estaticos desde `frontend/`, no desde la raiz del repo donde vive `assets/`. Nueva ruta `GET /assets/<path>` en el backend sirve el logo correctamente (verificado con Chrome headless + emulacion movil: `naturalWidth` paso de 0 a 1280).
- **Hamburguesa "se enzima" con el pipeline**: el boton de menu usaba `position:fixed` (flotaba libre sobre TODO el documento, sin relacion con el header). Paso a `position:absolute` anclado DENTRO del header (que ahora es `position:sticky`), asi nunca puede superponerse con el contenido de abajo.
- **"El menu desplegable se queda abajo"**: el nav (escaner/hunter) se envolvia a una segunda linea dentro del header angosto. Se movio al drawer lateral (sidebar-nav, visible solo en movil, arriba del formulario de escaneo) y se oculta del header en pantallas chicas: ya no hay wrap raro, el header queda fijo en una sola fila.
- Logo + marca CodexRC agregados tambien a hunter.html (identidad consistente en ambas paginas), con header sticky en movil.
- Limpieza de CSS muerta (`.prompt` ya no existia tras el rebrand, quedaban reglas huerfanas).
- Validado con Chrome headless real (CDP, emulacion de dispositivo 390px y 1366px) en las 4 combinaciones pagina x ancho: logo carga, hamburguesa solo aparece en movil, nav sin overlap, pipeline nunca se tapa.

## v0.53.2 — fix overflow real del panel motor de caza (2026-10-02)
- Bug confirmado con datos reales (reportado por el usuario con captura: linea de log "[1578/1615] gelato-integration-for-woocommerce" cortada en el borde de pantalla): `.hunt-card` no tenia `min-width:0` ni `overflow:hidden`, asi que el texto `white-space:nowrap` de `.hunt-log` (lineas de progreso WIDE-HUNT/RETRO-HUNT) forzaba a la tarjeta a estirarse mas alla del viewport (clasico "minimo automatico" de CSS Grid con contenido nowrap). Medido con Chrome headless: antes del fix la tarjeta llegaba a 476px en una pantalla de 390px (86px afuera); despues del fix, 366px (adentro, 0 elementos desbordados).

## v0.53.3 — fix denominador RETRO-HUNT (2026-10-02)
- Usuario pregunto si "2087 y 1010" eran reales (captura con RETRO-HUNT mostrando "1010/1007 auditados", matematicamente imposible). Verificado contra disco: ambos contadores SON reales (hechos/hunt_wide_done.txt = 2087 lineas, hechos/retro_done.txt = 1010 lineas unicas sin duplicados, timestamps y logs coinciden con corridas reales en tmux). El bug era el DENOMINADOR: "total_cola" de retro estaba hardcodeado en 1007 (una foto del tamano de la cola al momento de lanzar un run), mientras "hechos" es un contador acumulado de TODAS las corridas de retro a lo largo del tiempo. Fix: `total_cola` ahora se calcula en vivo desde `wide_corpus.json` filtrando por el mismo criterio de cooldown (`last_updated < 2026-06-01`) que usa `core/retro_hunt.py` para armar su cola real. Resultado tras el fix: 1010/1010 (RETRO-HUNT efectivamente completo al 100% del universo pre-cooldown real).

## v0.62.3 — drawer móvil navegable (RC-000146/147)

Presentacion unicamente; sin cambios en el motor de caza.

- RC-000146 (BUG REAL, reproducido con headless): al tocar
  "hunter"/"arsenal" en el menu movil NO navegaba y el menu se
  cerraba solo. Causa: el backdrop (body::before, z-index 30 en el
  contexto RAIZ) tapaba el drawer entero, porque <main> crea su
  propio contexto de apilamiento (position:relative + z-index:2):
  el z-index:40 del .sidebar solo compite DENTRO de <main>; desde
  afuera todo <main> vale "2". 30 > 2 -> backdrop sobre el drawer:
  el tap caia en el backdrop y solo cerraba el menu. Fix: el
  pseudo-elemento pasa a main::before (mismo contexto que el
  drawer) + body.nav-open main { z-index: 50 } para que el drawer
  tambien quede sobre el header sticky (z-index 5), que tapaba los
  primeros ~56px del menu. Al abrir: drawer 40 > backdrop 30 >
  header 5. Al cerrar: todo vuelve a su lugar. Cerrar = tocar la
  zona oscura (comportamiento estandar de drawer).
- RC-000147: el drawer (position:fixed) conservaba su scroll
  interno entre aperturas; si el usuario habia bajado hasta
  Autenticacion, al reabrir aparecia YA scrolleado con la nav fuera
  de pantalla ("tenia que empujar un chiquito hacia arriba"). Al
  abrir siempre arranca desde arriba.
- Header: fuera el "codexRC" de texto duplicado en las 3 paginas
  (quedaba logo + texto = 2 CodexRC visibles). Ahora solo logo,
  "// HUNTER"/"// ARSENAL" y la version.
- Escáner: fuera la card "Vulnerabilidades" (lista de CVEs
  conocidos por tecnologia, sin relación con hallazgos; eso vive
  en Hunter). Card + renderCve + integración eliminados.
- VERSION del backend actualizada a 0.62.3 (quedaba clavada en
  0.57.4, el header mostraba version vieja).

Validado en vivo con Chromium headless viewport 390x844:
navegacion real a hunter/arsenal OK, backdrop cierra, scrollTop
0 al reabrir, 0 spans duplicados, card CVE ausente, esquinas base
identicas rgb(29,42,34) en escáner y hunter.

## v0.62.4 — REVERSE-WEB: ingeniería inversa desde la web

Presentacion unicamente; los modulos RE no cambian.

- Los 3 modulos de ingenieria inversa (BIN-AUDIT, RE-ENGINE,
  DECOMPILE) existian solo por CLI/API: la web no tenia forma de
  subir un APK. Ahora el escáner tiene una seccion "Ingeniería
  inversa" en el menu lateral: elegir archivo (input file del
  navegador) o escribir la ruta del telefono, checkboxes por
  modulo (bin/re/decompile + modo --all para apps ofuscadas),
  y una card de resultados a lo ancho: FILTRACIONES arriba en
  rojo (sev critica/alta de cualquier modulo), luego las filas
  de cada modulo y el pseudocodigo de DECOMPILE en bloques.
- Backend: POST /api/reverse_run (corre los modulos pedidos
  sobre un path, aislamiento de fallos por modulo, normaliza
  hallazgos a lineas legibles) y POST /api/reverse_upload
  (recibe el archivo del navegador, sanea el nombre, guarda
  en /tmp/codexrc_reverse y devuelve el path).
- UX: al analizar, el drawer se cierra para que la card de
  resultados quede a la vista; en PC el sidebar siempre visible.

Validado en vivo con Chromium headless (390x844 y 1400x900):
subida de zip con secret AKIA + endpoint staging -> detectado,
seccion FILTRACIONES renderizada, /bin/sh real -> 3 hallazgos
con imports ELF, drawer cierra tras analizar, seccion visible
en PC sin abrir menu.

## v0.62.5 — MULTI-IA: estado individual por operador + shard de cola

Una sola cosa cambio de lugar: el ESTADO. El repo guarda codigo y
datos publicos (corpus, vdp_mapa); cada IA u operador guarda sus
hechos en su propio workspace. Sin tocar el motor ni la arquitectura.

- Nuevo core/state.py: home() = $CODEXRC_HOME si esta exportado, si
  no el repo mismo (compatibilidad total: sin la variable todo
  funciona exactamente como siempre). hechos() resuelve el
  hunt_wide_done.txt y los resultados al workspace propio.
- hunt_wide.py y plugin_batch.py escriben su avance/resultados via
  core/state (hechos/hunt_wide_done.txt, wide_hunt_results.json).
- Nuevo --shard N/M en hunt_wide y plugin_batch: reparto
  determinista del corpus por hash de slug (sha256 % M == N). Dos o
  mas IAs se reparten TODO el corpus sin coordinarse ni duplicar un
  solo blanco. Formato: --shard 0/2 y --shard 1/2.
- Estado 0 vivo del backlog y caza de 291 pagables corriendo sin
  cambios de comportamiento (sin CODEXRC_HOME = historico).

Validado en vivo: IA nueva con CODEXRC_HOME propio arranca con cola
llena (2120) sin heredar nuestro avance; shard 0/2 + 1/2 = 1071 +
1049 = 2120 exactos sin solaparse; sin variable, cola 0 como siempre.

## v0.62.6 — VDP-FRESH WATCHER: caza automática cada 6 horas

- Nuevo core/vdp_watcher.py: detecta pagables (710 con bounty) que
  sacaron version nueva desde la ultima auditoria y los manda SOLO a
  DIFF-HUNT. Determinista, Python puro, sin LLM: lo despierta un
  workflow del agente cada 6 horas y el agente solo triaga al final.
  Flags: --check (listar sin cazar), --limit N (prueba rapida),
  --sleep (pausa vs la API de wp.org).
- La memoria de "version auditada" (_auditadas) lee TODOS los
  resultados historicos del workspace de estado (wide_hunt_results*
  y watcher_diff*), respetando CODEXRC_HOME (multi-IA).
- La caza manual de los 8 pagables parcheados de hoy queda
  registrada como hechos/watcher_diff_20261003_manual.json para que
  el watcher no los repita.
- El parche fresco = mejor ventana para cazar parches incompletos:
  con esto dejamos de depender de acordarse de mirar.

Validado: --limit 12 sobre pagables reales (0 movidos, esquema de
salida correcto); JSON de diff_hunt compatible con la memoria de
versiones.

## v0.62.7 — REVIVE-SOLO: Termux:Boot

boot_install.sh: instala ~/.termux/boot/00-codexrc.sh para que cada
reinicio de Android levante el server solo (wake-lock + auto_update).
Requiere la app Termux:Boot de F-Droid, abrirla una vez, y luego
bash boot_install.sh. Android puede matar Termux cuando quiera: con
esto, cada arranque del telefono lo revive automaticamente.
