# Línea de tiempo de versiones — CodexRC

Condensado automático del CHANGELOG.md completo (2222 líneas) para referencia rápida.

### v0.40.0 — VERIFICACIÓN DEL SISTEMA
El sistema verifica los hallazgos automáticamente (contraste anónimo A→B, doble

### v0.41.0 — VENDOR-FARM
Descubrimiento de familias de vendors WordPress con instalaciones en rango pagable

### v0.42.0 — PLUGIN-BATCH (modo agente)
Un solo comando caza plugins WordPress por slugs: descarga la última versión estable,

### v0.43.0 — GATES-AUDIT — GATES-AUDIT
Nuevo modulo `core/gates_audit.py`: dictamina automaticamente si los handlers de un

### v0.44.0 — FP-AUTO-CLOSE
Nuevo modulo `core/fp_autoclose.py`: segunda capa de verificacion tras GATES-AUDIT.

### v0.45.0 — DIFF-HUNT
Pivote de estrategia: en vez de auditar plugins enteros (los top estan blindados),

### v0.45.1 — DIFF-HUNT paralelo (2026-10-02)
- core/diff_hunt.py: ThreadPoolExecutor (--workers, default 4); cada slug se diffea y

### v0.46.0 — VDP-1300: directorio completo de Patchstack (2026-10-02)
- Extracción del directorio publico de VDP activos de patchstack.com/database/vdp

### v0.47.0 — EVIDENCE-CHAIN + ABOGADOS: razonamiento de evidencia (2026-10-02)
Cambio de filosofía inspirado en RacerD/Infer/Pysa: no preguntar "¿podría ser vulnerable?" sino "¿qué evidencia tengo para afirmar que lo es?". Nuevo `core/evidence.py`:

### v0.48.0 — WIDE-HUNT: el corpus se multiplica (2026-10-02)
Con los abogados cerrando los falsos positivos solos (v0.47.0), limitar la caza a los VDP de Patchstack dejó de tener sentido técnico: el VDP no decide a quien cazamos, solo a quien reportamos.

### v0.49.1 — EVIDENCE-CHAIN hardening: bug de resolucion de rutas (2026-10-02)
El usuario compartio una especificacion tecnica de Evidence Chain (principios de evidencia, veredictos no monotonicos, reachability honesta). Al contrastarla contra la implementacion v0.47.0, surgio un bug real durante la revision manual de un hallazgo del dia (link-whisper).

### v0.50.0 — CODEX-OBSERVE + CODEX-REGRESS, alcance reducido (2026-10-02)
El usuario comparti una segunda especificacion tecnica: CODEX-OBSERVE (observabilidad)

### v0.51.0 — RETRO-HUNT + ABILITY-SCAN (2026-10-02)
- **RETRO-HUNT (core/retro_hunt.py)**: caza PRE-COOLDOWN. Cola = plugins >=5k installs cuya ultima actualizacion es anterior al gate de revision IA de WP.org (jun 2026); ese codigo distribuido nunca paso el escaneo automatico. Auditoria FULL-CODE (todo el plugin, no solo diff), orden: pagables por monto -> installs. Incremental crash-safe (hechos/retro_done.txt + retro_results.json.jsonl).

### v0.52.0 — UNIVERSAL-ENGINE (2026-10-02)
- **UNIVERSAL-ENGINE (core/universal_engine.py)**: orquestador. Descubre que es el blanco (fingerprint fuente o URL viva), modela superficie, elige analizadores segun perfil (no corre 500 pruebas siempre) y ejecuta kernel: TAINT-TRACE + CVE-MATCH + GATES-AUDIT + ABILITY-SCAN + FP-AUTO-CLOSE + EVIDENCE-CHAIN como componentes.

### v0.53.0 — UI-RENAISSANCE (2026-10-02)
- **Dashboard renovado con la identidad del logo**: paleta verde oliva militar extraida del banner (verde #9fce54 / logo puro #71983f / paneles #0d140a), marca "CodexRC" en el header (codex en verde, RC en blanco) con el banner como logo. Hunter con la misma identidad.

### v0.53.1 — fix UI movil real (2026-10-02)
- **Logo roto (404)**: `/assets/banner.jpg` no cargaba porque Flask solo servia estaticos desde `frontend/`, no desde la raiz del repo donde vive `assets/`. Nueva ruta `GET /assets/<path>` en el backend sirve el logo correctamente (verificado con Chrome headless + emulacion movil: `naturalWidth` paso de 0 a 1280).

### v0.53.2 — fix overflow real del panel motor de caza (2026-10-02)
- Bug confirmado con datos reales (reportado por el usuario con captura: linea de log "[1578/1615] gelato-integration-for-woocommerce" cortada en el borde de pantalla): `.hunt-card` no tenia `min-width:0` ni `overflow:hidden`, asi que el texto `white-space:nowrap` de `.hunt-log` (lineas de progreso WIDE-HUNT/RETRO-HUNT) forzaba a la tarjeta a estirarse mas alla del viewport (clasico "minimo automatico" de CSS Grid con contenido nowrap). Medido con Chrome headless: antes del fix la tarjeta llegaba a 476px en una pantalla de 390px (86px afuera); despues del fix, 366px (adentro, 0 elementos desbordados).

### v0.53.3 — fix denominador RETRO-HUNT (2026-10-02)
- Usuario pregunto si "2087 y 1010" eran reales (captura con RETRO-HUNT mostrando "1010/1007 auditados", matematicamente imposible). Verificado contra disco: ambos contadores SON reales (hechos/hunt_wide_done.txt = 2087 lineas, hechos/retro_done.txt = 1010 lineas unicas sin duplicados, timestamps y logs coinciden con corridas reales en tmux). El bug era el DENOMINADOR: "total_cola" de retro estaba hardcodeado en 1007 (una foto del tamano de la cola al momento de lanzar un run), mientras "hechos" es un contador acumulado de TODAS las corridas de retro a lo largo del tiempo. Fix: `total_cola` ahora se calcula en vivo desde `wide_corpus.json` filtrando por el mismo criterio de cooldown (`last_updated < 2026-06-01`) que usa `core/retro_hunt.py` para armar su cola real. Resultado tras el fix: 1010/1010 (RETRO-HUNT efectivamente completo al 100% del universo pre-cooldown real).

### v0.57.3 — HIGIENE DE DEPENDENCIAS (Termux-first)
- requirements.txt reescrito: 100% instalable en Termux armv7l. Fuera `rich`

### v0.57.4 — AUDITORIA DE SEGURIDAD DEL PROPIO PROYECTO
AUDITADO (sin cambios necesarios):

### v0.57.5 — TRIAJE SQLI N1: 11/11 FALSOS POSITIVOS, 3 CLASES DE FP ELIMINADAS
TRIAJE MANUAL (backlog wide, SQLi en plugins con VDP pagable):

### v0.57.6 — TRIAJE BAC N1: pods y ad-inserter, ambos MUERTOS
TRIAJE MANUAL (protocolo BAC: handler -> gate -> impacto):

### v0.57.7 — PATRON BAC MIRA EL CUERPO DEL HANDLER (RC-000131/133)
- finalize() postergado: los hallazgos bac-ajax-nopriv esperan a tener el

### v0.57.8 — TRIAJE de los 2 sobrevivientes no-loose-cmp: ambos MUERTOS
- simple-floating-menu (BAC 1177/1214): MUERTO. Cero hooks nopriv/REST

### v0.57.9 — RC-000135: loose-cmp exige contexto de AUTORIZACION
- El patron loose-auth-cmp ya no dispara con cualquier == sobre input:

### v0.57.10 — RC-000136: gate adyacente mata el loose-cmp
- _GATE_ADJ generalizado (sin hardcodear funciones de plugin):

### v0.58.0 — SEMANTIC CORE (nivel 0): identidad canonica + integridad
Inicio del Semantic Core (recomendacion experta: el motor pasa de

### v0.58.1 — SEMANTIC CORE Fase 1: CFG + dominancia en produccion
- core/cfg.py (Python puro, ~650 lineas): tokenizer PHP-lite

### v0.58.2 — SEMANTIC CORE: RC-000132 resuelto en el patron BAC
- cfg.py: all_protected(gate_rx, sens_rx) — True/False/None: ¿todos

### v0.58.3 — Triage de los 29 cerrado: 0 candidatos, 2 clases semanticas nuevas
- RC-000139 (cmp_router): comparacion dominada POR un gate = corre

### v0.59.0 — Fase 1.5: SSA-lite en TAINT-TRACE
- core/ssa.py: grafo de versiones def-use intra-funcion. Cada

### v0.60.0 — SSA consume la evidencia: FISCAL exige prueba def-use
- ssa.py: def_use_proof() — prueba estructurada {proof, value,

### v0.61.0 — Corpus fresco: VDP-FRESH + prioridad mid-band
PALANCA 1 (corpus fresco automatico):

### v0.62.0 — DIFF-HUNT v2: la fuente cambio, el motor se adapta
- wp.org sello el historial de plugins (oct 2026): la API ya no

### v0.62.1 — HUNTER anonimo con potencia completa
- MODO SIN SESION: nueva bateria _descubrir_acceso_anon. Sin

### v0.62.2 — capa UI/UX del pipeline y la navegacion
Presentacion unicamente; sin cambios en UNIVERSAL-ENGINE,

### v0.62.3 — drawer móvil navegable (RC-000146/147)
Presentacion unicamente; sin cambios en el motor de caza.

### v0.62.4 — REVERSE-WEB: ingeniería inversa desde la web
Presentacion unicamente; los modulos RE no cambian.

### v0.62.5 — MULTI-IA: estado individual por operador + shard de cola
Una sola cosa cambio de lugar: el ESTADO. El repo guarda codigo y

### v0.62.6 — VDP-FRESH WATCHER: caza automática cada 6 horas
- Nuevo core/vdp_watcher.py: detecta pagables (710 con bounty) que

### v0.62.7 — REVIVE-SOLO: Termux:Boot
boot_install.sh: instala ~/.termux/boot/00-codexrc.sh para que cada

### v0.62.8 — FP-FILTER de reflejo en pagina de bloqueo WAF
Leccion greenlightdispensary (03/10): el Arsenal reporto 16

### v0.63.0 — AUTHZ-PROOF capa 3: resolucion de hooks dinamicos (RC-000149)
GATES-AUDIT dejaba CALLBACK-NO-RESUELTO (o directamente no veia)

### v0.64.0 — AUTHZ-PROOF capa 1: ROLE-SOLVER (RC-000150)
GATES-AUDIT trataba cualquier current_user_can como "protegido"

### v0.65.0 — AUTHZ-PROOF capa 2: OBJECT-OWNER, IDOR estatico (RC-000151)
El hueco admitido del BAC: GATES-AUDIT no miraba de QUIEN es el

### v0.66.0 — AUTHZ-PROOF capa 5: FP-MEMORIA semantica (RC-000152)
"El falso positivo se paga una sola vez, nunca mas." fp_autoclose

### v0.67.0 — AUTHZ-PROOF capa 4: BAC-PROOF dinamico (RC-000153)
La joya de la corona del BAC 2.0: validacion DINAMICA con

### v0.68.0 — REG-BOT + AB-DIFF universal: identidades no-WordPress (RC-000154)
El concepto de la capa 4 (diff de sesiones) portado a CUALQUIER

### v0.69.0 — VISION-GATE: clasificador visual de challenges (RC-000155)
Gemini como SENSOR, no como conductor. Mismas reglas del JUEZ

### v0.70.0 — RACE-TRACE: TOCTOU en estado persistente
Tecnica nueva incorporada al arsenal estatico: la clase de bug

### v0.71.0 — ARSENAL-EXPANSION: RACE-PROOF + CSPT-SCAN + SAML-DEFENSE
Tres modulos nuevos pedidos por el operador (tecnicas calientes

### v0.72.0 — EDGESYNC-HUNT: detector de desync edge->back
Primer modulo de capa transporte del engine (hasta ahora eramos

### v0.73.0 — EDGESYNC-HUNT V2: bateria de 9 framings
Una sola sonda CL+TE no basta: cada parser resuelve la

### v0.74.0 — EDGESYNC-V3: SONDA-DE-CORRELACION
Salto de arquitectura: el veredicto ya no nace de una sola

### v0.75.0 — EDGE-PROFILE: el contrato observable del edge
Primera release del roadmap v0.75-v0.80 (EDGE-DIFFERENTIAL). No

### v0.76.0 — NORMALIZATION-AUDIT: que recibe el origin
Pregunta: cuando el edge ACEPTA un framing contradictorio,

### v0.77.0 — CONNECTION-STATE AUDIT: el estado es el testigo
Pregunta: ¿deja una peticion ambigua un estado observable

### v0.78.0 — STATE-CORRELATION: un veredicto por target
No agrega payloads. Une lo que v0.75 (contrato del edge),

### v0.79.0 — CACHE-CORRELATION: el estado compartido como evidencia
Pregunta central: ¿dos representaciones que deberian ser

### v0.80.0 — SEMANTIC-CACHE: desacuerdos semanticos (fase 2 del estado compartido)
Pregunta central: dado un diferencial o una convergencia de cache,

### v0.81.0 — ADAPTIVE-HUNT: la capa epistemica
Pregunta central: no "que vulnerabilidad puedo probar" sino

### v0.81.1 — RESEARCH-MEMORY: el motor recuerda
Pregunta central: si vuelvo a un target manana, ¿empiezo de

### v0.82.0 — GRAFO DE EXPERIMENTOS: seleccion por EDV
Pregunta central: dadas las hipotesis vivas y el presupuesto,

### v0.83.0 — EXPERIMENT-GRAPH: la investigacion como grafo
Objetivo: que codexRC construya y recorra un grafo de

### v0.84.0 — CROSS-LAYER CORRELATION
Un disparo, tres capas observadas a la vez (Edge / Cache /

### v0.85.0 — PIPE-CROSS
El Hunter automatico (/api/scan) ahora invoca la auditoria

### v0.86.0 — WCD-CACHE-KEY
Web Cache Deception como familia nativa del motor, con la

### v0.87.0 — CL.0-SINGLE-TIER
Request smuggling CL.0 como etapa DESYNC DIFFERENTIAL

### v0.88.0 — H2-TRANSLATION
Parser differential h2->h1 como etapa PARSER

### v0.89.0 — MULTI-CONNECTION
Contaminacion CRUZADA entre conexiones como etapa

### v0.90.0 — CROSS-REQUEST CORRELATION
Reconstruccion de la cola del origin por CORRELACION

### v0.90.1 — VALIDACION EN VIVO (linktr.ee) + TLS
- Validacion en vivo de los 4 probes desync contra

### v0.91.0 — REPRODUCTION ENGINE (etapa 21/22)
Ultima etapa de MODULO antes de IMPACT / FP-ELIMINATION

### v0.92.0 — IMPACT CORRELATION (etapa de IMPACT)
El roadmap cierra el circulo: el desync reproducido

### v0.94.0 — FP-ELIMINATION + EVIDENCE PACKAGE (CORONA)
Las dos ultimas etapas del roadmap, de una vez: la

### v0.95.0 — INTEGRACION AL HUNTER (corona montada)
Decision del operador cumplida: con la corona en mano,

### v0.96.0 — DOSSIER Q4-2026: TRES CLASES NUEVAS (139/139 PASS)
Investigacion de calibre integrada al motor (decision del operador:

### v0.96.1 — BLINDAJE POI-REACH: DOS FP ELIMINADOS (141/141 PASS)
Causa: la primera corrida LestGo del DOSSIER-HUNT regalo un POI-REACH

