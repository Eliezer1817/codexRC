#CodexRC

![CodexRC](assets/banner.jpg)

**Automated Web Security Auditing Tool** con backend único, dashboard web local y modo HUNTER de caza activa.

> Solo usar en objetivos que tengas autorización para auditar.

> **Demo real:** mira el dashboard cazando en vivo (login, sondas y hallazgo
> verificado) en [docs/demo_caza_dashboard.mp4](docs/demo_caza_dashboard.mp4).

> **¿Sos una IA (o le vas a pasar esta herramienta a una)?** Leé primero
> [AGENTS.md](AGENTS.md): manual operativo paso a paso con reglas de oro,
> comandos y cómo interpretar cada veredicto.

> ⚠️ **Proyecto en desarrollo activo:** se actualiza con mucha frecuencia (a veces varias versiones por día) y la interfaz y las baterías cambian sin aviso. **No recomendado todavía para uso en producción**: tomalo como una herramienta en construcción. Si igual lo probás, revisá siempre esta sección de novedades antes de correr la última versión. Las sondas son de lectura A→B: contrastan el acceso con y sin sesión, sin alterar datos del objetivo.

## Arquitectura

- **Backend:** `backend/app.py` es la única implementación del servidor Flask (versión actual: **v0.55.0**).
- **Core:** autenticación, reconocimiento, detección tecnológica, CVE matcher, GHOSTGATE, pipeline y el HUNTER se ejecutan dentro del backend.
  - `core/hunter.py` — spider, corpus XSS, DeepHunter (BAC/IDOR/CSP/superficie) y batería XSS-PRO.
  - `core/ghostgate.py` — evasión de Cloudflare delegando a navegador real cuando la IP está quemada.
  - `core/auth.py` — login automático por formulario HTML o API JSON (SPAs Angular/React), autodetección de endpoint de autenticación, CSRF y cabeceras Origin/Referer.
  - `core/brain.py` — CEREBRO: fingerprint del blanco (WordPress/plugins/frameworks, alerta vendor-farming) y priorización de la cola de caza por puntaje con presupuesto dinámico de sondas.
  - `core/sqli_bait.py` — SQLI-BAIT: SQLi en 4 niveles (error-based con fingerprint del motor, boolean por diferencial, time-based con confirmación anti-jitter, stacked).
  - `core/chain.py` y `core/self_tune.py` — encadenamiento determinista de hallazgos (XSS+CSP débil, SQLi+panel admin, IDOR masivo) y autoajuste persistente del presupuesto de sondas según el historial de params (`tune_state.json`, gitignored).
  - `core/cov_bait.py` — COV-BAIT (etapas 1 y 2): caza guiada por cobertura de código vía CDP (cliente websocket propio) con motor de mutación con feedback; lee las pistas de los scripts de la app.
  - `core/taint_trace.py` — TAINT-TRACE: análisis de flujo de datos fuente→sink sobre PHP (encuentra vulnerabilidades ciegas que no se ven en la respuesta).
  - `core/pattern_match.py` — CVE-MATCH: aprendizaje de patrones globales; detecta familias de fallos históricos (BAC ajax, type juggling, IPN downgrade, SSRF, upload, PrivEsc) sin firmas fijas y anota outliers contra la línea base del corpus (`pattern_baseline.json`).
  - `core/bin_audit.py` — BIN-AUDIT: análisis binario/nativo (secrets hardcodeados, endpoints internos, imports peligrosos del .dynsym, fingerprint; contenedores zip/apk/jar recursivos).
  - `core/re_engine.py` — REVERSE: ingeniería inversa nivel 2 (parse de DEX/class/ELF: clases y métodos de APKs, constant pool de JARs, .symtab interna, stripped, ofuscación ProGuard, entropía empaquetada).
  - `core/decompile.py` — DECOMPILE: descompilación parcial nivel 3 (bytecode DEX → pseudocódigo legible de los métodos sensibles, con detección de secrets en el flujo de ejecución).
  - `core/escalada.py` — ESCALADA: continúa solo tras el aviso crítico (VERITAS dirigido sobre las piezas de la cadena, techo de impacto por flags de cookies, kit PoC local con canarios inertes, playbook de próximos pasos).
  - `core/path_bait.py`, `core/ssti_bait.py`, `core/cache_bait.py`, `core/graphql_bait.py` — baterías de caza profunda: LFI con wrappers, SSTI, Web Cache Deception e introspección/batching de GraphQL.
  - `core/stealth_bait.py` — sondas de evasión y postMessage/CSP pasivas.
  - `core/veritas.py` — verificación con navegador real de cada candidato (canario inerte, solo lectura).
  - `core/waf_guard.py` — GHOST-SHIELD: jitter, clasificador de bloqueo y cooldown exponencial persistente.
  - `core/async_lane.py` — SLIPSTREAM: carril asíncrono (httpx, hasta 64 sondas en vuelo) con fallback a hilos.
  - `core/universal_engine.py` — UNIVERSAL-ENGINE: orquestador. Fingerprint del blanco (fuente o URL viva), elige analizadores según perfil, ejecuta los componentes existentes como un solo motor y mantiene el Ledger de Cobertura (ANALIZADO / DESCUBIERTO / NO ACCESIBLE / VERIFICADO).
  - `core/retro_hunt.py` — RETRO-HUNT: caza del código PRE-COOLDOWN (plugins ≥5k installs cuya última actualización es anterior al gate de IA de WP.org, junio 2026). Auditoría full-code, cola por bounty, incremental y crash-safe.
  - `core/wplab*.py` / WP-LAB — laboratorio WordPress local (PHP 8.2 + SQLite) para verificación dinámica AUTH-DIFF en sitio propio.
  - `core/report_export.py` — exportación de informes TXT/JSON/PDF (filtraciones arriba, hallazgos por severidad).
- **Frontend:** `frontend/index.html` (dashboard de escaneo) y `frontend/hunter.html` (terminal de caza). Solo presentan la interfaz y llaman a la API `/api/*`. `frontend/arsenal.html` es una **sección interna del operador** con acceso restringido: exige contraseña, registra cada intento de entrada en el log y su contenido **no se publica**; está pensada solo para el laboratorio propio o blancos con autorización explícita. No forma parte del pipeline de caza (el Hunter sigue operando con sondas de lectura A→B, canarios inertes).
- **Termux:** únicamente inicia el backend y mantiene disponible `localhost`; no contiene lógica de auditoría. Compatible con `armv7l` (32 bits): el bypass de Cloudflare usa `cloudscraper`, sin binarios precompilados.
- **GHOSTHOOK:** `ghosthook/worker.js` — colector de blind XSS gratuito para Cloudflare Workers + KV (ver más abajo).
- **Logs:** cada escaneo se guarda en `reports/codexrc_<id>.json` descargable desde el dashboard; los eventos generales quedan en `reports/backend.log` en JSONL con rotación automática y `request_id`.
- **VERITAS (precisión anti-falsos-positivos):** una reflexión puede mentir: el servidor devuelve el marcador pero el navegador real lo sanea, lo escapa o el CSP lo mata. VERITAS re-lanza cada candidato en Chrome headless con un canario inerte (solo cambia `document.title`, nada visible, no exfiltra, no escribe nada) y comprueba si EJECUTÓ de verdad mirando el DOM final. Confirmado → queda como alta con sello "verificado en navegador". No ejecuta → baja a descartado como falso positivo. El arma de precisión: mejor 4 hallazgos que ejecutan de verdad que 20 que solo se reflejan.
- **GHOST-SHIELD (evasión WAF con memoria):** la evasión no va en el payload sino en el comportamiento: jitter aleatorio en cada sonda (nunca intervalo fijo de bot), clasificador de bloqueo (403/429/503 + firmas de WAF y páginas de challenge) y cooldown exponencial por origen. La memoria de quién nos bloqueó persiste en disco (`waf_state.json`, fuera del repo): sobrevive jobs, reinicios y días. Tras 4 bloqueos duros el origen se marca quemado y todas sus sondas se saltan al instante; tras 1 hora de purga vuelve a tener chances, y una respuesta sana lo rehabilita. Ante bloqueo sugiere GHOSTGATE (navegador real, IP limpia). La capa vive dentro de la sesión HTTP, así que cubre araña y todas las baterías sin excepción.
- **SLIPSTREAM (carril async):** la batería GET ahora vuela con I/O asíncrono: un solo hilo mantiene hasta 64 sondas en vuelo vía event loop (httpx), heredando la sesión autenticada. Benchmark contra el lab a 60 objetivos: 219 sondas/s (35x más rápido que el modo secuencial, con los mismos hallazgos). Si httpx no está disponible, cae automáticamente al camino de hilos anterior.
- **PIPE-HUNT (modo tubería):** `waybackurls sitio.com | python3 hunt_pipe.py --xsspro --workers 8` — recibe URLs desde cualquier herramienta por stdin, las caza con el Hunter del backend local y resume los hallazgos. Con `--no-wait` solo encola y sigue.
- **OVERDRIVE (velocidad):** las baterías del corpus (GET y formularios) y los módulos de sonda de XSS-PRO (dangling, base tag, redirect) ejecutan sus sondas en paralelo con hasta 8 workers (por defecto 4). En benchmark contra el lab: 5.4x más rápido con 8 workers, con exactamente los mismos hallazgos. El parámetro `workers` (1-8) se controla desde la interfaz del Hunter o la API; con 1 queda el modo secuencial clásico.
## Novedades

Solo los hitos, de lo más reciente a lo más antiguo. El detalle completo de cada versión
(incluidos parches menores) está en [CHANGELOG.md](CHANGELOG.md).

- **v0.55.0 — ARSENAL:** módulo de verificación avanzada con acceso restringido. La documentación pública no describe su contenido: opera en dos niveles, y el avanzado **no se entrega desde el servidor sin autenticación previa**. El acceso requiere contraseña (configurable por el operador), **cada intento queda registrado en el log del backend** con hora y origen, y la sesión de uso expira a los 30 minutos. Condiciones de uso no negociables: laboratorio propio o blanco con autorización explícita, demostración mínima con stop al primer impacto confirmado, sin dump masivo, sin persistencia, nada destructivo. No se integra al pipeline de caza (el Hunter continúa con sondas de lectura A→B e inertes). El contenido de esta sección no se publicará por ahora.
- **v0.52.0 — UNIVERSAL-ENGINE:** el salto de arquitectura: codexRC deja de ser una colección de herramientas y pasa a ser un **motor que aprende cómo está construida una app desconocida y adapta su análisis a ella**. `core/universal_engine.py` descubre qué es el blanco (fingerprint de fuente PHP/JS/Python/Java/Go/Ruby o de URL viva: WordPress, Laravel, Django, Flask, Express, React, Android, Cloudflare), **elige qué analizadores activar según el perfil** (no corre 500 pruebas siempre, solo las que aplican) y ejecuta los módulos existentes (TAINT-TRACE, CVE-MATCH, GATES-AUDIT, ABILITY-SCAN, FP-AUTO-CLOSE, EVIDENCE-CHAIN, BIN-AUDIT, REVERSE) como **componentes de un solo motor**. Metodología OWASP: primero mapear arquitectura, después auth/authz/lógica/APIs. Incluye **Ledger de Cobertura**: cada ítem de superficie reporta su estado honesto — `ANALIZADO` (inspeccionado), `DESCUBIERTO` (identificado, no probado), `NO ACCESIBLE` (no pudo examinarse, con motivo), `VERIFICADO` (evidencia reproducible) — y los estados solo escalan hacia evidencia más fuerte. Fases BROWSER-INTEL (CDP/navegador real), UNIVERSAL-API (REST/GraphQL/WS), STATE-MACHINE (inconsistencias de estados/autorización) y POLYGLOT-TRACE quedan declaradas en el perfil y el kernel las activa por tipo de blanco. **WP-LAB**: laboratorio WordPress local (PHP 8.2 + SQLite, sin MySQL) para verificación dinámica AUTH-DIFF en sitio propio 100% legal.
- **v0.51.0 — RETRO-HUNT + ABILITY-SCAN:** los datos de blindaje dijeron que desde junio 2026 **todo release que sube a WP.org pasa por revisión IA antes de distribuirse**; por eso el código nuevo sale limpio. RETRO-HUNT invierte la caza: apunta al **código PRE-COOLDOWN** — plugins ≥5k instalaciones cuya última actualización es anterior al gate (su código distribuido nunca pasó por ese escaneo). Auditoría **FULL-CODE** (todo el plugin, no solo el diff), cola ordenada por bounty, incremental y crash-safe (`hechos/retro_done.txt`). Resultado del primer día: 60+ plugins con señal viva donde los frescos daban cero. **ABILITY-SCAN** (en GATES-AUDIT): detección de la nueva **Abilities API** (WP 6.9+) — cada `wp_register_ability()` sin `permission_callback` efectivo se marca `ABILITY-ABIERTA`; superficie 2026 que casi nadie escanea. Fixes: veredictos de la cadena de evidencia ahora anotan en RETRO-HUNT (import roto) y "vivo" significa realmente vivo (filtro de FP anotados).
- **v0.42.0 — PLUGIN-BATCH:** caza estática de plugins WordPress por slugs con un comando (descarga + TAINT-TRACE + CVE-MATCH, filtro de ruido, flag VDP).
- **v0.50.0 — CODEX-OBSERVE + CODEX-REGRESS (alcance reducido):** siguiendo una segunda especificación del usuario (CODEX-OBSERVE/INTEL/REGRESS, 8 fases), se implementó solo lo de mayor ROI para una herramienta de caza: `core/observe.py` registra cada veredicto (VERDICT_CREATED) con versión/commit/evidence_hash en `.codexrc/intelligence/events/` (gitignored, Fase 1 reducida); `core/regress.py` mantiene un Regression Corpus (`.codexrc/intelligence/regressions/corpus.jsonl`, versionado en git) con defectos reales confirmados — ya cargado con RC-000127 (el bug de resolución de rutas de v0.49.0, fixed en v0.49.1) para que nunca vuelva sin que un test lo note. **Fuera de alcance deliberadamente:** motor de anomalías, differential/metamorphic/property-based/fuzz testing y CODEX-INTEL (fases 3, 5-8) — construirlos no encuentra bugs pagables más rápido, son inversión de ingeniería sin payoff claro para el objetivo actual.
- **v0.49.1 — EVIDENCE-CHAIN HARDENING:** siguiendo una especificación técnica recibida del usuario (principios: evidencia antes que conclusión, veredictos no se degradan silenciosamente, falta de evidencia ≠ evidencia de ausencia), se cerró un bug REAL de resolución de rutas en `build_chain`: cuando dos archivos comparten nombre (ej. `Wpil/Error.php` vs `Wpil/Table/Error.php`), el motor analizaba el archivo EQUIVOCADO (tomaba el último del recorrido, no el correcto). Esto producía veredictos sobre código que no era el del hallazgo. Se agregó también detección de saneo indirecto (`$v[] = (int)$x` antes de llegar al sink) y trazabilidad (`verdict_history` + `evidence_hash` por cadena). Validado: el caso real de hoy (link-whisper SQLi) pasó de DEMOSTRADO-ESTATICO (falso positivo por archivo mal resuelto) a cerrado tras el fix; regresión 4/4 en plugins ya validados limpios.
- **v0.48.0 — WIDE-HUNT:** el corpus de caza pasa de los 1.300 VDP a TODOS los plugins wordpress.org con ≥5k instalaciones (3.260 blancos, descargables en segundos con `core/wide_corpus.py`). La mejora EVIDENCE-CHAIN hace que el ruido ya no sea excusa: se CAZA a todos, se REPORTA solo donde pagan (mapa `vdp_mapa.json` con los 1.298 VDP y su bounty individual; sin VDP = solo CVE credit). Runner: `core/hunt_wide.py` con workers paralelos, filtro de updates frescos, salto de ya-auditados y marca de pagabilidad por hallazgo.
- **v0.47.0 — EVIDENCE-CHAIN + ABOGADOS:** motor de razonamiento de evidencia (estilo RacerD/Infer): cada finding recibe una cadena de evidencia (SOURCE controlable, FLOW, AUTH gates, SANITIZATION, SINK, CORRELATION) sobre la que actúan un FISCAL (debe probar los 4 requisitos del ataque), una DEFENSA (busca refutaciones: gate, sanitizador, prepare, contexto admin, inalcanzable) y un JUEZ determinista. Veredictos: CONFIRMED / DEMOSTRADO-ESTATICO / PROBABLE / CONTESTADO / DESCARTADO; los descartados por la defensa ya no llegan al informe. BFS de callers resuelve el alcance real (hook → ... → función del sink) y GATES-AUDIT ahora parsea loaders propios (`loader->add_action(hook, $obj, 'metodo')`).
- **v0.46.0 — VDP-1300:** extracción del directorio COMPLETO de Patchstack (1.300 productos con VDP activo y bounty, no solo los 76 del GOLDEN LIST) y cruce automático con la API de wordpress.org para armar la lista maestra de blancos pagables.
- **v0.45.1 — DIFF-HUNT PARALELO:** el motor escanea varios plugins a la vez (ThreadPool, `--workers N`, por defecto 4); lotes grandes en una fracción del tiempo.
- **v0.45.0 — DIFF-HUNT:** caza solo en líneas nuevas de versiones recientes (diff entre versión actual y anterior, filtrado por `last_updated`); lo recién escrito es lo menos auditado.
- **v0.44.0 — FP-AUTO-CLOSE:** dictamina solo los falsos positivos conocidos (prepare/absint, XSS escapado, whitelist de upload, in_array estricto, gates protegidos, ruido público por diseño); la consola solo muestra hallazgos vivos.
- **v0.43.0 — GATES-AUDIT:** veredicto automático de protección por handler (caps/nonce/nopriv/REST abierto); PLUGIN-BATCH entrega cada hallazgo ya dictaminado y prioriza los candidatos BAC.
- **v0.41.0 — VENDOR-FARM:** descubrimiento de familias de vendors WP en rango pagable (10k-200k installs) con estimación de paga Patchstack.
- **v0.40.0 — VERIFICACIÓN DEL SISTEMA:** verificación automática de hallazgos (contraste anónimo, doble petición, CACHE-BAIT); los informes solo exponen veredictos automáticos.
- **v0.39.0 — SPA-DISCOVERY v2:** login automático en apps JS modernas (fetch/Vite, escalera de rutas, reintentos anti-Cloudflare). Parches 0.39.1-0.39.2: TOKEN-INHERIT y SCHEME-PROBE (herencia de tokens y detección del scheme de auth en SPAs).
- **v0.38.0 — ESCALADA:** ante una cadena crítica el Hunter sigue solo (VERITAS dirigido, techo de impacto, kit PoC local, playbook). 0.38.1-0.38.4: parches de honestidad, severidad, diagnóstico de auth y guardia blindado de auto_update.sh.
- **v0.37.0 — DECOMPILE:** bytecode DEX → pseudocódigo legible (nivel 3).
- **v0.36.0 — REVERSE:** ingeniería inversa de DEX/class/ELF (nivel 2).
- **v0.35.0 — BIN-AUDIT:** análisis binario: secrets, endpoints, imports peligrosos (nivel 1).
- **v0.34.0 — CVE-MATCH:** patrones globales de 6 familias CVE reales + línea base del corpus.
- **v0.33.0 — TAINT-TRACE:** flujo de datos fuente→sink en PHP (vulns ciegas).
- **v0.31.0/v0.32.0 — COV-BAIT:** caza guiada por cobertura de código vía CDP + mutación con feedback.
- **v0.30.0 — BATERÍAS DEDICADAS:** LFI, SSTI, Web Cache Deception, GraphQL.
- **v0.29.0 — STEALTH-BAIT:** caza de superficie oculta (postMessage, CSP, evasión).
- **v0.28.0 — ENCADENAR HALLAZGOS:** cadenas deterministas + autoajuste del presupuesto de sondas.
- **v0.27.0 — CEREBRO:** fingerprint del blanco y priorización de la cola de caza.
- **v0.26.0 — SQLI-BAIT:** SQLi en 4 niveles (error, boolean, time, stacked).
- **v0.25.0 — VERITAS:** verificación con navegador real anti-falsos-positivos. 0.25.1-0.25.2: aislamiento por blanco y caza en lote + export TXT/JSON/PDF.
- **v0.24.0 — GHOST-SHIELD:** evasión WAF con memoria persistente (jitter, cooldown, orígenes quemados).
- **v0.23.0 — SLIPSTREAM:** carril asíncrono, hasta 64 sondas en vuelo (35x más rápido).
- **v0.22.0 — OVERDRIVE + PIPE-HUNT:** sondas en paralelo (hasta 8 workers) y caza por tubería desde stdin.
- **v0.21.0 — XSS-PRO 2:** DOM clobbering, prototype pollution, mXSS, dangling markup, redirects.
- **v0.20.0 — XSS-PRO + GHOSTHOOK:** 6 vectores XSS avanzados + colector de blind XSS.
- **v0.19.0 — escalada de chunks:** el Hunter sigue assets JS dinámicos.

## Inicio en Termux

```bash
pkg update -y
pkg install python git -y
pip install --upgrade pip
pip install -r requirements.txt

git clone https://github.com/Eliezer1817/codexRC.git
cd codexRC
chmod +x start_termux.sh
./start_termux.sh
```

Luego abre en el navegador del teléfono:

**http://127.0.0.1:8000**

El modo HUNTER está disponible en **http://127.0.0.1:8000/hunter.html**.

## Modo HUNTER (caza activa)

Pipeline modular con sesión heredada del escáner (pruebas autenticadas): araña (SPIDER) + CEREBRO (fingerprint y priorización) + hasta 20 baterías intercambiables (surface, api_js, bac_api, idor, csp, blind, xss_pro, params_plus, xss_get/forms/headers/dom, path, ssti, cache, graphql, cov, stealth, sqli) + cierre con VERITAS, encadenamiento (chain) y autoajuste (self_tune). Abre con `frontend/hunter.html`.

**Baterías de solo lectura (activas por defecto):**

- **SPIDER** — mapea páginas, parámetros, formularios y archivos JS de la superficie.
- **SURFACE** — sondea rutas comunes para descubrir superficie real bajo shells SPA, APIs JSON expuestas, rutas protegidas y archivos sensibles (`.env`/`.git`, sin extraer valores).
- **API-JS** — sigue los chunks lazy de Angular/webpack recursivamente y extrae las rutas API reales con su verbo (`get*` de lectura; los `do*` de escritura quedan excluidos siempre).
- **BAC-API** — contraste GET logueado vs. anónimo en endpoints API JSON: detecta datos privados accesibles sin sesión.
- **IDOR** — lectura A→B sobre endpoints API con sesión probando ids vecinos (query, path y body JSON), con evidencia de identidad.
- **PARAMS+** — fuerza 32 nombres de parámetros comunes en páginas dinámicas.
- **CORPUS XSS** — reflexión GET/formularios/headers/DOM con marcadores inertes: detecta contexto exacto y qué caracteres sobreviven crudos, sin disparar payloads funcionales.
- **CSP** — lee la cabecera CSP y reporta reglas débiles (unsafe-inline, wildcards, ausencia de script-src) y `X-Frame-Options`.

**Baterías opt-in (activables con los toggles de la UI):**

- **BLIND / GHOSTHOOK** (opt_blind) — ESCRIBE en el blanco: siembra el payload del colector GHOSTHOOK en el campo de texto más largo de cada formulario. Solo en programas que permitan stored/blind XSS o en labs propios. Requiere `blind_endpoint` (la URL del worker desplegado).
- **XSS-PRO** (opt_xss_pro) — dieciséis vectores avanzados:
  1. **postMessage XSS** — listeners de `message` sin chequeo de origen con sinks peligrosos.
  2. **Carga dinámica de script** — `createElement('script')`/`getScript` con src influible por query/hash.
  3. **mXSS** — sinks de re-serialización (`innerHTML = x.innerHTML`) y contenedores mutables (svg/math/noscript/template).
  4. **Dangling markup** — reflexión en atributo con comilla cruda: exfiltración pasiva sin JS; sube a alta cuando la CSP bloquea scripts inline.
  5. **XSS almacenado** — marcador inerte POST que reaparece en otra página (escritura mínima, igual filosofía que BLIND).
  6. **CSP bypass** — unsafe-inline, allowlist JSONP, wildcard `https:`, `base-uri` ausente, `strict-dynamic`, `object-src`.
  7. **DOM clobbering** — `eval(window.*)`, selectores de id por concatenación, `window[...]` dinámico y sinks alimentados por propiedades globales clobberables.
  8. **Prototype pollution** — `Object.assign`/`extend(true)`/merges con datos de la URL sin saneo.
  9. **Iframe srcdoc/src** — iframes construidos con datos de la URL: ejecución con el origen del propio sitio.
  10. **Base tag injection** — reflexión con `<` crudo dentro de `<head>` o sin `base-uri` en CSP: secuestra URLs relativas.
  11. **Open redirect** — parámetros de redirección (`url`, `next`, `return`, `goto`...) que controlan la cabecera `Location`.
  12. **Open redirect a `javascript:`** — si el redirect acepta esquemas peligrosos, el click ejecuta JS en el origen del sitio (alta).
  13. **Path reflection** — la RUTA se refleja en 404/rewrites: contexto de inyección que el corpus de parámetros no cubre.
  14. **Sanitizer fingerprint** — detecta DOMPurify/sanitize-html/js-xss y su versión; versiones viejas se marcan con sus bypasses conocidos.
  15. **Self-XSS escalable** — inputs que persisten y se re-renderizan al propio usuario (escalan a stored si otra vista consume el dato).
  16. **Cookie a sink** — `document.cookie` alimentando sinks de HTML.

**FILTRACIÓN DE DATOS:** los hallazgos que exponen datos de usuarios (emails, balances, perfiles ajenos) se separan de los hallazgos técnicos: el endpoint `GET /api/jobs` devuelve la sección `leaks` aparte y la UI los muestra en la caja roja **FILTRACIÓN DE DATOS DE USUARIOS**, arriba de todo.

## GHOSTHOOK (colector blind XSS)

Worker de Cloudflare (KV gratuito) incluido en `ghosthook/worker.js`:

- `/x.js` — payload que captura URL, cookies visibles, referrer, formularios y dump del DOM.
- `/c` — recibe beacons (POST, `sendBeacon` y fallback `Image()` para cuando la CSP bloquea `connect-src`).
- `/panel?token=...` y `/hit` — lectura de las capturas con token.

Para desplegarlo: crea un worker en tu cuenta de Cloudflare con un namespace KV y pega `worker.js` cambiando `TOKEN` y el binding por los tuyos. Nunca commitees tu token real: el archivo del repo usa un placeholder.

## API principal

- `GET /health` — estado del backend.
- `GET /api/info` — nombre y versión actual.
- `GET /api/status` — estado operativo, hora de inicio y jobs en memoria.
- `POST /api/scan` — ejecuta el pipeline completo de escaneo.
- `POST /api/hunter` — ejecuta una caza (opciones `opt_*` por batería).
- `GET /api/jobs` — lista los escaneos de la sesión (incluye sección `leaks`).
- `GET /api/jobs/<id>` — consulta un escaneo.
- `GET /api/jobs/<id>/log` — descarga el JSON completo del escaneo.
- `GET /api/jobs/<id>/export?format=txt|json|pdf` — informe del escaneo (TXT plano, JSON dump o PDF estilizado; filtraciones arriba).
- `POST /api/hunt_batch` — caza en LOTE: `{"targets": ["https://a.com", "https://b.com"], ...opciones}`; aislamiento por blanco, un blanco caído no tumba el lote.
- `GET /api/batch/<id>` — progreso en vivo del lote (log + resumen agregado).
- `GET /api/batches` — lista los lotes de la sesión.
- `POST /api/bin` — BIN-AUDIT: análisis binario/nativo. `{"path": "sdk.zip"}` → secrets hardcodeados, endpoints internos, imports peligrosos, fingerprint.
- `POST /api/re` — REVERSE: ingeniería inversa nivel 2. `{"path": "app.apk"}` → estructura interna (clases/métodos DEX, constant pool de JARs, .symtab de ELF, ofuscación, entropía).
- `POST /api/decompile` — DECOMPILE: bytecode DEX → pseudocódigo legible. `{"path": "app.apk"}` (opcional `"all_methods": true`).
- `POST /api/patterns` — CVE-MATCH: detección de familias de fallos históricos por patrón. `{"path": "plugin.php", "top": 20}`.
- `POST /api/taint` — TAINT-TRACE: flujo de datos fuente→sink en PHP. `{"path": "carpeta_o_archivo", "top": 20}`.
- `GET /api/pipeline/schema` — estructura visual del pipeline.

Las credenciales y tokens se usan únicamente en memoria durante el escaneo y no se devuelven en la respuesta de autenticación.

## Funcionalidades del escaneo

- Autenticación por cookies, login automático (formularios HTML o API JSON de SPAs), Bearer token y header personalizado.
- Auto-descubrimiento del endpoint de login para apps Angular/React/Vue: basta URL base, usuario y contraseña.
- Verificación de sesión contra una URL protegida, con detección de redirecciones al login y nombre visible del usuario.
- Reconocimiento de headers, redirecciones, cookies y headers de seguridad.
- Detección tecnológica y correlación de CVEs mediante CIRCL.
- Dashboard visual del pipeline.

Para una comprobación confiable, completa **URL protegida para verificar sesión** con una ruta que requiera autenticación (p. ej. `/account` o `/dashboard`). Si se deja vacía, se usa la URL objetivo.

## Auto-update en Termux (desde GitHub)

Flujo: editas en GitHub → haces commit → Termux detecta el commit → `git pull` automático → el servidor se reinicia → tu localhost queda actualizado al instante.

```bash
bash auto_update.sh         # vigila cada 20 segundos
bash auto_update.sh 10      # vigila cada 10 segundos
```

- Requiere que la carpeta sea un clon `git` (no un zip descargado).
- Usa `termux-wake-lock` si tenés Termux:API, para que Android no duerma el proceso.
- Toda la actividad queda en `auto_update.log`.
- Ctrl+C detiene el watcher y el servidor.
