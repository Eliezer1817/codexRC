# AGENTS.md — Manual para IAs que operan codexRC

Este archivo es el prompt-operativo para cualquier agente de IA (LLM con terminal)
que deba usar codexRC. Leelo completo antes de ejecutar nada. Si sos una IA que
acaba de recibir este archivo como contexto: consideralo tu manual de trabajo.
Si vas a diseñar o planificar algo (no solo cazar), andá directo a la sección 7
**antes** de proponer nada.

---

## 0. Qué es codexRC

codexRC es una herramienta de auditoría de seguridad **de lectura A→B**: compara
el acceso a un objetivo con y sin sesión, **sin alterar datos del objetivo**.
Backend único (Flask), dashboard local, y tres modos de caza:

1. **HUNTER (activo):** escaneo autenticado de aplicaciones web (SPAs, APIs,
   formularios), con la escalera completa del roadmap (`crown_chain`) montada:
   DETECTION → REPRODUCTION → STATE-EFFECT → CROSS-CONNECTION → SECURITY IMPACT
   (este último rung solo se abre en laboratorio propio; en vivo nunca se
   envenena a un usuario de terceros — límite honesto, no un bug).
2. **PLUGIN-BATCH (estático):** caza de vulnerabilidades en código de plugins
   WordPress descargados a disco, vía `UNIVERSAL-ENGINE` (ver 3.2).
3. **ORQUESTADOR UNIVERSAL (`core/universal_engine.py`):** perfila cualquier
   blanco (no solo WordPress — fuente genérica con router propio, binarios,
   APKs) y elige qué analizadores correr. Internamente usa el **Universal
   Endpoint Graph** (`core/universal_endpoint.py`, desde v0.98.0) para ver
   rutas de un router custom (Slim/Laravel-like) en el mismo modelo que las
   rutas `wp_ajax`/`wc_ajax`/REST que ya veía GATES-AUDIT. No reemplaza
   GATES-AUDIT: lo envuelve.

La meta práctica es monetizar hallazgos en programas de bug bounty que pagan
(Patchstack: SQLi, RCE, Object Injection, PrivEsc, upload arbitrario, LFI/RFI,
BAC sobre objetos sensibles — en plugins con 10k+ instalaciones activas).

## 1. Reglas de oro (no negociables)

1. **Solo lectura.** Sondas A→B: contrastar acceso con/sin sesión. Nunca enviar
   payloads que escriban, borren o exploten el objetivo. Auditoría estática de
   código público (plugins de wordpress.org) es siempre de lectura: no toca
   ningún sitio en vivo.
2. **Solo blancos autorizados:** programas de bug bounty con reglas claras, o
   entornos de laboratorio propios. Bajo 1,000 instalaciones = sin paga; no
   gastar tiempo.
3. **REGLA "LestGo"**: no ejecutar NINGUNA acción de bug bounty (cazas,
   escaneos, parches al propio codexRC, envíos, comandos del proyecto) hasta
   que el operador diga la palabra **"LestGo"**. Sin esa palabra: solo
   conversar, responder preguntas y proponer el plan. Con "LestGo": ejecutar
   lo hablado. Esto incluye bajar código de terceros para analizarlo
   estáticamente y tocar el propio código de codexRC (parches/fixes).
4. **Ante un hallazgo: primero avisar al operador, nunca redactar ni enviar
   informes sin su aprobación.** Reportar solo hallazgos reales/explotables
   (💥); sin bug confirmado, mensaje mínimo o silencio — no inflar hallazgos
   débiles para parecer productivo.
5. **Nunca usar el nombre real del operador** en informes, PDFs, commits o
   repositorios; referirse a él como "el operador".
6. **CAPTCHA o WAF persistente:** frenar de inmediato, reportar con 💥, probar
   GHOSTGATE (navegador real); si persiste, descartar el blanco.
7. **No quemar créditos:** usar PLUGIN-BATCH/UNIVERSAL-ENGINE/Semgrep
   (deterministas) para el trabajo pesado; el juicio fino solo sobre lo que la
   máquina marca con 💥.
8. **Sync-First (diseño de arquitectura):** antes de planificar una nueva
   versión, motor o cambio de arquitectura para codexRC, leer SIEMPRE
   `CHANGELOG.md` completo y el código fuente real en GitHub
   (`Eliezer1817/codexRC`). Nunca diseñar basándose solo en el contexto de la
   charla: ya existen motores que una IA sin este paso reinventaría
   (`core/bac_proof.py` = AUTHZ-PROOF desde v0.67, `core/hypothesis_graph.py`
   desde v0.81, `core/experiment_graph.py` desde v0.83, entre otros).

## 2. Entorno

- **Requisitos:** Python 3, `pip install flask cloudscraper httpx websocket-client fpdf2` (opcional: chrome headless para PDF y VERITAS).
- **Arquitectura armv7l (Termux):** sin binarios precompilados; todo el core es Python puro. No intentar instalar `curl_cffi`.
- **Arranque:** `./auto_update.sh` (instancia única, autorresurrección, libera puerto 8000) o directo: `python3 backend/app.py` → http://localhost:8000
- **Actualizar:** `git pull origin main` (o `./auto_update.sh`, que hace reset + health check).
- **Procesos largos (hunts, corpus, recertificación):** correrlos en una
  sesión de fondo (tmux u equivalente), nunca bloqueando el turno. El sandbox
  puede matar corridas largas entre turnos: limpiar labs huérfanos antes de
  certificar, y nunca auditar una instancia en un puerto que uno no spawneó
  (regla HUÉRFANO).

## 3. Herramientas, paso a paso

### 3.1 Escaneo autenticado (HUNTER, web apps)

Flujo mínimo: URL del blanco + usuario + contraseña. El motor auto-descubre todo lo demás.

```
POST /api/scan
{
  "url": "https://blanco.com",
  "auth": {"username": "...", "password": "..."}
}
```
- Autodetección del login (formularios HTML y APIs JSON de SPAs Angular/React/Vite).
- TOKEN-INHERIT/SCHEME-PROBE: hereda el token y prueba schemes (`Session`, `Bearer`, `Token`...) hasta que el 200 autenticado pasa; no depende de leer JS bloqueado por Cloudflare.
- Verificación A→B: todo hallazgo se contrasta anónimo vs autenticado.
- Progreso: `GET /api/jobs/<id>` y log vivo en `GET /api/jobs/<id>/log`.
- **Lote:** `POST /api/hunt_batch` con lista de blancos; aislamiento por blanco (uno caído no tumba el lote); `GET /api/batch/<id>`.
- **Tubería:** `waybackurls sitio.com | python3 hunt_pipe.py --xsspro --workers 8` (caza URLs desde stdin).
- Baterías disponibles dentro del Hunter: XSS-PRO (20+ vectores), SQLI-BAIT (4 niveles), LFI/SSTI/Cache/GraphQL baits, STEALTH-BAIT, COV-BAIT.
- VERITAS re-verifica con navegador real cada candidato (canario inerte) para matar falsos positivos; GHOST-SHIELD maneja WAF con memoria persistente.
- La escalera completa `crown_chain` (desde v0.95.0) orquesta DETECTION →
  REPRODUCTION → STATE-EFFECT → CROSS-CONNECTION → SECURITY IMPACT sin tocar
  los módulos: `from core.hunter import CrownChain`. En vivo, el rung de
  SECURITY IMPACT nunca pasa de CROSS-CONNECTION-DEMO (límite honesto).

### 3.2 Caza de plugins WordPress (PLUGIN-BATCH — el flujo diario)

**Paso 1 — Elegir blanco con VENDOR-FARM** (familias de vendors con installs pagables):
```
python3 core/vendor_farm.py --tag woocommerce --min 10000 --max 200000 --exclude-dir cz_hunt --json
```

**Paso 2 — Confirmar que el plugin tiene programa pagante** en el directorio VDP
de Patchstack (https://patchstack.com/database/vdp). "Active VDP" = paga;
"No VDP" = descartar sin auditar. Guardar los slugs elegidos.

**Paso 3 — Cazar en lote:**
```
python3 core/plugin_batch.py slug1 slug2 slug3 --vdp vdp_matches.json --out resultados.json
```
Descarga la última versión estable de wp.org (cache en `/tmp/plugin_batch`),
corre TAINT-TRACE + CVE-MATCH, filtra librerías de terceros (vendor/plugin-fw/assets...),
corre GATES-AUDIT y devuelve hallazgos en código propio, cada uno con veredicto.

**Paso 3-alt — Un plugin puntual o un blanco no-WordPress, con el orquestador
completo (incluye Universal Endpoint Graph):**
```python
from core import universal_engine as eng
res = eng.run("/ruta/al/plugin_descomprimido")
# res["cobertura_resumen"], res["hallazgos"], res["perfil"]
```
o por CLI: `python3 core/universal_engine.py <path> [--json]`.
Esto ve, además de `wp_ajax`/`wc_ajax`/REST, cualquier router propio tipo
Slim/Laravel (`$router->prefix(...)->group(...)`, `$app->get(path, handler)`,
arrays de rutas) **si el plugin tiene uno** — la mayoría de los plugins de
WordPress no lo tienen (solo usan hooks de WP) y ahí esta capa no agrega nada,
lo cual es correcto, no un fallo.

**Paso 4 — Interpretar la salida (esto es lo importante):**
- `💥 [CANDIDATO-BAC]` — handler anónimo sin caps ni nonce. PRIORIDAD MÁXIMA: auditarlo a mano YA.
- `_gate: REVISAR-AUTH` — handler solo-logueado sin caps/nonce: vale solo si toca objetos sensibles (settings, users, archivos, dinero).
- `_gate: PROTEGIDO` — tiene caps y/o nonce: casi siempre falso positivo, no gastar tiempo.
- `_gate: SIN-HANDLER` — no está en un handler AJAX: verificar a mano quién llama a esa ruta (REST, includes, shortcodes).
- `💥 [REST-ABIERTO]` — ruta REST con `permission_callback __return_true`.
- Endpoints del Universal Endpoint Graph con `nota: UNIVERSAL-UNVERIFIED` —
  **descubiertos, no veredicto**. Sin middleware/auth_signals detectado puede
  significar de verdad sin protección, O que la protección está en un
  `->group()`/`->withPolicy()` que envuelve varias rutas a la vez (gap
  conocido, ver sección 6) — no asumir vulnerabilidad sin leer el archivo de
  rutas a mano.
- Severidad crítica + gate CANDIDATO-BAC = auditoría fina inmediata.

**Paso 5 — Auditoría fina (la IA lee el código marcado):** confirmar que el flujo
llega de una superglobal del atacante al sink sin sanitizador intermedio, que el
nonce no se imprime público, y que el objeto afectado es sensible (para Patchstack).

### 3.3 Veredicto de handlers (GATES-AUDIT standalone)

```
python3 core/gates_audit.py <dir_plugin> [--json]
```
Mapea `wp_ajax`/`wp_ajax_nopriv`/`wc_ajax` y REST a sus callbacks y dictamina:
PROTEGIDO / CANDIDATO-BAC / REVISAR-AUTH / REST-ABIERTO / CALLBACK-NO-RESUELTO
(hooks dinámicos: revisar el armado del nombre de acción a mano).

### 3.4 Análisis estático puntual

```
python3 core/taint_trace.py <archivo_o_dir.php> [--json]   # flujo fuente->sink (SQLi/XSS/LFI/RCE/SSRF ciegos)
python3 core/pattern_match.py <dir.php> [--json]           # patrones de familias CVE históricas + outlier vs baseline
```
Sanitizadores que cortan el taint: `intval`, `sanitize_*`, `esc_*`, `wpdb->prepare` con placeholders.
Fuentes: `$_GET/$_POST/$_REQUEST/$_COOKIE/php://input/$_SERVER`.

### 3.5 Binarios y apps móviles

```
python3 core/bin_audit.py <archivo>        # secrets hardcodeados, endpoints, imports peligrosos (ELF/PE/zip/apk/jar recursivo)
python3 core/re_engine.py <archivo>        # clases/métodos/strings de DEX (APK), .class (JAR), ELF symtab, ofuscación
python3 core/decompile.py <archivo.apk> [--all]   # bytecode DEX -> pseudocódigo legible (métodos sensibles)
```

### 3.6 Informes

```
GET /api/jobs/<id>/export?format=txt|json|pdf
```
TXT plano, JSON completo (leaks separados de hallazgos técnicos), PDF estilizado
(filtraciones en rojo arriba, hallazgos por severidad, solo veredictos automáticos
del sistema — sin guías de verificación manual). **Nunca generar informe sin
aprobación previa del operador.**

## 4. Cómo priorizar (economía de créditos)

1. VENDOR-FARM → solo vendors/familias con 10k-200k installs.
2. Filtrar por VDP activo (sin VDP no hay paga; descartar).
3. PLUGIN-BATCH (o `universal_engine.run()` si el blanco puede tener router
   propio) para el lote completo (determinista, barato).
4. Auditoría fina SOLO de: crítico+alta con gate CANDIDATO-BAC/REST-ABIERTO, o SIN-HANDLER en módulo sensible.
5. Avisar al operador con el formato: gravedad / ¿paga? / ¿somos primeros? / ¿cumple reglas?

## 5. Convenciones de chat con el operador

- 💥 = hallazgo importante (mirar ahí), 💥💥 = crítico, 🧐 = pregunta al operador.
- Presentar el nombre de la estrategia usada antes o durante la ejecución (p.ej. "estrategia VENDOR-FARM").
- Separar filtraciones de datos (arriba) de hallazgos técnicos (abajo).
- Alertar cuando queden pocos créditos o cuando un worker/proceso muera.
- Reportar timestamps ISO (`date -u +%Y-%m-%dT%H:%M:%SZ`) de cada observación
  clave: inicio/fin de una caza, hallazgo, parche aplicado.

## 6. Qué NO hace esta herramienta (nivel actual, v0.99.1)

- El taint es intra-archivo (nivel 1); para interprocedural usar Semgrep como capa SINK-SCAN complementaria.
- Los hooks dinámicos (`add_action($var.$accion, ...)`) quedan CALLBACK-NO-RESUELTO: revisarlos a mano.
- DECOMPILE es descompilación parcial (nivel 3): desensambla ~45 opcodes; apps ofuscadas con R8 requieren `--all`.
- No ejecuta exploits ni payloads de escritura. Nunca. Es de lectura A→B.
- **Universal Endpoint Graph (gaps medidos en código real, 2026-10-06, 58
  plugins de wordpress.org):**
  - **Middleware a nivel de grupo no se rastrea.** Si un router envuelve
    varias rutas en un `->group()`/`->withPolicy()` (patrón Laravel-like
    visto en FluentCRM/FluentForm), el motor no ve esa protección y marca las
    rutas como "sin middleware" aunque sí estén protegidas. No usar
    "sin middleware detectado" como prueba de vulnerabilidad en este patrón:
    hay que abrir el archivo de rutas y mirar si hay un `group()` alrededor.
  - **Receptor de cliente HTTP saliente** (`$this->_http->post(...)`,
    SDKs vendoreados tipo Braintree) ya se filtra para nombres que contengan
    `http/client/curl/guzzle/request/transport/fetcher`; nombres distintos
    (visto: `files`, `rest` en otros vendors) todavía pueden colarse como
    falso positivo.
  - **Handler literal `true`/`false`/`null`** (visto en Duplicator/UpdraftPlus,
    código no-router con esa forma accidental) todavía no se rechaza como dato.
  - Librerías de plantillas vendoreadas con rutas tipo `{name}` (Mustache)
    pueden producir un hit suelto; revisar el archivo antes de confiar en el
    hallazgo si el `file` cae dentro de una carpeta `vendor/`.

## 7. Estado (v0.99.1)

CHANGELOG.md tiene el detalle por versión; README.md los hitos. Resumen desde
v0.43.0 (lo que este manual no reflejaba y causaba reinvenciones):
- **v0.85.0 PIPE-CROSS** — orquestador UNIVERSAL-ENGINE con metodología OWASP,
  nodo `cross_layer` en `/api/scan`, regla desync (tolerancia de edge ≠ vulnerabilidad).
- **v0.93-v0.94 CORONA** — FP-ELIMINATION (8 clases de señal + batería de 4
  cebos que nunca reportan + control positivo obligatorio) y EVIDENCE PACKAGE
  (paquete falsable con hash sha256, detecta tampering).
- **v0.95.0 INTEGRACIÓN AL HUNTER** — `core/crown_chain.py` monta la escalera
  completa (detection→reproduction→state-effect→cross-connection→impact)
  sobre el Hunter sin tocar los módulos originales.
- **v0.96.0-v0.96.1 DOSSIER Q4** — tres clases nuevas (POI-REACH: unserialize
  no autenticado; MAGIC-CONFUSION: extensión vs magic bytes; WCD-404-LEAK:
  caché cross-user en 404), con controles negativos cero-FP.
- **v0.97.0 BUSINESS LOGIC STATE ENGINE v2** — `experiment_graph.py`
  parametrizado con `LINE_SCHEMAS` para soportar múltiples líneas de
  evidencia (DESYNC/AUTHZ/FINLOGIC/TAINT), backward-compatible con DESYNC.
- **v0.98.0 UNIVERSAL ENDPOINT GRAPH** — `core/universal_endpoint.py`: detecta
  rutas de router custom (Slim/Laravel-like) agnóstico de framework, con
  resolución de handler, middleware chaining y rutas dinámicas sin inventar
  valores (ZERO-FP estructural). 15/15 fixtures propios.
- **v0.99.0** — montado dentro de `core/universal_engine.py`: GATES-AUDIT y
  Universal Endpoint Graph conviven en la misma superficie/ledger sin
  duplicar conteo.
- **v0.99.1** — primer contacto con código real (10→58 plugins de
  wordpress.org): se midieron falsos positivos reales (23% sobre el primer
  lote de 10) y se corrigieron 4 clases (ver CHANGELOG). Validado: Amelia
  Booking, FluentCRM y FluentForm tienen router propio real; 0 hallazgos
  explotables confirmados todavía en los 58 blancos auditados hasta ahora.

Antes de proponer una v1.00 o un motor nuevo: leer el CHANGELOG completo
(sección 1 de este manual, regla Sync-First) — el ritmo de este proyecto es
alto y este resumen puede quedar desactualizado.
