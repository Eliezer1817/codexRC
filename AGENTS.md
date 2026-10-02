# AGENTS.md — Manual para IAs que operan codexRC

Este archivo es el prompt-operativo para cualquier agente de IA (LLM con terminal)
que deba usar codexRC. Leelo completo antes de ejecutar nada. Si sos una IA que
acaba de recibir este archivo como contexto: consideralo tu manual de trabajo.

---

## 0. Qué es codexRC

codexRC es una herramienta de auditoría de seguridad web **de lectura A→B**:
compara el acceso a un objetivo con y sin sesión, **sin alterar datos del objetivo**.
Tiene backend único (Flask), dashboard local, y dos modos de caza:

1. **HUNTER (activo):** escaneo autenticado de aplicaciones web (SPAs, APIs, formularios).
2. **PLUGIN-BATCH (estático):** caza de vulnerabilidades en código de plugins WordPress descargados a disco.

La meta práctica es monetizar hallazgos en programas de bug bounty que pagan
(Patchstack: SQLi, RCE, Object Injection, PrivEsc, upload arbitrario, LFI/RFI,
BAC sobre objetos sensibles — en plugins con 10k+ instalaciones activas).

## 1. Reglas de oro (no negociables)

1. **Solo lectura.** Sondas A→B: contrastar acceso con/sin sesión. Nunca enviar
   payloads que escriban, borren o exploten el objetivo.
2. **Solo blancos autorizados:** programas de bug bounty con reglas claras, o
   entornos de laboratorio propios. Bajo 1,000 instalaciones = sin paga; no gastar tiempo.
3. **Ante un hallazgo: primero avisar al operador, nunca redactar ni enviar
   informes sin su aprobación.**
4. **Nunca usar el nombre real del operador** en informes, PDFs o repositorios.
5. **CAPTCHA o WAF persistente:** frenar de inmediato, reportar con 💥, probar
   GHOSTGATE (navegador real); si persiste, descartar el blanco.
6. **No quemar créditos:** usar PLUGIN-BATCH/Semgrep (deterministas) para el
   trabajo pesado; el juicio fino solo sobre lo que la máquina marca con 💥.

## 2. Entorno

- **Requisitos:** Python 3, `pip install flask cloudscraper httpx websocket-client fpdf2` (opcional: chrome headless para PDF y VERITAS).
- **Arquitectura armv7l (Termux):** sin binarios precompilados; todo el core es Python puro. No intentar instalar `curl_cffi`.
- **Arranque:** `./auto_update.sh` (instancia única, autorresurrección, libera puerto 8000) o directo: `python3 backend/app.py` → http://localhost:8000
- **Actualizar:** `git pull origin main` (o `./auto_update.sh`, que hace reset + health check).

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

**Paso 4 — Interpretar la salida (esto es lo importante):**
- `💥 [CANDIDATO-BAC]` — handler anónimo sin caps ni nonce. PRIORIDAD MÁXIMA: auditarlo a mano YA.
- `_gate: REVISAR-AUTH` — handler solo-logueado sin caps/nonce: vale solo si toca objetos sensibles (settings, users, archivos, dinero).
- `_gate: PROTEGIDO` — tiene caps y/o nonce: casi siempre falso positivo, no gastar tiempo.
- `_gate: SIN-HANDLER` — no está en un handler AJAX: verificar a mano quién llama a esa ruta (REST, includes, shortcodes).
- `💥 [REST-ABIERTO]` — ruta REST con `permission_callback __return_true`.
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
3. PLUGIN-BATCH para el lote completo (determinista, barato).
4. Auditoría fina SOLO de: crítico+alta con gate CANDIDATO-BAC/REST-ABIERTO, o SIN-HANDLER en módulo sensible.
5. Avisar al operador con el formato: gravedad / ¿paga? / ¿somos primeros? / ¿cumple reglas?

## 5. Convenciones de chat con el operador

- 💥 = hallazgo importante (mirar ahí), 💥💥 = crítico, 🧐 = pregunta al operador.
- Presentar el nombre de la estrategia usada antes o durante la ejecución (p.ej. "estrategia VENDOR-FARM").
- Separar filtraciones de datos (arriba) de hallazgos técnicos (abajo).
- Alertar cuando queden pocos créditos o cuando un worker/proceso muera.

## 6. Qué NO hace esta herramienta (nivel actual)

- El taint es intra-archivo (nivel 1); para interprocedural usar Semgrep como capa SINK-SCAN complementaria.
- Los hooks dinámicos (`add_action($var.$accion, ...)`) quedan CALLBACK-NO-RESUELTO: revisarlos a mano.
- DECOMPILE es descompilación parcial (nivel 3): desensambla ~45 opcodes; apps ofuscadas con R8 requieren `--all`.
- No ejecuta exploits ni payloads de escritura. Nunca. Es de lectura A→B.

## 7. Estado (v0.43.0)

CHANGELOG.md tiene el detalle por versión; README.md los hitos. Últimos hitos:
GATES-AUDIT (veredicto automático de handlers), PLUGIN-BATCH (caza por slugs),
VENDOR-FARM (familias pagables), VERIFICACIÓN DEL SISTEMA (veredictos automáticos en informes).
