# codexRC

![CodexRC](assets/banner.jpg)

**Automated Web Security Auditing Tool** con backend único, dashboard web local y modo HUNTER de caza activa.

> Solo usar en objetivos que tengas autorización para auditar.

> ⚠️ **Proyecto en desarrollo activo:** se actualiza con mucha frecuencia (a veces varias versiones por día) y la interfaz y las baterías cambian sin aviso. **No recomendado todavía para uso en producción**: tomalo como una herramienta en construcción. Si igual lo probás, revisá siempre esta sección de novedades antes de correr la última versión. Las sondas son de lectura A→B: contrastan el acceso con y sin sesión, sin alterar datos del objetivo.

## Arquitectura

- **Backend:** `backend/app.py` es la única implementación del servidor Flask (versión actual: **v0.25.2**).
- **Core:** autenticación, reconocimiento, detección tecnológica, CVE matcher, GHOSTGATE, pipeline y el HUNTER se ejecutan dentro del backend.
  - `core/hunter.py` — spider, corpus XSS, DeepHunter (BAC/IDOR/CSP/superficie) y batería XSS-PRO.
  - `core/ghostgate.py` — evasión de Cloudflare delegando a navegador real cuando la IP está quemada.
  - `core/auth.py` — login automático por formulario HTML o API JSON (SPAs Angular/React), autodetección de endpoint de autenticación, CSRF y cabeceras Origin/Referer.
- **Frontend:** `frontend/index.html` (dashboard de escaneo) y `frontend/hunter.html` (terminal de caza). Solo presentan la interfaz y llaman a la API `/api/*`.
- **Termux:** únicamente inicia el backend y mantiene disponible `localhost`; no contiene lógica de auditoría. Compatible con `armv7l` (32 bits): el bypass de Cloudflare usa `cloudscraper`, sin binarios precompilados.
- **GHOSTHOOK:** `ghosthook/worker.js` — colector de blind XSS gratuito para Cloudflare Workers + KV (ver más abajo).
- **Logs:** cada escaneo se guarda en `reports/codexrc_<id>.json` descargable desde el dashboard; los eventos generales quedan en `reports/backend.log` en JSONL con rotación automática y `request_id`.
- **VERITAS (precisión anti-falsos-positivos):** una reflexión puede mentir: el servidor devuelve el marcador pero el navegador real lo sanea, lo escapa o el CSP lo mata. VERITAS re-lanza cada candidato en Chrome headless con un canario inerte (solo cambia `document.title`, nada visible, no exfiltra, no escribe nada) y comprueba si EJECUTÓ de verdad mirando el DOM final. Confirmado → queda como alta con sello "verificado en navegador". No ejecuta → baja a descartado como falso positivo. El arma de precisión: mejor 4 hallazgos que ejecutan de verdad que 20 que solo se reflejan.
- **GHOST-SHIELD (evasión WAF con memoria):** la evasión no va en el payload sino en el comportamiento: jitter aleatorio en cada sonda (nunca intervalo fijo de bot), clasificador de bloqueo (403/429/503 + firmas de WAF y páginas de challenge) y cooldown exponencial por origen. La memoria de quién nos bloqueó persiste en disco (`waf_state.json`, fuera del repo): sobrevive jobs, reinicios y días. Tras 4 bloqueos duros el origen se marca quemado y todas sus sondas se saltan al instante; tras 1 hora de purga vuelve a tener chances, y una respuesta sana lo rehabilita. Ante bloqueo sugiere GHOSTGATE (navegador real, IP limpia). La capa vive dentro de la sesión HTTP, así que cubre araña y todas las baterías sin excepción.
- **SLIPSTREAM (carril async):** la batería GET ahora vuela con I/O asíncrono: un solo hilo mantiene hasta 64 sondas en vuelo vía event loop (httpx), heredando la sesión autenticada. Benchmark contra el lab a 60 objetivos: 219 sondas/s (35x más rápido que el modo secuencial, con los mismos hallazgos). Si httpx no está disponible, cae automáticamente al camino de hilos anterior.
- **PIPE-HUNT (modo tubería):** `waybackurls sitio.com | python3 hunt_pipe.py --xsspro --workers 8` — recibe URLs desde cualquier herramienta por stdin, las caza con el Hunter del backend local y resume los hallazgos. Con `--no-wait` solo encola y sigue.
- **OVERDRIVE (velocidad):** las baterías del corpus (GET y formularios) y los módulos de sonda de XSS-PRO (dangling, base tag, redirect) ejecutan sus sondas en paralelo con hasta 8 workers (por defecto 4). En benchmark contra el lab: 5.4x más rápido con 8 workers, con exactamente los mismos hallazgos. El parámetro `workers` (1-8) se controla desde la interfaz del Hunter o la API; con 1 queda el modo secuencial clásico.
## Novedades por versión

Lo nuevo de cada entrega, de la más reciente a la más antigua:

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

Pipeline de 7 nodos con sesión heredada del escáner (pruebas autenticadas). Abre con `frontend/hunter.html`.

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
- **XSS-PRO** (opt_xss_pro) — quince vectores avanzados:
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
