# codexRC

![CodexRC](assets/banner.jpg)

**Automated Web Security Auditing Tool** con backend único, dashboard web local y modo HUNTER de caza activa.

> Solo usar en objetivos que tengas autorización para auditar.

> ⚠️ **Proyecto en desarrollo activo:** se actualiza con mucha frecuencia (a veces varias versiones por día) y la interfaz y las baterías cambian sin aviso. **No recomendado todavía para uso en producción**: tomalo como una herramienta en construcción. Si igual lo probás, revisá siempre esta sección de novedades antes de correr la última versión. Las sondas son de lectura A→B: contrastan el acceso con y sin sesión, sin alterar datos del objetivo.

## Arquitectura

- **Backend:** `backend/app.py` es la única implementación del servidor Flask (versión actual: **v0.38.2**).
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
  - `core/report_export.py` — exportación de informes TXT/JSON/PDF (filtraciones arriba, hallazgos por severidad).
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
