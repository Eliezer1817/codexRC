# CodexRC — Historial completo de falsos positivos, bugs del motor y lecciones

**Versión del documento:** 1.0 (03/10/2026)
**Motor:** CodexRC / UNIVERSAL-ENGINE v0.57.10
**Autor:** elaborado por el agente de IA del operador (identidad del operador omitida por política)
**Propósito:** presentar a expertos por área el historial real de falsos positivos y defectos del motor, con la causa raíz de cada uno, el fix aplicado y preguntas abiertas. Cada área es autocontenida: se puede enviar a un experto solo su sección.

**Contexto mínimo para cualquier experto:** CodexRC es un motor de caza de vulnerabilidades en plugins de WordPress escrito en Python puro (corre en Android/Termux armv7l, sin librerías compiladas). Tiene capas: TAINT-TRACE (flujo de datos fuente→sink, intra-archivo, punto fijo), PATRON/CVE-MATCH (patrones estructurales ponderados, sin firmas fijas), GATES-AUDIT (mapeo de hooks AJAX/REST a sus callbacks y sus gates), EVIDENCE-CHAIN (cadena de evidencia evaluada por agentes deterministas: FISCAL, DEFENSA, JUEZ; nunca un LLM como juez) y DIFF-HUNT (solo código nuevo de los últimos 90 días). Filosofía declarada: preferir falsos negativos a falsos positivos (camino Infer/CodeQL). Regla de oro operativa: cada patrón de FP recurrente se codifica UNA vez como regla; nunca se tria a mano dos veces la misma clase.

---

## ÁREA 1 — Análisis de taint / flujo de datos (TAINT-TRACE)

**Para expertos en:** taint analysis, análisis estático de PHP, abstract interpretation.

### FP-1.1 · Sinks que matchean wrappers de WordPress (RC-000128)
- **Qué pasó:** el sink SQLi `->query(` matcheaba `new WP_Query`, `WP_Term_Query`, `WP_User_Query`. El core de WordPress sanitiza internamente; no es SQL crudo.
- **Impacto medido:** 19 de 39 SQLi del backlog wide-hunt eran esta familia (mayoría en unlimited-elements, que usa `$query->query($args)` en vez de `$wpdb->query`).
- **Fix (v0.57.5):** el sink exige `$wpdb->` o `$this->` con contexto de tabla real; los wrappers conocidos de WP se excluyen por nombre de clase.
- **Pregunta al experto:** ¿conviene una lista negativa de wrappers o resolver el tipo del receptor (interprocedural light) antes de decidir si es sink?

### FP-1.2 · `prepare` multilínea autorreferencial (RC-000129)
- **Qué pasó:** el patrón de "prepare seguro" no limpiaba el taint cuando el formato era construido iterativamente: `$q = $wpdb->prepare($q, $args)` y acumulación `.=`. El punto fijo re-infectaba la variable en cada iteración, y el formato concatenado con `$wpdb->prefix` rompía el reconocimiento de placeholder.
- **Fix (v0.57.5):** reconocimiento de la forma autorreferencial + el prefijo de tabla tratado como constante segura en el format-string.
- **Pregunta al experto:** en análisis intra-archivo con punto fijo, ¿cuál es la forma correcta de modelar "acumulador que pasa por prepare en un loop" sin análisis de reachability completo?

### FP-1.3 · Taint a nivel archivo, sin scopes de función (RC-000130)
- **Qué pasó:** una variable local reutilizada como texto no-SQL en OTRA función del mismo archivo (`$jsst_query` = `implode` de términos de búsqueda en js-support-ticket) contaminaba los queries de todas las demás funciones del archivo.
- **Fix (v0.57.5):** scopes de función: el taint vive y muere dentro del cuerpo de cada función.
- **Pregunta al experto:** obvio en retrospectiva, pero el diseño original elegía granularidad de archivo por simplicidad. ¿Qué granularidad mínima recomendarían para un motor de Python puro: función, bloque, o SSA light?

### Controles positivos del área (para calibrar)
- Lab vulnerable 3/3 detectado (SQLi ciego, XSS, unserialize), 0 FP en control sanitizado.
- Sanitizadores reconocidos: `intval/absint/sanitize_*/esc_*`, `prepare` con placeholders, `extract($_GET)` flag directo, `implode(array_fill(%d))` ya no se taintea (FP de format-string).

---

## ÁREA 2 — Patrones estructurales / BAC (PATRON + CVE-MATCH)

**Para expertos en:** static analysis rules, WordPress security, authorization logic.

El detector de patrones combina señales estructurales débiles ponderadas (hook nopriv +3, escritura +3, input +2, protección -4) y cita la familia CVE al disparar. Sin firmas fijas: la misma regla "re-descubre" fallos conocidos. Redescubrió solo, por puro patrón, el 0-day real de RegistrationMagic (`validate_ipn`, paypal.php:193, salto `validate_ipn→callback→paypal_ipn` nopriv, sin autenticación) — validación de que el enfoque funciona.

### FP-2.1 · BAC: handler con gate interno (RC-000131)
- **Qué pasó:** hooks `wp_ajax_nopriv` registrados de forma INTENCIONAL (formularios front-end públicos) pero con gate completo dentro del handler: whitelist de métodos + nonce obligatorio + capability check. El patrón disparaba por el HOOK, sin mirar el cuerpo. Caso real: pods `admin_ajax`: 20 sinks reportados, todos FP.
- **Fix (v0.57.7):** `finalize()` postergado: los hallazgos esperan el mapa de TODAS las funciones, resuelven el callback del hook (`'fn'`, `array($this,'método')`) y escanean el CUERPO del handler en busca de gates. Handler gateado = descartado.

### FP-2.2 · BAC: gate en el caller, no en la función (RC-000133)
- **Qué pasó:** el patrón disparaba sobre funciones que ni siquiera tienen hook nopriv: solo "escribe datos + usa input + bonus de nonce público en el archivo". El gate vivía en el CALLER (pods `admin_save`, gate en I18n.php:123: `pods_is_admin` + `wp_verify_nonce`).
- **Fix (v0.57.7):** se exige que la señal nopriv esté en el cuerpo escaneado.

### FP-2.3 · Ramas públicas por diseño (RC-000132) — SIN RESOLVER COMPLETO
- **Qué pasó:** handler nopriv cuyas ramas públicas son features intencionales (render de bloques de ads, ads.txt público) y las ramas sensibles están gated por option default-off o constante "pro". El write real (`update_option`) vive en la rama gated.
- **Estado:** parcial. El gate interno se cubre; la separación de ramas por diseño SIGUE REQUIRIENDO triaje. **Pregunta abierta al experto:** ¿cómo distinguir automáticamente "rama pública por diseño" de "rama pública alcanzable por salto de flujo"? ¿Análisis de dominance en el CFG alcanza?

### FP-2.4 · "Verificación de pago degradable" que es diseño del vendor (RC-000134)
- **Qué pasó:** wc-multivendor-membership completa la suscripción sin contactar gateway. Suena a IPN-downgrade (familia CVE-2026-9242), pero: el paymode se valida contra allow-list doble estricta (`enabled` ∩ `offline`, `in_array` con `true`), los gateways online SOLO se completan tras IPN verificado, y `is_valid_member_id` exige `get_current_user_id() == $member_id` (self-scoped, no IDOR). El propio vendor dejó comentario citando CVE-2026-12967: ya parcheó esta clase.
- **Lección:** "completa pago sin gateway" no es bug cuando el método es offline habilitado por el admin (conciliación manual). La regla para automatizar: exigir AUSENCIA de `in_array` estricto sobre el paymode antes de reportar. Aún manual.

### FP-2.5 · Loose-cmp: comparación floja sin contexto de autorización (RC-000135)
- **Qué pasó:** el patrón `loose-auth-cmp` (familia CVE-2023-6875, Post SMTP) disparaba con CUALQUIER `==`/`!=` sobre input de usuario con score 6/6 de una sola señal: filtros de query (`$_POST['term_id'] != 0`), flags (`checkbox == 1`), presencia de parámetros (`$_GET['code'] != ''`), routers de flujo OAuth. 23 de 29 hallazgos N1∩VDP de esta familia eran esta clase.
- **Matices que costó aprender (sub-fixes):**
  - El token `auth` matcheaba `author` en queries de posts → lookbehind anti-author.
  - El token `token` mantenía vivo cualquier handler OAuth por contexto → tokens débiles solo cuentan en el snippet de la comparación (±80 chars), no en contexto.
  - `"nonce was verified"` en un COMENTARIO contaba como gate → comentarios despojados del contexto antes de evaluar tokens.
  - El snippet se toma de la LÍNEA SEÑALADA, no del primer `==` del cuerpo (FP: checkbox de newsletter dentro de una función de registro llena de password/nonce en jsst-hooks.php:175).
- **Fix (v0.57.9):** tokens AUTH fuertes (password/passwd/user_pass/nonce/capability/current_user_can/login/role/privilege/cookie/manage_options) en snippet o contexto ±5 líneas; tokens débiles (auth/token/secret) solo en operandos.
- **Control crítico preservado:** el caso real 6875 (`==` sobre password) sigue vivo tras todas las guardas. El filtro de flag en el mismo archivo muere.

### FP-2.6 · Loose-cmp: router detrás de gate adyacente (RC-000136)
- **Qué pasó:** quedaban 6 vivos de la forma `$_GET['auth']==$ntInfo['lcode']` (social-networks-auto-poster, 6 archivos clonados): llevan "auth" en el operando (pasaban la guarda de tokens) pero en la misma línea o la anterior hay un capability check real (`nxs_snap_user_can_access()`). Esa llamada ES el control de acceso; la comparación floja es solo el router del flujo.
- **Fix (v0.57.10):** `_GATE_ADJ` generalizada (sin hardcodear funciones de plugin): `current_user_can|user_can(|is_user_logged_in|_can_access\b|wp_die|die(|exit` en ±1 línea → FP. Se evalúa ANTES que los tokens (si no, los 6 volvían por el token del operando).
- **Residuo conocido:** 2 hallazgos fuera del backlog con el gate a 2-3 líneas (nxs_class_snap.php:177, filtro magic-quotes; nxs_functions_adv.php:10, dispatcher ajax con `current_user_can` 2 líneas arriba). ¿Ensanchamos la ventana a ±2 o mantenemos ±1 para no matar gates lejanos bypasseables? **Pregunta abierta al experto.**

---

## ÁREA 3 — Cadena de evidencia / resolución de rutas (EVIDENCE-CHAIN)

**Para expertos en:** program analysis infrastructure, data structures, verificación.

### BUG-3.1 · Resolución de ruta por basename (RC-000127) — bug CRÍTICO real del motor
- **Qué pasó:** dos archivos del mismo plugin compartían basename (`Wpil/Error.php` vs `Wpil/Table/Error.php`). El fallback de resolución de ruta en `build_chain` no rompía el loop externo de `os.walk`, así que el motor analizaba el archivo EQUIVOCADO: el ÚLTIMO visitado, no el correcto.
- **Impacto:** cualquier hallazgo en un archivo con basename duplicado podía llevar evidencia de otro archivo. Cuantificación del alcance en corridas previas: no determinado. Caso testigo real: link-whisper SQLi pasó de falso positivo "DEMOSTRADO-ESTATICO" a correctamente CERRADO tras el fix.
- **Fix (v0.49.1):** match por ruta relativa exacta primero; el basename quedó como último recurso.
- **Pregunta al experto:** en un walker sobre árboles de archivos, ¿qué invariantes de integridad referencia→contenido recomiendan (hash de contenido como testigo, índice de rutas normalizadas)?

### Diseño del área (para opinión general)
- Cada hallazgo recibe cadena SOURCE/FLOW/AUTH/SANITIZATION/SINK/CORRELATION.
- FISCAL prueba 4 requisitos; DEFENSA argumenta refutaciones (gate, sanitizador, prepare, admin-only); JUEZ determinista emite veredicto: CONFIRMED / DEMOSTRADO-ESTATICO / PROBABLE / CONTESTADO / DESCARTADO. Nunca un LLM como juez.
- Los DESCARTADO por la DEFENSA se filtran de los vivos en DIFF-HUNT.

---

## ÁREA 4 — Mapeo de gates / hooks (GATES-AUDIT)

**Para expertos en:** WordPress internals, hooks AJAX/REST.

### FP-4.1 · Notices cosméticos con nonce (validación de campo)
- **Qué pasó:** los primeros candidatos BAC de wpdatatables y ai-engine resultaron notices cosméticas (updates de UI) con nonce válido. El veredicto REVISAR-AUTH se disparaba por mapear bien el hook pero no ponderar qué HACÍA la acción.
- **Lección incorporada:** CANDIDATO-BAC requiere además write con impacto (options de otro scope, datos de terceros), no solo handler sin gate aparente.

### FP-4.2 · Hooks dinámicos no resueltos (nivel honesto declarado)
- **Qué pasó:** `CALLBACK-NO-RESUELTO` para hooks registrados con nombres dinámicos (`add_action('wp_ajax_'.$this->prefix.'_'.$action, ...)`). El motor los marca nivel 1 (no los resuelve) en vez de inventar.
- **Pendiente histórico:** deep-dive de ai-engine `files.php` (candidates LFI `file_get_contents $path` en classes/modules/files.php:140,167 + rest.php SIN-HANDLER). Nunca se cerró formalmente. **Pregunta al experto:** ¿vale la pena resolver prefijos de hook por inferencia de constantes de clase, o el ratio FP/TP no lo paga?

### Registros auditados y muertos en triaje manual (muestra del ruido que producen los handlers ajax sin gate aparente)
- cartflows v3.2.1: el "código sospechoso nuevo" era el parche de seguridad del propio vendor.
- captcha-code-authentication v3.33: comparación floja HEREDADA solo en registro (categoría no pagada); el login está blindado con `===`.
- simple-local-avatars v2.8.6: nonce + whitelist mime estricta.
- ht-mega theme-builder v3.3.2: refleja constantes internas, no input.
- wpzoom instagram settings v2.4.0: imprime flags internos del plugin.

---

## ÁREA 5 — Triaje de hallazgos dinámicos / web apps (no-WordPress)

**Para expertos en:** web security, DOM security, SPAs.

### FP-5.1 · Reflexión en puntos RSC/Next.js (xenpaid.com)
- **Qué pasó:** CODEX-OBSERVE marcó puntos de reflexión que en Next.js con RSC no ejecutan script (los datos viajan por el protocolo RSC, no por HTML directo).
- **Lección:** la superficie XSS efectiva depende de la arquitectura de render; un motor que no modela RSC/hidratación va a reportar reflexiones inertes.
- **Pregunta al experto:** ¿qué heurística mínima distingue un sink DOM real de una reflexión RSC inert, sin renderizar?

### FP-5.2 · postMessage handlers sin origen verificado... que sí lo verifican (xenpaid)
- **Qué pasó:** EVIDENCE-CHAIN + TAINT-TRACE marcaron hallazgos postMessage; la DEFENSA los refutó como falsos positivos (checks de origin presentes).
- **Estado:** cerrados por refutación de la DEFENSA. La cadena funcionó como debe.

---

## ÁREA 6 — Infraestructura, operación y tooling propio

**Para expertos en:** pipelines de análisis, reliability, LLM ops.

### BUG-6.1 · Workers del sandbox se niegan SIEMPRE a análisis de seguridad
- **Qué pasó:** los sub-agentes del sandbox (workers de IA) rechazaron TODO análisis de seguridad sobre código concreto, probado con 3 framings (directo, contexto defensivo completo, micro-tarea neutra de trazabilidad): 6 negativas.
- **Decisión:** Semgrep v1.178.0 en sandbox como capa SINK-SCAN determinista (nunca se niega); los workers SOLO para tareas no-security (descargas, inventarios, formateo). El LOGIC-AUDIT lo hace el agente principal.
- **Pregunta al experto:** patrones conocidos para enrutar tareas a modelos que no se niegan sin perder cobertura?

### BUG-6.2 · Arsenal: selección de payload atascada en UNA opción (v0.57.1)
- **Qué pasó:** el módulo de pruebas mantenía un solo payload elegido manualmente y no ciclaba la suite. Causa: la validación de UI bloqueaba la auto-selección y el loop no escalaba por tipo de hallazgo.
- **Fix (v0.57.1):** auto-selección por tipo de hallazgo conocido; default a la matriz LAB completa para tipos desconocidos. Se eliminó el estado "atascado".

### BUG-6.3 · Regresión de resolución de URLs absolutas (UNIVERSAL-API, v0.57.x)
- **Qué pasó:** la refactorización a UNIVERSAL-API-MATRIX rompió `_armar_url_api`: endpoints absolutos se concatenaban mal; y un payload sin el campo `login` que el backend esperaba causaba rechazo silencioso.
- **Fix:** manejo de absolutos + mecanismo de payload adaptativo que aprende los campos que el servidor exige.
- **Lección:** cada refactorización de URL-building necesita tests con URLs absolutas, relativas y con base combinada, ANTES de tocar el motor.

### BUG-6.4 · Endpoints no-responsivos consumían el presupuesto del lote
- **Qué pasó:** en caza en lote, un blanco con API colgada congelaba la ejecución (timeout largo por intento).
- **Fix:** presupuesto duro de 60 intentos por blanco + timeout por intento + aislamiento (un blanco fallido no tumba el lote).

### BUG-6.5 · Filtro de ruido de librerías: rutas sin barra inicial (v0.42.x)
- **Qué pasó:** `is_noise` no matcheaba rutas de librerías sin `/` inicial, así que vendor/ y lib/ enteros entraban al análisis y generaban hallazgos de terceros.
- **Fix:** normalización con prepend de `/`.

### BUG-6.6 · Type-confusion en la medición del propio agente (metodología, v0.57.8)
- **Qué pasó:** al comparar hallazgos viejos vs nuevos por UBICACIÓN (archivo+línea±5), el agente contó como "sobreviviente" un hallazgo de OTRA familia que casualmente caía en la misma línea. El "15 loose-cmp vivos" real era 29, y 2 de los "sobrevivientes" eran de otra clase.
- **Fix:** el match exige misma familia de patrón, no solo ubicación. Lección de método: medir supervivencia exige igualdad de (ubicación, tipo), nunca ubicación sola.

### Limitaciones estructurales honestas (declaradas, no bugs)
- Python puro en armv7l/Termux: no hay curl_cffi ni librerías compiladas; se usan fallbacks (cloudscraper). Los análisis interprocedurales se delegan a Semgrep.
- TAINT-TRACE intra-archivo: para interprocedural está Semgrep (capa separada).
- El punto fijo es heurístico (nivel 1); documentado como tal.

---

## Los dos controles que validan el sistema (verdaderos positivos)

1. **RegistrationMagic `validate_ipn` (paypal.php:193):** 0-day real, DEMOSTRADO-ESTATICO por la cadena completa, salto `validate_ipn→callback→paypal_ipn` nopriv sin autenticación. Redescubierto por el patrón de CVE-MATCH SIN firma del fallo, y confirmado por EVIDENCE-CHAIN. Después de 10 clases de FP cerradas, el caso sigue vivo.
2. **CVE-2023-6875 lab (Post SMTP family):** `==` flojo sobre password, sin gate adyacente, sin tokens de comentario. Sigue detectado tras TODAS las guardas (135, 136). Es el test de no-regresión de la familia loose-cmp.

**Métrica de madurez del corpus:** 10 clases de FP codificadas (RC-000127 a RC-000136). Última familia cerrada (loose-cmp N1∩VDP): 29 hallazgos → 0 vivos, 23 muertos por RC-000135 y 6 por RC-000136, 0 muertos a mano en la última pasada.

---

## Preguntas transversales para cualquier experto

1. Con filosofía "preferir FN a FP", ¿dónde está el punto óptimo de endurecimiento de reglas antes de empezar a perder TP reales que no conocemos?
2. Las guardas actuales son regex sobre contexto local (±1 a ±5 líneas). ¿Qué caso justificaría pasar a análisis de CFG real (dominance, reachability) y cuál es el costo esperable?
3. Corpus de regresión: hoy son 10 casos con repro mínima. ¿Qué tamaño y forma de corpus consideran suficiente para refactors del motor sin miedo (estilo Soundness testing)?
4. Segunda etapa de juicio: con las restricciones (sin LLM externo confiable para security, Python puro), ¿reglas deterministas + cola de triaje batch es el techo razonable, o hay una capa automática que estamos dejando en la mesa?
