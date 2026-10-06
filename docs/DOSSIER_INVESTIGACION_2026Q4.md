# Dossier de investigación — Q4 2026

Investigación de clases de vulnerabilidad recientes, de alto valor y
ausentes del motor. Criterio de admisión: paga en Patchstack/bounties,
es novedosa (no está en tools abiertos) y encaja en los oráculos
honestos del pipeline. Invariante: nada de esto se ejecuta en vivo sin
orden del operador.

---

## 1. MAGIC-CONFUSION — extensión vs contenido en rutas de upload

**Fuente:** CVE-2026-65640, WordPress Core ≤ 7.0.3, Author+ RCE
(CVSS 9.1, publicado 12/08/2026, hallado por pwn.ai, parche 7daaa50).

**La lección estructural:** ImageMagick decide el formato por magic
bytes (`%!`, `\x04%!`, `\xC5\xD0\xD3\xC6`, formato prefijado tipo
`EPS:file.png`), WordPress confía en la extensión. Cualquier ruta de
upload que llegue a Imagick/Ghostscript SIN `wp_check_filetype_and_ext()`
es RCE potencial. Las rutas que ya lo esquivan en core: XML-RPC
`wp.uploadFile` y extracción de cover-art de MP3s, ambas vía
`wp_upload_bits()` que jamás inspecciona contenido.

**Por qué es calibre:** es una familia NUEVA (agosto 2026) y aplica a
cualquier PLUGIN que procese media con Imagick en rutas de upload
propias. Nadie publica un hunter estático de esta clase todavía.

**Integración propuesta (estática):**
- `pattern_match`: familia MAGIC-CONFUSION. Señal: sink
  `readImage`/`readImageBlob`/`Imagick(` alcanzado desde una ruta de
  upload donde NO domina `wp_check_filetype_and_ext` ni sniffing de
  contenido propio.
- `gates_audit`: el gate aquí es el check de contenido, no un nonce:
  extender el modelo de gates para tratar validadores de contenido
  (finfo, magic bytes, `getimagesize`) como gates de sink.
- Escalera honesta: MAGIC-CONFUSIBLE (estático) → verificación WP-LAB
  con payload PostScript inerte y control benigno (un PNG real).
  Nunca Ghostscript ejecutable en blanco de terceros: PoC con archivo
  inerte que DEMUESTRE el routing, no la ejecución.

**Precio:** RCE pagable; Author+ = rol aceptado por Patchstack.

---

## 2. POI-REACH — Object Injection unauth con gadget chain

**Fuente:** CVE-2026-2599, "Contact Form Entries" ≤ 1.4.7, CVSS 9.8,
unauthenticated PHP Object Injection → RCE. `download_csv()` hace
`unserialize()` de input del usuario sin `allowed_classes`.

**La lección estructural:** la clase sigue pagando (Patchstack la
lista explícitamente). Lo que falta en los tools abiertos no es
detectar `unserialize` — es probar **alcance**: unauth + gadget chain
disponible en el propio plugin. La superficie ganadora: handlers de
export/CSV/download, que reciben parámetros serializados y casi nunca
pasan por gates.

**Por qué es calibre:** `unserialize($input)` unauth con POP chain
propia = $600–$2.600 según installs. Nuestro TAINT-TRACE ya detecta
unserialize; falta la parte que cobra.

**Integración propuesta (estática):**
- `taint_trace`: sink unserialize con línea `SOURCE` (ya existe);
  etiquetar handlers export/download/csv como superficie prioritaria.
- `gates_audit`: veredicto AUTH del handler que contiene el
  unserialize (unauth/nonce-less = candidato POI-REACH).
- Gadget chain: `deep_scan` indexa clases del plugin con métodos
  mágicos (`__destruct`, `__wakeup`, `__toString`) y propiedades
  llamables → POP-CANDIDATE como evidencia de explotabilidad
  (demostrable en WP-LAB con harmless chain).
- Escalera honesta: POI-DETECTED (sink unauth) → POI-CHAIN (gadget
  en el mismo plugin) → POI-DEMO (WP-LAB, chain inerte).

---

## 3. WCD-404-LEAK — la cache que guarda cadáveres con datos

**Fuente:** reporte real 2025 (System Weakness, ValidByAccident,
marcado duplicado = confirmando que el programa lo paga): endpoint
autenticado con payload de extensión falsa devuelve **404 con el cuerpo
lleno de datos privados**, y el cache guarda el 404 como clave única.
Usuario B visita la misma URL → datos del usuario A.

**La lección estructural:** el status code miente. La pregunta correcta
no es "¿cachea páginas privadas?" sino "¿la respuesta — incluso de
error — contiene datos de sesión y es cacheable?".

**Por qué es calibre:** es una variante 2025 de la clase que ya casi
cobramos en linktr.ee (allí el edge no cacheaba nada: LEAK-NO-CACHE
fue el veredicto honesto). Con este lente el motor pregunta más.

**Integración propuesta (dinámica, sobre cache_semantic):**
- Nuevo escenario: enviar disfraz de extensión, leer STATUS + BODY.
  Oráculo: body contiene marcadores de datos de cuenta (email, nombre,
  tokens) con status 404/4xx → STATUS-LIE-DETECTED.
- Segundo paso (el que paga): esperar/forzar cache HIT de la URL
  disfrazada y verificar como usuario B distinto → cross-user leak
  real. Presupuesto declarado, read-only, cuentas ninja propias.
- Escalera honesta: STATUS-LIE (señal) → WCD-404-LEAK (cache HIT
  cross-user) → impacto PII. Sin HIT: LEAK-NO-CACHE honesto, igual que
  el test de linktr.ee.

---

## Contexto de mercado (verificado 05/10/2026)

- Patchstack 2025: 7.966 vulnerabilidades nuevas en WP; 33% de plugins
  vulnerables sin fix. XSS = 47,7% del volumen pero severidad baja;
  lo que paga es lo de siempre: RCE, Object Injection, PrivEsc, BAC
  sobre secretos.
- WordPress Core 7.0.4 parcheó la familia Imagick: los plugins que
  duplican el patrón (procesan media por su cuenta) quedaron expuestos
  a la misma clase. Corpus de 3.260 plugins ≥5k installs = superficie
  real para MAGIC-CONFUSION.
- USENIX Sec'25 (Zhang et al.): minería precisa de gadget chains por
  taint tracking a nivel de llamada — metodología aplicable al
  POP-CANDIDATE de POI-REACH.

## NOTA DE CAZA (05/10/2026, primera corrida LestGo con v0.96.0)

Calibración sobre contact-form-entries 1.4.7 (CVE-2026-2599): el
motor NO dispara (poi=0/0/0) porque el flujo real del CVE es
SEGUNDO ORDEN: el payload serializado entra por el formulario, se
almacena en DB, y el unserialize ocurre al leer la entrada
(download_csv -> maybe_unserialize SIN allowed_classes, alcanzable
sin login vía vx_crm_key en $_GET, lineas 76-83 y 3017).
TAINT-TRACE level-1 no modela ida-vuelta por DB. Gap honesto
documentado: la clase POI-REACH hoy caza unserialize DIRECTO
(input del usuario al sink sin persistencia). Extension futura:
taint de segunda orden (source = handler que guarda, sink =
unserialize de lectura DB). No es falso negativo del corpus:
el caso de prueba cubre el flujo directo, como fue diseñado.

## ESTADO DE INTEGRACIÓN (05/10/2026): COMPLETO v0.96.0

Las TRES clases fueron integradas y certificadas (139/139 PASS):
POI-REACH (core/poi_reach.py, casos RC-000261..263), MAGIC-CONFUSION
(core/magic_confusion.py, RC-000264..265) y WCD-404-LEAK
(labs/wcd404_lab.py + core/wcd404_probe.py, RC-000266..268).
Ver CHANGELOG v0.96.0. Lo que sigue (caza con blancos reales)
requiere 'LestGo'.

## Orden de integración propuesto (histórico)

1. POI-REACH (paga ya, motor casi listo, solo faltan gates + gadgets)
2. MAGIC-CONFUSION (clase fresca, sin competencia, RCE)
3. WCD-404-LEAK (upgrade barato de cache_semantic, cierra la pregunta
   que linktr.ee dejó a medias)

Ninguna acción en vivo sin "LestGo". Todo nace en LAB con corpus.

---

## Evaluado y descartado: HTTP/2 Bomb (CVE-2026-49975)

Bomb HPACK + retención Slowloris contra nginx ≤1.29.7, Apache httpd
≤2.4.67, IIS, Envoy, Pingora. DoS por amplificación de memoria.

**Por qué NO entra al motor:** es clase de disponibilidad. Los
programas de bounty excluyen DoS del scope (probarlo = tumbar el
servicio de un tercero: destructivo, contra nuestras reglas read-only).
No paga, no se reporta, no se ejecuta en vivo jamás.

**Valor residual:** la mecánica (amplificación HPACK en la traducción
edge→origin) confirma que nuestra h2_lab/h2_probe modela la capa
correcta. Si algún día un vendor paga por DoS con autorización
escrita, el lab ya sabe hablar H2 real. Nada más que hacer aquí.

**Decisión:** documentado, descartado. El foco sigue en POI-REACH →
MAGIC-CONFUSION → WCD-404-LEAK (las clases que pagan).
