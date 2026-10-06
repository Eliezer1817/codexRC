# CodexRC — Documentación Maestra
### De punta a punta: qué es, qué hace, cómo está armado y en qué versión está hoy

> Generado el 06/10/2026 a partir del código fuente real del repositorio
> (README.md, ARCHITECTURE.md, AGENTS.md, CHANGELOG.md de 2222 líneas y
> los 102 módulos de `core/`). No contiene información inventada: cada
> dato sale de un archivo existente, citado donde corresponde.

---

## 1. Qué es CodexRC, en una frase

**Motor de auditoría y caza de vulnerabilidades web**, con backend local,
evidencia determinista, veredictos falsables, y campañas masivas sobre
plugins de WordPress y blancos autorizados. No es un escáner que dice
"podría ser vulnerable": construye una cadena de evidencia
(`SOURCE → FLOW → AUTH → SANITIZATION → SINK → CORRELATION`) evaluada por
"abogados" deterministas (nunca una IA que opina), y solo reporta cuando
esa cadena está completa y es reproducible.

### Las 5 reglas de oro (filosofía, de `README.md`)

1. **Sin evidencia no hay hallazgo.** Toda cadena se evalúa, nunca se
   infiere por intuición.
2. **Mejor 4 hallazgos que ejecutan de verdad que 20 que solo se
   reflejan.** VERITAS re-verifica cada candidato en navegador real con
   un canario inerte antes de sellarlo.
3. **El ruido muere en el motor, no a mano.** Guardas semánticas,
   refutación por dominancia y corpus de regresión eliminan falsos
   positivos solos, con registro del porqué.
4. **La tolerancia del edge no es vulnerabilidad.** Solo el *mismatch*
   observable edge/origin escala; la escalera de impacto nunca se salta
   (DETECTED sin reproducción no avanza).
5. **La caza respeta el blanco.** Sondas read-only A→B, canarios
   inertes, jitter, presupuestos de requests declarados por módulo, y
   parada al primer impacto confirmado. En vivo jamás se envenena la
   respuesta de un usuario tercero.

---

## 2. Arquitectura general (6 subsistemas)

Fuente: `ARCHITECTURE.md`. El layout físico es:

```
backend/app.py     Único entrypoint HTTP (Flask): rutas /api/*, jobs,
                    watchdog, auth de Arsenal.
core/*.py           102 módulos, una responsabilidad cada uno (sin
                    subcarpetas: organización por archivo plano).
frontend/*.html     3 UIs autocontenidas (index, hunter, arsenal).
hechos/             Memoria de "ya auditado" — NUNCA se vacía o se
                    re-audita todo desde cero por error.
reports/            Informes JSON/PDF/TXT generados por job.
docs/               Especificaciones y esta documentación.
```

### 2.1 Motor de caza (corazón)
`hunter.py` es una **fachada** que re-exporta Spider, DeepHunter,
XSSHunter, BlindXSS y XSSPro desde sus módulos `hunter_*.py`. Los
consumidores (backend, CLI, async_lane) solo conocen la fachada, nunca
los módulos internos directamente. `brain.py`, `self_tune.py` y
`pipeline.py` orquestan decisiones.

### 2.2 Autenticación (`auth.py`, ~60KB)
Matrix universal: combina bases × rutas × payloads. La sesión heredada
se guarda por origen (nunca pisa sesiones de otro blanco). Incluye
`ghostgate.py` (evasión de Cloudflare vía navegador real, nombre fijado
por el operador) y `waf_guard.py` (jitter + cooldown con memoria
persistente).

### 2.3 Verificación anti-falsos-positivos (lo que hace confiable al motor)
Cadena de evidencia en orden:
- `taint_trace.py` — TAINT-TRACE: sigue fuente→sink intra-archivo.
- `gates_audit.py` — GATES-AUDIT: dictamina si un handler AJAX/REST está
  protegido (nonce/capability).
- `evidence.py` — EVIDENCE-CHAIN: arma la cadena completa y la evalúa
  con jueces deterministas (nunca un LLM).
- `fp_autoclose.py` — cierra falsos positivos ya conocidos.
- `pattern_match.py` — CVE-MATCH con patrones ponderados contra una
  baseline histórica.
- `veritas.py` — navegador real contra falsos positivos, con
  degradación elegante si no hay Chromium.
- `observe.py` / `regress.py` — CODEX-OBSERVE / CODEX-REGRESS: el
  corpus de regresión (141 casos a la fecha de este documento).
- `escalada.py` — sigue el hallazgo crítico con 4 pasos automáticos,
  solo sobre piezas verificadas.

### 2.4 Caza masiva (plugins de WordPress)
`wide_corpus.py` arma el universo (todo plugin de wordpress.org con
≥5.000 instalaciones). `hunt_wide.py` es el runner incremental
(crash-safe, nunca re-audita lo ya hecho). `diff_hunt.py` audita solo
código nuevo entre versiones. `plugin_batch.py`, `retro_hunt.py`,
`vendor_farm.py` y `cve_matcher.py` completan la batería. `dossier_hunt.py`
es el driver más reciente (Q4-2026), enfocado en las clases nuevas
POI-REACH y MAGIC-CONFUSION.

### 2.5 Ingeniería inversa (binarios/APKs)
`bin_audit.py` (secretos en ELF), `re_engine.py` (parseo puro Python de
DEX/JAR/ELF) y `decompile.py` (bytecode DEX → pseudocódigo). Todo en
Python puro para correr sin compilar en entornos como Termux/armv7l.

### 2.6 Backend + UI
Rutas Flask con jobs bajo lock, watchdog de procesos zombie
(`zombies.py`). Seguridad: bind solo a loopback por defecto, logs sin
secretos (passwords/tokens/cookies nunca se registran), Arsenal con
modo EXTREMO que exige contraseña y token de desbloqueo temporal.

---

## 3. La escalera cero-falsos-positivos (cómo se decide un veredicto)

Principio transversal a todos los módulos nuevos (v0.85+): **cada
peldaño exige el anterior**, nunca se salta un escalón. Ejemplo genérico
de la familia desync/HTTP:

```
BENIGN  →  X-DETECTED  →  X-DESYNC  →  X-STATE-EFFECT  →  💥 SECURITY-IMPACT-DEMO
```

Y para Object Injection (`poi_reach.py`):
```
POI-DETECTED (unserialize con taint sin sanitizar)
   → POI-UNAUTH (el sink vive en superficie anónima)
      → POI-CHAIN (hay gadget con método mágico alcanzable)
         → POI-REACH (💥 candidato reportable)
```
Sin alcance anónimo, el veredicto honesto queda en **POI-AUTH**: es una
pista, no un hallazgo reportable.

Solo dos símbolos están reservados para parar todo y avisar al
operador: **💥** (hallazgo explotable real) y 🚨/😱 (hallazgo crítico).
Todo lo demás es ruido que el motor filtra solo.

---

## 4. Línea de tiempo de versiones (resumen)

CodexRC lleva **78 versiones documentadas** en el CHANGELOG (desde
v0.40 "Verificación del sistema" hasta v0.96.1). El detalle completo,
versión por versión, está en
[`version_timeline.md`](./version_timeline.md) (generado automáticamente
del CHANGELOG real). Hitos mayores:

| Versión | Hito |
|---|---|
| v0.40 – v0.53 | Cimientos: verificación, vendor-farm, plugin-batch, gates-audit, diff-hunt, evidence-chain, VDP-1300, UI-Renaissance |
| v0.57.x | AUTH matrix universal, auditoría de seguridad propia, triaje masivo de falsos positivos (BAC/SQLi) |
| v0.62.x | REVERSE-WEB, MULTI-IA (coordinación entre operadores), VDP-FRESH watcher cada 6h |
| v0.67 – v0.81 | BAC-PROOF (IDOR dinámico en WP-LAB), ADAPTIVE-HUNT (capa epistémica), ARSENAL de 2 niveles |
| v0.82 – v0.84 | Grafo de experimentos, selección por EDV, correlación cross-layer |
| v0.85 – v0.96.1 | **La corona 👑**: cadena completa de detección de desync HTTP (CL.0 → H2 → multi-conexión → cross-request → reproducción → impacto → FP-elimination → evidence package), integración al Hunter (`crown_chain.py`), y el dossier Q4-2026 (POI-REACH, MAGIC-CONFUSION) |

### 4.1 La corona (v0.85 → v0.96.1), paso a paso
Esta es la cadena de detección de HTTP request smuggling / desync que
se construyó módulo por módulo, cada uno con su propio corpus de
regresión y validación en LAB antes de integrarse:

1. **v0.85 PIPE-CROSS** — nodo cross_layer en el pipeline de escaneo.
2. **v0.86 WCD-CACHE-KEY** — envenenamiento de caché vía clave mal
   normalizada.
3. **v0.87 CL.0-SINGLE-TIER** — smuggling de un solo salto.
4. **v0.88 H2-TRANSLATION** — edge HTTP/2 real traducido a H1 interno;
   oráculo de atribución por stream.
5. **v0.89 MULTI-CONNECTION** — una conexión envenena el pool y otra
   (TCP distinto) hereda el eco.
6. **v0.90 CROSS-REQUEST CORRELATION** — dos smuggles en la misma
   conexión, desplazamiento `k` medible y consistente.
7. **v0.91 REPRODUCTION ENGINE** — exige firma y `k` idénticos en dos
   pases independientes (A y B) antes de llamarlo reproducible.
8. **v0.92 IMPACT CORRELATION** — ¿el desync daña a un usuario *distinto*
   del atacante? Recurso simulado, atribución ALIGNED /
   SMUGGLED-PROTECTED / MISPAIRED-BENIGN.
9. **v0.93 FP-ELIMINATION** — batería de 4 cebos que nunca deben
   reportar + control positivo obligatorio.
10. **v0.94 EVIDENCE PACKAGE** — paquete falsable con hash SHA-256
    canónico, comandos de reproducción y límites declarados.
11. **v0.95 INTEGRACIÓN AL HUNTER** — `crown_chain.py` orquesta los 5
    peldaños (DETECTION → REPRODUCTION → STATE-EFFECT →
    CROSS-CONNECTION → SECURITY IMPACT) sin tocar los módulos
    originales.
12. **v0.96.0 / v0.96.1 DOSSIER Q4-2026** — tres clases nuevas:
    POI-REACH (Object Injection con alcance), MAGIC-CONFUSION
    (confusión de extensión/contenido hacia Imagick), y el
    blindaje que cerró 2 falsos positivos reales encontrados en el
    primer barrido en vivo contra `weforms`.

---

## 5. Catálogo completo de módulos

Los 102 archivos de `core/` están indexados con su versión de origen y
descripción real (extraída del encabezado de cada archivo) en
**[`modulos_index.csv`](./modulos_index.csv)** — abrilo en Excel/Sheets
para filtrar por versión o buscar por palabra clave.

Agrupados por función (ver sección 2 para el detalle narrativo):

- **Detección de desync/HTTP**: `cl0_probe`, `h2_probe`, `mc_probe`,
  `crc_probe`, `edgesync`, `wcd_bait`, `wcd404_probe`, `cache_*` (bait,
  baseline, controls, correlation, fingerprint, semantic).
- **Reproducción/impacto**: `repro_engine`, `race_proof`, `race_trace`,
  `chain`, `crown_chain`, `impact_probe`, `state_correlation`.
- **Anti-FP / evidencia**: `fp_elimination`, `fp_autoclose`, `fp_memory`,
  `evidence`, `evidence_package`, `veritas`, `ghostgate`, `waf_guard`.
- **Autenticación / IDOR / BAC**: `auth`, `bac_proof`, `gates_audit`,
  `poi_reach`, `normalization_audit`.
- **Inyección**: `sqli_bait`, `ssti_bait`, `graphql_bait`,
  `magic_confusion`.
- **XSS**: `hunter_xss`, `hunter_xsspro`, `hunter_blind`, `cspt_scan`.
- **Caza masiva WordPress**: `wide_corpus`, `hunt_wide`, `diff_hunt`,
  `plugin_batch`, `dossier_hunt`, `retro_hunt`, `vendor_farm`,
  `cve_matcher`.
- **Ingeniería inversa**: `bin_audit`, `re_engine`, `decompile`.
- **Investigación/estrategia**: `research_memory`, `experiment_catalog`,
  `experiment_graph`, `experiment_selector`, `hypothesis_graph`,
  `adaptive_hunt`, `self_tune`, `brain`.
- **Infraestructura/soporte**: `pipeline`, `zombies`, `cfg`,
  `connection_state`, `tech_detect`, `recon`, `taint_trace`,
  `report_export`, `vision_gate`, `semantic_*`.

---

## 6. Estado actual del motor (a la fecha de este documento)

- **Versión**: v0.96.1 "BLINDAJE POI-REACH".
- **Corpus de regresión**: 141/141 casos, 0 fallos (certificado hoy).
- **Auditoría de 588 plugins**: ejecutada completa (0 💥 confirmados,
  6 candidatos POI-AUTH detectados). *Nota de transparencia: el JSON
  detallado con esos 6 candidatos se perdió en una limpieza de archivos
  temporales; el motor que los generó sigue intacto y puede re-correr
  el barrido cuando el operador dé la orden "LestGo".*
- **Lo que el motor NO hace todavía de forma automática**: no dispara
  ataques de IDOR/lógica de negocio por sí solo. Hoy detecta candidatos
  (Fase 1: lectura estática de endpoints vía `gates_audit`/`poi_reach`)
  y valida BAC/IDOR dinámicamente contra un WP-LAB local
  (`bac_proof.py`, con usuarios Admin/Suscriptor/Anónimo), pero no
  arma automáticamente los payloads de lógica financiera (montos
  negativos, decimales truncados, sobreescritura de estado de pago).
  Esa pieza (el "Destructor de Lógica Financiera") es la que se definió
  construir a continuación.

---

## 7. Roadmap inmediato (decidido en esta conversación)

Objetivo: hacer que CodexRC sea mejor que Burp Suite Pro en control de
acceso (IDOR) y lógica de negocio, su único punto débil real.

1. Ya tenemos: extracción estática de endpoints
   (`gates_audit`/`poi_reach`) + disparo multi-rol dinámico
   (`bac_proof.py`, Admin/Suscriptor/Anónimo contra WP-LAB).
2. Falta: módulo de **inferencia de parámetros** (leer qué variables
   lee cada handler: `$_POST['ticket_id']`, `$_GET['user_id']`, etc.) y
   autocompletarlas con valores de prueba.
3. Falta: **Destructor de Lógica Financiera** — detectar variables tipo
   `price`/`amount`/`qty`/`discount`/`total` y aplicarles la batería de
   ataques (negativos, decimales truncados, arrays, sobreescritura de
   estado `status=paid`).

---

## 8. Documentos relacionados

- [`README.md`](../README.md) — filosofía, instalación, uso rápido.
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) — mapa técnico para editar sin romper.
- [`AGENTS.md`](../AGENTS.md) — manual operativo para IAs que operan el repo.
- [`CHANGELOG.md`](../CHANGELOG.md) — historial completo, versión por versión (2222 líneas).
- [`version_timeline.md`](./version_timeline.md) — timeline condensado de las 78 versiones.
- [`modulos_index.csv`](./modulos_index.csv) — índice de los 102 módulos (abrir en Excel).
- [`AUDITORIA_FALSOS_POSITIVOS.md`](./AUDITORIA_FALSOS_POSITIVOS.md) — metodología anti-FP detallada.
- [`DOSSIER_INVESTIGACION_2026Q4.md`](./DOSSIER_INVESTIGACION_2026Q4.md) — investigación de las clases nuevas del Q4 2026.
