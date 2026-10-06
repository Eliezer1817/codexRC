# CodexRC

![CodexRC](assets/banner.jpg)

**Motor de auditoría y caza de vulnerabilidades web** con backend local, evidencia determinista, veredictos falsables y campañas masivas sobre plugins WordPress y blancos autorizados.

> ⚠️ **Solo usar en objetivos con autorización explícita de auditoría.**

> 🧠 **¿Operás con una IA?** Leé primero [AGENTS.md](AGENTS.md): manual operativo, reglas de oro y catálogo de veredictos. La arquitectura interna está en [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Índice

- [Filosofía](#filosofía)
- [Condiciones de uso](#condiciones-de-uso)
- [Arquitectura general](#arquitectura-general)
- [Pipeline de evidencia](#pipeline-de-evidencia)
- [Cadena desync HTTP](#cadena-desync-http)
- [Mapa de módulos](#mapa-de-módulos)
- [Modos de caza](#modos-de-caza)
- [Escalas de veredictos](#escalas-de-veredictos)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Disciplina de calidad (CODEX-REGRESS)](#disciplina-de-calidad-codex-regress)
- [Hitos](#hitos)
- [Documentación](#documentación)
- [Multi-IA / multi-operador](#multi-ia--multi-operador)
- [Créditos](#créditos)

---

## Filosofía

CodexRC no pregunta *"¿podría ser vulnerable?"*. Pregunta
**"¿qué evidencia tengo para afirmarlo?"**.

1. **Sin evidencia no hay hallazgo.** Cada finding construye una cadena
   (SOURCE → FLOW → AUTH → SANITIZATION → SINK → CORRELATION) evaluada
   por abogados deterministas, nunca por intuición.
2. **Mejor 4 hallazgos que ejecutan de verdad que 20 que solo se
   reflejan.** VERITAS re-verifica cada candidato en navegador real con
   un canario inerte antes de sellarlo.
3. **El ruido muere en el motor, no a mano.** Guardas semánticas,
   refutación por dominancia y corpus de regresión: los falsos
   positivos se eliminan solos y queda registro del porqué.
4. **La tolerancia del edge no es vulnerabilidad.** Solo el mismatch
   observable edge/origin escala, y la escalera de impacto nunca se
   salta: DETECTED sin reproducción no avanza.
5. **La caza respeta el blanco.** Sondas de lectura A→B, canarios
   inertes, jitter, presupuestos de requests declarados por módulo y
   stop al primer impacto confirmado. En vivo jamás se envenena la
   respuesta de un usuario de terceros.

---

## Condiciones de uso

- **Autorización primero.** Programas de bug bounty con alcance
  definido, laboratorios propios o blancos con permiso explícito.
  Auditar sistemas ajenos sin autorización es ilegal.
- **Proyecto en desarrollo activo.** Varias versiones por día; la
  interfaz cambia sin aviso. Revisar [CHANGELOG.md](CHANGELOG.md)
  antes de actualizar.
- **Arsenal restringido.** `frontend/arsenal.html` es sección interna
  del operador: contraseña con log de intentos, sesión de 30 minutos,
  modo LAB por defecto. El nivel EXTREMO exige confirmación escrita y
  sus condiciones no negocian: laboratorio propio o blanco
  autorizado, demostración mínima, sin dump masivo, sin persistencia,
  sin destructivos.
- **Sondas de lectura A→B.** Contraste de acceso con y sin sesión, sin
  alterar datos, sin payloads de exploit.
- **GHOSTGATE.** Si Cloudflare rebota la IP, la acción se delega a un
  navegador real con IP limpia; si el bloqueo persiste, el blanco se
  descarta. Ante CAPTCHA: frenar y descartar.
- **Límites del programa.** Rate limits por hora, scope del vendor y
  divulgación coordinada, siempre.

---

## Arquitectura general

```
                    ┌──────────────────────────────┐
                    │   Frontend (localhost)       │
                    │  index.html · hunter.html    │
                    │      arsenal.html 🔒          │
                    └──────────────┬───────────────┘
                                   │ /api/*
                    ┌──────────────▼───────────────┐
                    │   Backend Flask (backend/)   │
                    │  server 127.0.0.1 + token    │
                    └──────────────┬───────────────┘
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      ▼                            ▼                            ▼
  RECON / CERE              ANÁLISIS ESTÁTICO            CAZA ACTIVA
  recon · tech_detect       cfg (dominancia)             hunter_* (spider,
  brain (priorización)      ssa (def-use)                deep, xss, xsspro, blind)
  auth (login auto)         taint_trace · gates_audit    sqli_bait · cov_bait
  ghostgate · waf_guard     pattern_match · cve_matcher   path/ssti/cache/graphql
  veritas (verificación)    bin_audit · re_engine         escalada · veritas
  async_lane (SLIPSTREAM)   decompile · deep_scan
      └────────────┬───────────────────┴──────────────────┬────────┘
                   ▼                                      ▼
            EVIDENCE-CHAIN (evidence.py + semantic_core)
            cadena + FISCAL / DEFENSA / JUEZ deterministas
                   ▼
            VEREDICTO · CODEX-OBSERVE · informes TXT/JSON/PDF
```

- **Backend:** `backend/app.py`, Flask restringido a `127.0.0.1` con
  token; toda la lógica en `core/`.
- **Frontend:** dashboards de presentación sobre `/api/*`.
  `arsenal.html` es la sección restringida del operador.
- **Termux:** arranca el backend en `localhost`; compatible con
  `armv7l` (32 bits), Python puro (bypass de Cloudflare vía
  `cloudscraper`, sin binarios precompilados).
- **Logs:** cada escaneo en `reports/codexrc_<id>.json`; eventos en
  `reports/backend.log` (JSONL, rotación automática, `request_id`).

---

## Pipeline de evidencia

Cada hallazgo atraviesa capas de evidencia cada vez más semántica:

```
 CONTROL FLOW                 DATA FLOW
 CFG (core/cfg)               SSA-lite (core/ssa)
 dominancia · reachability    versiones · lineage · def-use
      │                            │
      └────────────┬───────────────┘
                   ▼
            TAINT-TRACE (fuente → sink)
                   ▼
      EVIDENCE-CHAIN (core/evidence)
      FISCAL prueba · DEFENSA refuta · JUEZ dicta
                   ▼
            VERITAS (verificación en navegador real)
```

- **SEMANTIC CORE** (`core/semantic_core.py`): identidad canónica de
  archivos + testigo de hash. El basename NO es identidad: resolución
  ambigua o hash distinto = `INTEGRITY`, y un veredicto alto jamás se
  sostiene sobre el archivo equivocado.
- **CFG + dominancia** (`core/cfg.py`): un gate "cerca" del handler
  solo cuenta si domina el flujo (RC-000132).
- **SSA-lite** (`core/ssa.py`): grafo de versiones def-use por
  función. El sink recibe la cadena completa (`$sql ← COPY ← $term ←
  SOURCE @L11`) y `def_use_proof()` entrega prueba estructurada. SSA
  nunca dictamina vulnerabilidad: refutar exige que la asignación
  limpia **domine el sink** (RC-000142).
- **EVIDENCE-CHAIN** (`core/evidence.py`): la cadena completa + tres
  abogados. FISCAL debe PROBAR cada requisito (con `DEF_USE_COMPLETE`,
  no por proximidad); DEFENSA busca refutaciones (gate protegido,
  sanitizador, prepare, admin-only, reasignación limpia); el JUEZ
  dicta con reglas fijas. Los proofs con ancestros desconocidos jamás
  sostienen `DEMOSTRADO-ESTATICO`.

---

## Cadena desync HTTP

El roadmap desync (22 etapas, v0.86 → v0.95) está completo y
montado en el Hunter. Un hallazgo de desync escala por una escalera
que **nunca se salta**:

```
 rung 1  DETECTION          cl0 + h2 + mc + crc (4 probes
                           independientes, cero-FP cada uno)
 rung 2  REPRODUCIBLE      2 genealogías independientes ×
                           pase A/B con firma idéntica
 rung 3  STATE-EFFECT      firma k medible y consistente
 rung 4  CROSS-CONNECTION  contaminación entre conexiones
                           PROPIAS del atacante
 rung 5  SECURITY IMPACT   daño a un usuario DISTINTO
                           (solo LAB: en vivo jamás se
                           envenena a un tercero)
```

- **Cada probe tiene su propio oráculo**: CL.0 por timing
  diferencial, H2 por atribución de stream, multi-conn por herencia de
  pool LIFO, cross-request por permutación (el eco propio desplazado
  exactamente por k ecos del smuggle).
- **El disparo único no escala.** Un flaky es NON-REPRODUCIBLE y no
  avanza. Dos genealogías × pase A/B con la misma firma k son
  obligatorias.
- **FP-ELIMINATION**: batería de 4 escenarios cebo que JAMÁS reportan
  (quiet_drain, benign pipelining, pool shift, flaky) + control
  positivo obligatorio (pool_swap DEBE reportar; sin él la batería es
  vacua). Veredicto: FP-ELIMINATED.
- **EVIDENCE PACKAGE**: paquete falsable de la cadena completa con
  comandos de reproducción exactos, hash sha256 del payload canónico
  (detecta tampering) y límites declarados (read-only, modo lab,
  recurso protegido simulado, presupuestos).
- **Integración al Hunter**: `core/crown_chain.py` orquesta la
  escalera con los motores del roadmap sin tocar ningún módulo; la
  fachada `core/hunter.py` la exporta como `CrownChain`. Modo lab:
  `CHAIN-COMPLETE-LAB`. Modo live: read-only, presupuesto 60 reqs,
  tope honesto `CROSS-CONNECTION-DEMO`.
- Reglas de oro del desync: nunca auditar una instancia de lab que
  uno no spawnó (puerto ocupado antes del spawn = UNSTABLE); no
  paralelizar auditorías desync; la tolerancia del edge no es
  vulnerabilidad.

---

## Mapa de módulos

### Reconocimiento e infraestructura

| Módulo | Función |
|---|---|
| `recon` · `tech_detect` | reconocimiento y fingerprint tecnológico |
| `auth` | login automático por formulario HTML o API JSON (Angular/React), autodetección de endpoint, CSRF, Origin/Referer |
| `brain` | CEREBRO: fingerprint del blanco y priorización de la cola con presupuesto dinámico |
| `ghostgate` | GHOSTGATE: delega a navegador real (IP limpia) cuando Cloudflare rebota la IP |
| `waf_guard` | GHOST-SHIELD: jitter por sonda, clasificador de bloqueo, cooldown exponencial, memoria de IPs quemadas |
| `async_lane` | SLIPSTREAM: carril asíncrono (64 sondas en vuelo, ~219/s) con fallback a hilos |
| `pipeline` | orquestación de escaneos completos |
| `self_tune` | autoajuste persistente del presupuesto de sondas |

### Análisis estático (PHP y binarios)

| Módulo | Función |
|---|---|
| `cfg` | CFG con dominancia: el control de acceso solo cuenta si domina el flujo |
| `ssa` | SSA-lite: versiones def-use, cadenas completas y `def_use_proof` |
| `taint_trace` | TAINT-TRACE: flujo fuente → sink (SQLi ciego, XSS, unserialize, LFI, RCE, SSRF) |
| `gates_audit` | mapea handlers ajax/REST a su callback y dictamina protección |
| `pattern_match` | CVE-MATCH: patrones ponderados de familias históricas (BAC ajax, type juggling, IPN downgrade, SSRF, upload, PrivEsc) |
| `cve_matcher` · `diff_hunt` | cruce con CVEs conocidos y caza de código NUEVO (updates ≤ 90 días) |
| `bin_audit` | BIN-AUDIT: secrets hardcodeados, endpoints internos, imports peligrosos (ELF real) |
| `re_engine` | REVERSE: parse de DEX/class/ELF, ofuscación ProGuard, entropía |
| `decompile` | DECOMPILE: bytecode DEX → pseudocódigo legible |
| `deep_scan` · `zombies` | escaneo profundo y detección de código muerto/heredado |
| `poi_reach` | POI-REACH: Object Injection con alcance (GATES) y gadget chain POP-CANDIDATE en el mismo plugin |
| `magic_confusion` | MAGIC-CONFUSION: extensión vs contenido (magic bytes) en rutas de upload hacia Imagick, sin gate de contenido |

### Superficie HTTP universal (ROUTER/ENDPOINT GRAPH v0.98.0)

| Módulo | Función |
|---|---|
| `handler_resolver` | resuelve el cuerpo REAL de method/function/closure contando llaves (mismo criterio que `_line_in_handler`) |
| `router_graph` | grafo ROUTER→ROUTE→HANDLER→PARAMETER/MIDDLEWARE con evidencia archivo+línea |
| `universal_endpoint` | descubre y normaliza rutas de CUALQUIER router (WP hooks, Slim-like, PSR-7 custom, array router) a un modelo común; ZERO-FP: exige evidencia estructural de path, nunca un nombre de método aislado |

Nace de una brecha real: GATES-AUDIT solo entiende hooks clásicos de
WP, así que un router custom (caso Amelia Booking, v0.97.0) dejaba su
API invisible para TAINT/AUTHZ/FIN-LOGIC. Este motor NO reemplaza
GATES-AUDIT ni duplica AUTHZ-PROOF/FIN-LOGIC: los adaptadores
`to_gates_handlers()`/`to_fin_param_sources()` entregan la MISMA
superficie con la MISMA interfaz que ya consumen, venga de donde venga
el router. `ENDPOINT-DISCOVERED` no es `VULNERABILITY`; `HANDLER-RESOLVED`
no es `AUTHZ-PROTECTED`. Validado con `tests/universal_endpoint_regress.py`
(14/14 PASS). Lab: `labs/router_lab.py`.

### Lógica de negocio (FIN-LOGIC v2)

| Módulo | Función |
|---|---|
| `fin_param_graph` | grafo relacional de parámetros (qué campos se leen juntos: price, qty, discount, total...) |
| `fin_invariants` | infiere invariantes aritméticas del código (`total = price*qty - discount`) para violarlas a propósito |
| `fin_mutation_planner` | planificador de mutaciones L0 (campo único) / L1 (combinación) / L2 (ruptura de invariante) |
| `fin_state_engine` | snapshot + diff de estado de un recurso antes/después de una acción |
| `fin_state_transitions` | grafo estático de transiciones de estado legítimas vs forzadas (pending→paid→refunded) |
| `fin_replay_engine` | detecta falta de idempotencia (repetir una acción no debe repetir el beneficio) |
| `fin_race_engine` | condiciones de carrera controladas (doble canje del mismo cupón en paralelo) |
| `fin_logic_probe` | orquesta L0 contra un lab/blanco y dictamina FIN-IMPACT-DEMO |
| `fin_fp_memory` | puente a `fp_memory`: la memoria de FP también aprende huellas de lógica de negocio |

Validado con `tests/fin_logic_regress.py` (corpus propio: 13/13 PASS,
nunca `safe → IMPACT`). Lab: `labs/fin_logic_lab.py`.

### Razonamiento de evidencia

| Módulo | Función |
|---|---|
| `semantic_core` | identidad canónica + integridad de archivos (RC-000127) |
| `evidence` | EVIDENCE-CHAIN + FISCAL/DEFENSA/JUEZ + historial de veredictos |
| `observe` | CODEX-OBSERVE: reflexión sobre puntos ciegos (qué NO se analizó) |
| `escalada` | tras hallazgo crítico: VERITAS dirigido, techo de impacto, kit PoC local |
| `veritas` | verificación con navegador real (canario inerte, solo lectura) |
| `fp_autoclose` | FP-AUTO-CLOSE: cierra familias de falsos positivos aprendidas |
| `experiment_graph` · `desync_hunt` | EDV: hipótesis, contratos pre-registrados, genealogías y transiciones de candidato sobre el grafo de experimentos |

### Desync HTTP

| Módulo | Función |
|---|---|
| `cl0_probe` | CL.0-SINGLE-TIER: desync de una capa por POST `Content-Length: 0` + prefijo smuggleado, oráculo de timing diferencial |
| `h2_probe` | H2-TRANSLATION: edge HTTP/2 real (prefacio + HPACK + frames) traduce a origin H1; oráculo de atribución por stream |
| `mc_probe` | MULTI-CONNECTION: oráculo de herencia por pool LIFO de conexiones origin; la conexión A envenena y la B hereda |
| `crc_probe` | CROSS-REQUEST CORRELATION: oráculo de permutación; el desplazamiento k del eco propio es medible y consistente |
| `repro_engine` | REPRODUCTION: 2 genealogías independientes × pase A/B; REPRODUCIBLE exige firma y k idénticos; flaky = NON-REPRODUCIBLE |
| `impact_probe` | IMPACT CORRELATION: daño a un usuario DISTINTO (pool LIFO + recurso protegido simulado); SECURITY-IMPACT-DEMO exige 2/2 + control limpio |
| `fp_elimination` | FP-ELIMINATION: tabla de clases de señal + batería de cebos que jamás reportan + control positivo obligatorio |
| `evidence_package` | EVIDENCE PACKAGE: cadena completa falsable, comandos de reproducción, hash canónico, límites declarados |
| `crown_chain` | CROWN CHAIN: orquestador de la escalera completa (detección → repro → state-effect → cross-connection), exportado por la fachada del Hunter |
| `wcd_bait` · `cache_*` | WCD-CACHE-KEY: Web Cache Deception con contratos, escalera BENIGN → LEAK-NO-CACHE → WCD-CACHE → WCD-DEMO |
| `wcd404_probe` | WCD-404-LEAK: el status code miente (4xx con cuerpo de datos de cuenta); cache HIT cross-user en ≤8 reqs read-only; sin HIT = LEAK-NO-CACHE honesto |

### Caza activa (Hunter)

| Módulo | Función |
|---|---|
| `hunter` (fachada) · `hunter_base` · `hunter_spider` · `hunter_deep` · `hunter_xss` · `hunter_xsspro` · `hunter_blind` | spider, corpus XSS, DeepHunter (BAC/IDOR/CSP/superficie), batería XSS-PRO, y fachada que exporta `CrownChain` |
| `sqli_bait` | SQLI-BAIT: 4 niveles (error-based con fingerprint, boolean por diferencial, time-based anti-jitter, stacked) |
| `cov_bait` | COV-BAIT: caza guiada por cobertura de código vía CDP con mutación con feedback |
| `path_bait` · `ssti_bait` · `cache_bait` · `graphql_bait` · `stealth_bait` | LFI con wrappers, SSTI, Web Cache Deception, GraphQL, sondas postMessage/CSP |
| `chain` | encadenamiento determinista (XSS+CSP débil, SQLi+panel, IDOR masivo) |

### Campañas y corpus

| Módulo | Función |
|---|---|
| `wide_corpus` · `hunt_wide` | corpus de TODOS los plugins wordpress.org ≥5k installs; cola priorizada: VDP-FRESH → pagables → banda 5k-50k → resto |
| `retro_hunt` | RETRO-HUNT: código PRE-COOLDOWN (plugins congelados antes del gate de IA de WP.org), full-code por bounty |
| `plugin_batch` | PLUGIN-BATCH: caza por slugs, un comando |
| `vendor_farm` | VENDOR-FARM: caza por vendor completo |
| `vdp_fresh` | VDP-FRESH: diff semanal del directorio VDP de Patchstack (GOLDEN LIST): altas, bounties nuevos y bajas |

### Reportes y entorno

| Módulo | Función |
|---|---|
| `report_export` | informes TXT/JSON/PDF: filtraciones arriba, hallazgos por severidad, sello verificado |
| `universal_engine` | UNIVERSAL-ENGINE: orquestador que aprende cómo está construida la app y adapta los analizadores; Ledger de Cobertura |
| `regress` | CODEX-REGRESS: corpus de regresión (ver abajo) |
| `wplab*` (WP-LAB) | laboratorio WordPress local (PHP 8.2 + SQLite) para verificación dinámica AUTH-DIFF |
| `ghosthook/` | colector de blind XSS gratuito para Cloudflare Workers + KV |

---

## Modos de caza

- **DIFF-HUNT** — solo el código NUEVO de cada plugin (≤ 90 días). La
  ventana real de ser primeros: el parche del vendor y el hardening
  reciente no cuentan como blanco.
- **WIDE-HUNT** — corpus completo ≥ 5k installs (3.260 plugins). Cola
  incremental y crash-safe; prioridad mid-band 5k-50k: medianos con
  menos blindaje y competencia que los top. `--dry-run` imprime la
  cola sin cazar.
- **RETRO-HUNT** — el código que nadie mira: plugins congelados antes
  del gate de IA de WP.org (junio 2026), auditoría full-code por
  bounty.
- **VDP-FRESH** — el corpus fresco automático: diff semanal del
  directorio VDP de Patchstack. Un VDP recién agregado se caza ya
  (etiqueta NUEVO-VDP, sin filtros), porque nadie lo revisó aún.
- **PLUGIN-BATCH / VENDOR-FARM** — caza dirigida por slugs o vendor
  completo.
- **PIPE-HUNT** — `waybackurls sitio.com | python3 hunt_pipe.py --xsspro
  --workers 8`: URLs por stdin desde cualquier herramienta.
- **CROWN CHAIN** — `python3 core/crown_chain.py --url blanco.com`:
  escalera desync completa en vivo (read-only); `--mode lab` ensambla
  el paquete de evidencia completo.

---

## Escalas de veredictos

**Hallazgos de código** (escala RacerD):

| Veredicto | Significado |
|---|---|
| `CONFIRMED` | prueba estática completa + dinámica reproducida |
| `DEMOSTRADO-ESTATICO` | prueba estática completa (FISCAL 4/4, INTEGRITY ok, proof def-use completo) |
| `PROBABLE` | flujo probado con alcance/dinámica/ancestros sin resolver |
| `CONTESTADO` | la defensa tiene refutación parcial |
| `DESCARTADO` | refutación fuerte (gate, sanitizador, prepare, admin-only, reasignación limpia) |

**Desync HTTP** (escalera por probe, nunca se salta):

| Veredicto | Significado |
|---|---|
| `BENIGN` / `UNSTABLE` / `UNKNOWN` | sin señal / no juzgable / sin reflejo suficiente: sin claim |
| `X-DETECTED` | tolerancia del edge observada (todavía no es vulnerabilidad) |
| `X-DESYNC` | mismatch observable edge/origin |
| `X-STATE-EFFECT` | efecto de estado en la conexión propia, con firma k |
| `REPRODUCIBLE` | 2 genealogías × pase A/B con firma y k idénticos; flaky = NON-REPRODUCIBLE |
| `CROSS-CONNECTION-DEMO` | contaminación entre conexiones propias (tope en vivo) |
| `SECURITY-IMPACT-DEMO` | daño a usuario distinto, 2/2 con control limpio (solo LAB) |
| `CHAIN-COMPLETE-LAB` / `PACKAGE-VALID` | cadena completa verificada y paquete falsable emitido |
| `FP-ELIMINATED` | batería de cebos sin reportes + control positivo activo |

Cada cadena expone **falsadores**: qué evidencia tumbaría el veredicto.

---

## Instalación

### Termux (Android, armv7l)

```bash
pkg update && pkg install python git
git clone https://github.com/Eliezer1817/CodexRC.git
cd CodexRC
pip install -r requirements.txt          # Python puro, apto 32 bits
python3 backend/app.py                   # servidor en 127.0.0.1
```

`auto_update.sh` mantiene el server vivo: instancia única por lock,
resurrección ante crash con volcado de diagnóstico, anti-cuelgue y
wake-lock (Ajustes → Apps → Termux → Batería → Sin restricciones).

### Linux / macOS

```bash
git clone https://github.com/Eliezer1817/CodexRC.git
cd CodexRC
pip install -r requirements.txt
python3 backend/app.py
```

Dashboards: `http://127.0.0.1:8000` (escaneo) y `frontend/hunter.html`
(caza). El Arsenal exige contraseña y registra cada intento.

---

## Uso rápido

```bash
# Auditoría de un plugin descargado (estático + cadena de evidencia)
python3 core/taint_trace.py ./plugin --top 20
python3 core/evidence.py ./plugin

# Cadena desync completa
python3 core/crown_chain.py --url https://blanco.com      # vivo, read-only
python3 core/crown_chain.py --mode lab                    # paquete completo
python3 core/repro_engine.py --url https://blanco.com     # reproducción A/B
python3 core/fp_elimination.py                            # batería de cebos

# Campañas sobre el corpus
python3 core/hunt_wide.py --dry-run          # ver la cola priorizada
python3 core/hunt_wide.py --workers 6        # cazar
python3 core/diff_hunt.py slug1 slug2        # solo código nuevo
python3 core/plugin_batch.py slug1 slug2 --vdp vdp_matches.json

# Corpus fresco (flujo semanal)
python3 core/vdp_fresh.py --snapshot         # línea base
python3 core/vdp_fresh.py --diff data/vdp_mapa.json   # -> vdp_nuevos.json

# Análisis binario / APK
python3 core/bin_audit.py ./sdk.zip
python3 core/re_engine.py ./app.apk
python3 core/decompile.py ./app.apk --all

# Caza de blanco autorizado (login + sesiones)
python3 core/pipeline.py https://blanco.com --user X --pass Y
```

La API local expone todo lo mismo en `/api/*` (catálogo en
`AGENTS.md`).

---

## Disciplina de calidad (CODEX-REGRESS)

Cada bug del motor se congela en un caso del corpus
`.codexrc/intelligence/regressions/corpus.jsonl` con repro y
expectativa; la suite corre en cada versión y 0 fallos es obligatorio:

```bash
python3 core/regress.py    # 131 casos, corrida fría ~7 min
```

El corpus usa caché intra-corpus con hash de código: corrida tibia
instantánea cuando nada cambió. Invariantes que protege, por ejemplo:
el 0-day real de RegistrationMagic (IPN downgrade) debe permanecer
vivo; las comparaciones flojas protegidas por gates deben morir
(RC-000135/136); la refutación SSA exige dominancia (RC-000142); la
resolución por basename jamás analiza el archivo equivocado
(RC-000127); la batería de cebos desync jamás reporta (RC-000254) y el
paquete de evidencia detecta tampering (RC-000257).

---

## Hitos

De lo más reciente a lo más antiguo. Detalle por versión en
[CHANGELOG.md](CHANGELOG.md).

- **v0.97.0 — BUSINESS LOGIC STATE ENGINE v2:** 10 fases nuevas
  (grafo de parámetros, invariantes, mutación L0/L1/L2, motor de
  estado, transiciones, replay, race, cadena de evidencia hermana,
  memoria FP). Corpus propio 13/13 PASS. Validado contra Amelia
  Booking ($1.400 bounty): 0 explotables, router custom fuera de la
  gramática actual de GATES-AUDIT (pendiente de extensión).
- **v0.95.0 — INTEGRACIÓN AL HUNTER:** la cadena desync completa
  orquestada por `crown_chain` y exportada desde la fachada del
  Hunter; rung de impacto limitado a lab en vivo. Corpus 131.
- **v0.94.0 — EVIDENCE PACKAGE:** paquete falsable de la cadena
  completa: comandos de reproducción, hash sha256 canónico que detecta
  tampering, límites declarados.
- **v0.93.0 — FP-ELIMINATION:** tabla de clases de señal + batería de
  4 cebos que jamás reportan + control positivo obligatorio.
- **v0.92.0 — IMPACT CORRELATION:** daño a usuario distinto demostrado
  en lab (pool LIFO + recurso protegido simulado), 2/2 con control
  limpio.
- **v0.91.0 — REPRODUCTION ENGINE:** 2 genealogías independientes ×
  pase A/B; el disparo único no escala.
- **v0.90.0 — CROSS-REQUEST CORRELATION:** oráculo de permutación con
  firma k medible.
- **v0.89.0 — MULTI-CONNECTION:** oráculo de herencia por pool LIFO;
  la conexión A envenena y la B hereda.
- **v0.88.0 — H2-TRANSLATION:** edge HTTP/2 real traduce a origin H1;
  oráculo de atribución por stream.
- **v0.87.0 — CL.0-SINGLE-TIER:** desync de una capa con oráculo de
  timing diferencial.
- **v0.86.0 — WCD-CACHE-KEY:** Web Cache Deception con contratos y
  escalera BENIGN → LEAK-NO-CACHE → WCD-CACHE → WCD-DEMO.
- **v0.85.0 — PIPE-CROSS:** nodo cross_layer en pipeline `/api/scan`,
  correlación entre capas.
- **v0.61.0 — Corpus fresco:** VDP-FRESH + prioridad mid-band en
  WIDE-HUNT.
- **v0.60.0 — SSA consume la evidencia:** FISCAL exige prueba def-use;
  refutación exige dominancia (RC-000142).
- **v0.59.0 — SSA-lite:** grafo de versiones def-use; el sink reporta
  la cadena completa.
- **v0.57.x — Refactor modular + auditoría propia:** core particionado,
  hardening del backend, ARCHITECTURE.md.
- **v0.55.0 — ARSENAL:** sección restringida (LAB/EXTREMO, contraseña,
  log de intentos).
- **v0.52.0 — UNIVERSAL-ENGINE:** de colección de herramientas a motor
  que adapta los analizadores.
- **v0.50.0 — CODEX-OBSERVE + CODEX-REGRESS:** puntos ciegos + corpus
  de regresión.
- **v0.47.0 — EVIDENCE-CHAIN + ABOGADOS:** FISCAL/DEFENSA/JUEZ
  deterministas.
- **v0.45.0 — DIFF-HUNT:** caza solo de código nuevo.

---

## Documentación

| Documento | Contenido |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | historial completo, versión por versión |
| [ARCHITECTURE.md](ARCHITECTURE.md) | arquitectura interna y guía de intervención |
| [AGENTS.md](AGENTS.md) | manual operativo para IAs: reglas de oro, comandos, veredictos |
| [docs/AUDITORIA_FALSOS_POSITIVOS.md](docs/AUDITORIA_FALSOS_POSITIVOS.md) | auditoría de FPs del motor |

**Demo real:** el dashboard cazando en vivo (login, sondas y hallazgo
verificado) en
[docs/demo_caza_dashboard.mp4](docs/demo_caza_dashboard.mp4).

---

## Multi-IA / multi-operador

Varias IAs u operadores pueden clonar el repo y cazar en paralelo sin
pisarse ni duplicar trabajo:

1. **Estado individual**: exportar `CODEXRC_HOME` con un directorio
   distinto por IA. Ahí viven su `hechos/hunt_wide_done.txt` y sus
   resultados. Sin exportarla, todo funciona como siempre.

       export CODEXRC_HOME=~/.codexrc_hermes

2. **Reparto del corpus**: `--shard N/M` divide la cola por hash
   determinista de slug. Cada instancia toma su fracción exacta.

       python3 core/hunt_wide.py --shard 0/2
       python3 core/hunt_wide.py --shard 1/2

El repo comparte código y datos públicos (data/); los
hechos de caza son privados de cada workspace.

---

## Créditos

Proyecto personal del operador, construido para la caza responsable en
programas de bug bounty con reglas estrictas: lectura A→B, sin
payloads de exploit, divulgación coordinada.

<p align="center"><b>La evidencia primero. Si no se puede probar, no se reporta.</b></p>
