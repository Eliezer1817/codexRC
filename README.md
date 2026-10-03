# CodexRC

![CodexRC](assets/banner.jpg)

**Motor de auditoría y caza de vulnerabilidades web** con backend local, dashboard propio, veredictos basados en evidencia y campañas de caza masiva sobre plugins WordPress y blancos autorizados.

> ⚠️ **Solo usar en objetivos que tengas autorización para auditar.**

> 🧠 **¿Sos una IA (o le vas a pasar esta herramienta a una)?** Leé primero
> [AGENTS.md](AGENTS.md): manual operativo paso a paso, reglas de oro,
> comandos y cómo interpretar cada veredicto. La arquitectura interna está
> documentada en [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Índice

- [Filosofía](#filosofía)
- [Advertencias y condiciones de uso](#advertencias-y-condiciones-de-uso)
- [Arquitectura general](#arquitectura-general)
- [El pipeline de evidencia](#el-pipeline-de-evidencia)
- [Mapa de módulos](#mapa-de-módulos)
- [Modos de caza](#modos-de-caza)
- [Escala de veredictos](#escala-de-veredictos)
- [Instalación](#instalación)
- [Uso rápido](#uso-rápido)
- [Disciplina de calidad (CODEX-REGRESS)](#disciplina-de-calidad-codex-regress)
- [Novedades (hitos)](#novedades-hitios)
- [Documentación](#documentación)
- [Créditos](#créditos)

---

## Filosofía

CodexRC no pregunta *"¿podría ser vulnerable?"*. Pregunta
**"¿qué evidencia tengo para afirmar que realmente lo es?"**.

1. **Sin evidencia no hay hallazgo.** Cada finding construye una cadena
   (SOURCE → FLOW → AUTH → SANITIZATION → SINK → CORRELATION) sobre la
   que razonan abogados deterministas, no intuiciones.
2. **Mejor 4 hallazgos que ejecutan de verdad que 20 que solo se
   reflejan.** VERITAS re-verifica cada candidato en un navegador real
   con un canario inerte antes de sellarlo.
3. **El ruido se elimina en el motor, no a mano.** Guardas semánticas,
   refutación por dominancia, corpus de regresión: los falsos positivos
   mueren solos y queda registro de por qué.
4. **La caza respeta el blanco.** Sondas de lectura A→B (contrasta el
   acceso con y sin sesión), canarios inertes, jitter y cortesía con
   las APIs públicas. Nada de payloads de exploit.

---

## Advertencias y condiciones de uso

- **Autorización primero.** Esta herramienta está pensada para
  programas de bug bounty con alcance definido, laboratorios propios y
  blancos con autorización explícita. Auditar sistemas ajenos sin
  permiso es ilegal en la mayoría de jurisdicciones.
- **Proyecto en desarrollo activo.** Se actualiza con mucha frecuencia
  (a veces varias versiones por día) y la interfaz cambia sin aviso.
  No recomendado aún para uso en producción; revisá siempre
  [CHANGELOG.md](CHANGELOG.md) antes de correr la última versión.
- **Arsenal restringido.** `frontend/arsenal.html` es una sección
  interna del operador con acceso por contraseña (cada intento queda
  registrado), sesión de 30 minutos y contenido no publicado. Opera en
  modo **LAB** por defecto; el nivel avanzado (EXTREMO) exige
  advertencia y confirmación, y sus condiciones son no negociables:
  laboratorio propio o blanco autorizado, demostración mínima con stop
  al primer impacto, sin dump masivo, sin persistencia, nada destructivo.
- **Las sondas son de lectura A→B.** Contrastan el acceso con y sin
  sesión, sin alterar datos del objetivo, sin payloads de exploit.
- **El Hunter puede quemar tu IP.** Si el blanco usa Cloudflare y la
  IP rebota, existe GHOSTGATE (delegar a un navegador real con IP
  limpia); si el bloqueo persiste, el blanco se descarta.
- **Respetá los límites de los programas.** Rate limits por hora,
  scope definido por el vendor, reglas de divulgación coordinada.

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
                    │  única implementación,       │
                    │  server 127.0.0.1            │
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

- **Backend:** `backend/app.py`, servidor Flask restringido a
  `127.0.0.1` con token de autenticación; toda la lógica vive en `core/`.
- **Frontend:** dashboards que solo presentan la interfaz y llaman a
  `/api/*`. `arsenal.html` es la sección restringida del operador.
- **Termux:** solo inicia el backend y mantiene disponible
  `localhost`; compatible con `armv7l` (32 bits), todo en Python puro
  (el bypass de Cloudflare usa `cloudscraper`, sin binarios
  precompilados ni `curl_cffi`).
- **Logs:** cada escaneo se guarda en `reports/codexrc_<id>.json`
  descargable desde el dashboard; los eventos quedan en
  `reports/backend.log` (JSONL, rotación automática, `request_id`).

---

## El pipeline de evidencia

Cada hallazgo pasa por capas que producen evidencia cada vez más
semántica:

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
  ambigua o hash que no coincide = `INTEGRITY`, y un veredicto alto
  jamás se sostiene sobre evidencia de un archivo equivocado.
- **CFG + dominancia** (`core/cfg.py`): un gate "cerca" del handler
  solo cuenta si realmente domina el flujo (RC-000132).
- **SSA-lite** (`core/ssa.py`): grafo de versiones def-use por
  función. Cada asignación crea una versión (SOURCE / SANITIZED /
  PREPARED / CONCAT / COPY / CONST / UNKNOWN-FN / UNKNOWN-VAR) con
  padres. El sink recibe la **cadena completa** (`$sql ← COPY ← $term
  ← SOURCE @L11`), y `def_use_proof()` entrega una prueba estructurada
  que SSA nunca dictamina vulnerabilidad: {proof, value, lineage,
  source, unknown_ancestors, transformations}. Refutar exige que la
  asignación limpia **domine el sink** (RC-000142).
- **EVIDENCE-CHAIN** (`core/evidence.py`): la cadena completa + los
  tres abogados. FISCAL debe PROBAR cada requisito ("taint alcanza el
  sink" exige `DEF_USE_COMPLETE`, ya no se marca probado sin prueba);
  DEFENSA busca refutaciones (gate protegido, sanitizador, prepare,
  admin-only, reasignación limpia demostrada por SSA); el JUEZ pesa y
  dicta con reglas fijas (nunca un LLM). Los proofs con ancestros
  desconocidos jamás sostienen `DEMOSTRADO-ESTATICO`.

---

## Mapa de módulos

### Reconocimiento e infraestructura

| Módulo | Qué hace |
|---|---|
| `recon` · `tech_detect` | reconocimiento y fingerprint tecnológico del blanco |
| `auth` | login automático por formulario HTML o API JSON (SPAs Angular/React), autodetección de endpoint, CSRF, cabeceras Origin/Referer |
| `brain` | CEREBRO: fingerprint del blanco y priorización de la cola por puntaje con presupuesto dinámico |
| `ghostgate` | GHOSTGATE: delega a un navegador real (IP limpia) cuando la IP está quemada en Cloudflare |
| `waf_guard` | GHOST-SHIELD: jitter por sonda, clasificador de bloqueo, cooldown exponencial y memoria persistente de IPs quemadas |
| `async_lane` | SLIPSTREAM: carril asíncrono (hasta 64 sondas en vuelo, ~219 sondas/s) con fallback a hilos |
| `pipeline` | orquestación de escaneos completos |
| `self_tune` | autoajuste persistente del presupuesto de sondas según historial |

### Análisis estático (PHP y binarios)

| Módulo | Qué hace |
|---|---|
| `cfg` | CFG con dominancia: el control de acceso solo cuenta si domina el flujo |
| `ssa` | SSA-lite: versiones def-use, cadenas completas y `def_use_proof` |
| `taint_trace` | TAINT-TRACE: flujo fuente → sink (SQLi ciego, XSS, unserialize, LFI, RCE, SSRF) |
| `gates_audit` | mapea handlers ajax/REST a su callback y dictamina si están protegidos |
| `pattern_match` | CVE-MATCH: patrones ponderados de familias históricas (BAC ajax, type juggling, IPN downgrade, SSRF, upload, PrivEsc) con línea base global del corpus |
| `cve_matcher` · `diff_hunt` | cruce con CVEs conocidos y caza solo de código NUEVO (updates ≤ 90 días) |
| `bin_audit` | BIN-AUDIT: secrets hardcodeados, endpoints internos, imports peligrosos (ELF real), contenedores recursivos |
| `re_engine` | REVERSE: parse de DEX/class/ELF, ofuscación ProGuard, entropía |
| `decompile` | DECOMPILE: bytecode DEX → pseudocódigo legible de métodos sensibles |
| `deep_scan` · `zombies` | escaneo profundo y detección de código muerto/heredado |

### Razonamiento de evidencia

| Módulo | Qué hace |
|---|---|
| `semantic_core` | identidad canónica + integridad de archivos (RC-000127) |
| `evidence` | EVIDENCE-CHAIN + FISCAL/DEFENSA/JUEZ + historial de veredictos |
| `observe` | CODEX-OBSERVE: reflexión sobre puntos ciegos (qué NO se analizó) |
| `escalada` | tras un hallazgo crítico: VERITAS dirigido, techo de impacto, kit PoC local con canarios inertes |
| `veritas` | verificación con navegador real (canario inerte, solo lectura) |
| `fp_autoclose` | FP-AUTO-CLOSE: cierra familias de falsos positivos aprendidas |

### Caza activa (Hunter)

| Módulo | Qué hace |
|---|---|
| `hunter` (fachada) · `hunter_base` · `hunter_spider` · `hunter_deep` · `hunter_xss` · `hunter_xsspro` · `hunter_blind` | spider, corpus XSS, DeepHunter (BAC/IDOR/CSP/superficie), batería XSS-PRO |
| `sqli_bait` | SQLI-BAIT: 4 niveles (error-based con fingerprint del motor, boolean por diferencial, time-based anti-jitter, stacked) |
| `cov_bait` | COV-BAIT: caza guiada por cobertura de código vía CDP con motor de mutación con feedback |
| `path_bait` · `ssti_bait` · `cache_bait` · `graphql_bait` · `stealth_bait` | LFI con wrappers, SSTI, Web Cache Deception, GraphQL, sondas postMessage/CSP |
| `chain` | encadenamiento determinista (XSS+CSP débil, SQLi+panel, IDOR masivo) |

### Campañas y corpus

| Módulo | Qué hace |
|---|---|
| `wide_corpus` · `hunt_wide` | corpus = TODOS los plugins wordpress.org ≥5k installs; cola priorizada: VDP-FRESH → pagables → banda 5k-50k → resto |
| `diff_hunt` | DIFF-HUNT: solo código nuevo (updates ≤ 90 días), paralelo |
| `retro_hunt` | RETRO-HUNT: código PRE-COOLDOWN (plugins cuya última actualización es anterior al gate de IA de WP.org), full-code por bounty |
| `plugin_batch` | PLUGIN-BATCH: caza plugins por slugs, un comando de agente |
| `vendor_farm` | VENDOR-FARM: caza por vendor completo |
| `vdp_fresh` | VDP-FRESH: diff semanal del directorio VDP de Patchstack (GOLDEN LIST): altas, bounty nuevos y bajas |

### Reportes y entorno

| Módulo | Qué hace |
|---|---|
| `report_export` | informes TXT/JSON/PDF (filtraciones arriba, hallazgos por severidad, sello verificado) |
| `universal_engine` | UNIVERSAL-ENGINE: orquestador que aprende cómo está construida una app y adapta los analizadores; Ledger de Cobertura (ANALIZADO / DESCUBIERTO / NO ACCESIBLE / VERIFICADO) |
| `wplab*` (WP-LAB) | laboratorio WordPress local (PHP 8.2 + SQLite) para verificación dinámica AUTH-DIFF en sitio propio |
| `regress` | CODEX-REGRESS: corpus de regresión (ver abajo) |
| `ghosthook/` | colector de blind XSS gratuito para Cloudflare Workers + KV |

---

## Modos de caza

- **DIFF-HUNT** — solo el código NUEVO de cada plugin (≤90 días). La
  ventana real de ser primeros: el parche de seguridad del propio
  vendor y el hardening reciente no cuentan como blanco.
- **WIDE-HUNT** — corpus completo ≥5k installs (3.260 plugins). Cola
  incremental y crash-safe; prioridad mid-band 5k-50k (medianos con
  menos blindaje y competencia que los top). `--dry-run` imprime la
  cola sin cazar.
- **RETRO-HUNT** — el código que nadie mira: plugins congelados antes
  del gate de IA de WP.org (junio 2026), auditoría full-code por bounty.
- **VDP-FRESH** — el corpus fresco automático: diff semanal del
  directorio VDP de Patchstack. Un VDP recién agregado se caza ya
  (etiqueta NUEVO-VDP, sin filtro de 90 días ni de corpus), porque
  nadie lo revisó aún.
- **PLUGIN-BATCH / VENDOR-FARM** — caza dirigida por slugs o por
  vendor completo, un comando.
- **PIPE-HUNT** — `waybackurls sitio.com | python3 hunt_pipe.py --xsspro
  --workers 8`: recibe URLs por stdin desde cualquier herramienta.

---

## Escala de veredictos

Solo se reporta lo demostrable (escala RacerD):

| Veredicto | Significado |
|---|---|
| `CONFIRMED` | prueba estática completa + dinámica reproducida |
| `DEMOSTRADO-ESTATICO` | prueba estática completa (FISCAL 4/4, INTEGRITY ok, proof def-use completo) |
| `PROBABLE` | flujo probado pero con alcance/dinámica/ancestros desconocidos sin resolver |
| `CONTESTADO` | la defensa tiene refutación parcial |
| `DESCARTADO` | refutación fuerte (gate, sanitizador, prepare, admin-only, reasignación limpia demostrada) |

Cada cadena expone **falsadores**: qué evidencia tumbaría el veredicto.

---

## Instalación

### Termux (Android, armv7l)

```bash
pkg update && pkg install python git
git clone https://github.com/Eliezer1817/CodexRC.git
cd CodexRC
pip install -r requirements.txt          # 100% Python puro, apto para 32 bits
python3 backend/app.py                   # servidor en 127.0.0.1
```

`auto_update.sh` mantiene el server vivo: instancia única por lock,
resurrección ante crash con volcado de diagnóstico, anti-cuelgue y
wake-lock (requiere Ajustes → Apps → Termux → Batería → Sin
restricciones).

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

# Campañas sobre el corpus
python3 core/hunt_wide.py --dry-run          # ver la cola priorizada
python3 core/hunt_wide.py --workers 6        # cazar
python3 core/diff_hunt.py slug1 slug2        # solo código nuevo
python3 core/plugin_batch.py slug1 slug2 --vdp vdp_matches.json

# Corpus fresco (flujo semanal)
python3 core/vdp_fresh.py --snapshot         # línea base
python3 core/vdp_fresh.py --diff vdp_mapa.json   # -> vdp_nuevos.json

# Análisis binario / APK
python3 core/bin_audit.py ./sdk.zip
python3 core/re_engine.py ./app.apk
python3 core/decompile.py ./app.apk --all

# Caza de blanco autorizado (login + sesiones)
python3 core/pipeline.py https://blanco.com --user X --pass Y
```

La API local expone todo lo mismo en `/api/*` (ver `AGENTS.md` para el
catálogo completo).

---

## Disciplina de calidad (CODEX-REGRESS)

Cada bug del motor (falso positivo, refutación inservida, regressión
de control de acceso) se congela en un caso del corpus
`.codexrc/intelligence/regressions/corpus.jsonl` con repro y
expectativa, y la suite corre en cada versión:

```bash
python3 core/regress.py    # corpus completo, 0 fallos requeridos
```

Ejemplos de invariantes que el corpus protege: el 0-day real de
RegistrationMagic (IPN downgrade) debe permanecer vivo; las
comparaciones flojas protegidas por gates deben morir (RC-000135/136);
la refutación SSA exige dominancia (RC-000142); la resolución de rutas
por basename jamás analiza el archivo equivocado (RC-000127).

---

## Novedades (hitos)

Solo los hitos, de lo más reciente a lo más antiguo. Detalle completo
de cada versión en [CHANGELOG.md](CHANGELOG.md).

- **v0.61.0 — Corpus fresco:** VDP-FRESH (diff semanal del directorio
  VDP de Patchstack) + prioridad mid-band 5k-50k en WIDE-HUNT.
- **v0.60.0 — SSA consume la evidencia:** FISCAL exige prueba def-use
  para "taint alcanza el sink"; proofs incompletos jamás sostienen
  DEMOSTRADO-ESTATICO; refutación exige dominancia (RC-000142).
- **v0.59.0 — SSA-lite:** grafo de versiones def-use en TAINT-TRACE;
  el sink reporta la cadena completa, no solo proximidad.
- **v0.58.x — SEMANTIC CORE:** identidad canónica + integridad,
  CFG con dominancia en producción, cierre de la familia loose-cmp
  (RC-000132/135/136) y triaje completo del backlog N1∩VDP.
- **v0.57.x — Refactor modular + auditoría propia:** core particionado
  en submódulos, hardening del backend (localhost + token gating),
  higiene de dependencias Termux-first, ARCHITECTURE.md.
- **v0.55.0 — ARSENAL:** sección restringida del operador (LAB/EXTREMO,
  contraseña + log de intentos, sesión 30 min).
- **v0.53.0 — UI-RENAISSANCE:** estética terminal renovada, legible en
  PC y móvil.
- **v0.52.0 — UNIVERSAL-ENGINE:** de colección de herramientas a motor
  que aprende cómo está construida la app y adapta los analizadores.
- **v0.50.0 — CODEX-OBSERVE + CODEX-REGRESS:** puntos ciegos +
  corpus de regresión.
- **v0.49.0 — VERIFICACIÓN DEL SISTEMA / EVIDENCE-CHAIN hardening.**
- **v0.47.0 — EVIDENCE-CHAIN + ABOGADOS:** razonamiento de evidencia
  determinista (FISCAL/DEFENSA/JUEZ).
- **v0.48.0 — WIDE-HUNT:** el corpus se multiplica a ≥5k installs.
- **v0.45.0 — DIFF-HUNT:** caza solo de código nuevo.
- **v0.40.0 — VERIFICACIÓN DEL SISTEMA** (validación de credenciales y
  sesiones contra blancos reales).

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

## Créditos

Proyecto personal del operador, construido para la caza responsable en
programas de bug bounty con reglas estrictas (lectura A→B, sin
payloads de exploit, divulgación coordinada).

<p align="center"><b>La evidencia primero. Si no se puede probar, no se reporta.</b></p>
