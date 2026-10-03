# ARCHITECTURE.md — codexRC (mapa para IAs futuras)

> Proposito: que cualquier IA (o humano) que toque este repo sepa QUE HAY,
> QUE TOCA QUE, y QUE NO HAY QUE ROMPER. Leer esto ANTES de editar.

## Regla de oro

**Nunca cambiar logica y estructura en el mismo commit.** Si moves codigo,
movelo VERBATIM (cortar/pegar sin tocar una linea) y validá con import +
instanciacion + pyflakes. Si cambias comportamiento, hacelo en un commit
aparte con su propia validacion. Dos incognitas por commit = no se sabe
que rompio.

## Layout

```
backend/app.py     Unico entrypoint HTTP (Flask). TODAS las rutas /api/*,
                   registro de jobs (JOBS dict + lock), watchdog, auth de
                   Arsenal. main.py es CLI historico.
core/*.py          50 modulos, UNA responsabilidad cada uno. Sin carpeta
                   core/subpackages: la organizacion es por archivo plano.
frontend/*.html    3 UIs autocontenidas (index, hunter, arsenal). Llaman
                   solo a /api/* del backend. Cero build/npm.
config/            example_config.yaml (referencia)
hechos/            REGISTROS DE PROGRESO: hunt_wide_done.txt y retro_done.txt
                   son la memoria de "ya auditado" (caza incremental).
                   TOCAR ESTO = re-auditar todo desde cero. NUNCA vaciar.
reports/           Informes JSON/PDF/TXT generados por job (descartable)
ghosthook/         Binarios del hook de navegador (assets fijos)
poc/               Kits PoC locales generados (descartable, regenerable)
docs/              Especificaciones recibidas del operador
.agents.md / CHANGELOG.md / auto_update.sh
```

## Los 6 subsistemas y sus invariants

### 1. Motor de caza (corazon)
- `hunter.py` es una **FACHADA** (v0.57.2): re-exporta Spider, DeepHunter,
  XSSHunter, BlindXSS, XSSPro desde `hunter_{spider,deep,xss,blind,xsspro}.py`.
  Los importers (backend/app.py, async_lane.py, CLI) SOLO conocen la fachada.
  INVARIANTE: agregar una clase nueva al corpus = crear su archivo propio +
  re-exportarla en la fachada. Nunca volver a engordar hunter.py.
- `hunter_base.py`: constantes compartidas (SKIP_EXT, regexes JS, _norm, Log).
- `async_lane.py` (SLIPSTREAM): carril async con httpx. Su contrato:
  si httpx falta, `run()` lanza ImportError y el CALLER (hunter_xss.test_params)
  cae a hilos. NO "arreglar" ese raise: es el fallback disenado.
- `brain.py`, `self_tune.py`, `pipeline.py`: orquestacion y decisiones.

### 2. Autenticacion (auth.py, ~60KB)
- Matrix UNIVERSAL: bases x rutas x payloads (v0.57.0). La sesion heredada
  se guarda POR ORIGEN en LAST_AUTH_CONFIGS (nunca global pisada).
- INVARIANTE: `login_debug` registra NOMBRES y CONTEOS, nunca VALORES de
  credenciales. Los steps se auditan por eso: no loguear password/token.
- `ghostgate.py` + `waf_guard.py`: GHOSTGATE (evasion CF via navegador real)
  y GHOST-SHIELD (jitter + cooldown con memoria en waf_state.json).
  curl_cffi/cloudscraper son OPCIONALES con flags HAS_*: cualquier cambio
  debe seguir funcionando con ambas en False.

### 3. Verificacion anti-FP (lo que nos hace confiables)
Cadena de evidencia, en orden:
- `taint_trace.py` TAINT-TRACE: fuentes->sinks intra-archivo. Sanitizadores
  cortan taint. `wpdb->prepare` con placeholders = seguro.
- `gates_audit.py` GATES-AUDIT: dictamina si un handler AJAX/REST esta
  protegido (nonce/capability). Veredictos CANDIDATO-BAC / PROTEGIDO etc.
- `evidence.py` EVIDENCE-CHAIN: cada finding recibe cadena
  SOURCE/FLOW/AUTH/SANITIZATION/SINK/CORRELATION + FISCAL/DEFENSA/JUEZ
  (deterministas, LLM nunca es juez). CRITICO: la resolucion de ruta en
  build_chain matchea por ruta RELATIVA EXACTA primero (bug v0.49.1: dos
  archivos con mismo basename pisaban el analisis del otro).
- `fp_autoclose.py`: cierra falsos positivos conocidos.
- `pattern_match.py` CVE-MATCH: patrones ponderados, no firmas fijas;
  cada hallazgo cita la baseline global (pattern_baseline.json).
- `veritas.py`: navegador REAL contra falsos positivos. Si chrome falta,
  `available()` = False y todo lo demas sigue (nunca crash).
- `observe.py` / `regress.py` (CODEX-OBSERVE / CODEX-REGRESS): corpus de
  casos protegidos (~127). Es memoria: agregar caso nuevo cuando un FP
  nuevo se descubre, nunca borrar casos viejos.
- `escalada.py`: sigue el hallazgo crítico con 4 pasos automáticos.
  REGLA: solo escala piezas VERIFICADAS; una pieza sin verificar es
  hipotesis, no hallazgo "alta".

### 4. Caza masiva (plugins WP / DIFF-HUNT)
- `wide_corpus.py`: TODO plugin wordpress.org >= 5k installs (refrescable).
- `hunt_wide.py`: runner. Cola = corpus ∩ updates<=90d menos hechos/hunt_wide_done.txt.
  ESCritura INCREMENTAL crash-safe (.jsonl + done.txt). INVARIANTE: nunca
  re-auditar lo ya hecho; si el runner se cuelga, al revivir CONTINUA.
- `diff_hunt.py`: DIFF-HUNT, solo codigo nuevo (v0.45.0).
- `plugin_batch.py` / `retro_hunt.py` / `vendor_farm.py` / `cve_matcher.py`.

### 5. Ingenieria inversa (binarios / APKs)
`bin_audit.py` (secrets/ELF), `re_engine.py` (DEX/JAR/ELF parse Python puro),
`decompile.py` (bytecode DEX -> pseudocodigo). Todos Python puro: tienen
que seguir funcionando en armv7l SIN compilar nada.

### 6. Backend + UI
- backend/app.py: rutas, JOBS con JOBS_LOCK, _prune_jobs (tope MAX_JOBS),
  watchdog de zombies (`zombies.py`).
- SEGURIDAD (v0.57.4): bind 127.0.0.1 por defecto (LAN solo con
  CODEXRC_LAN=1); /api/auth_token solo-loopback; Arsenal con token 30 min;
  ARS_PASSWORD via env con aviso si queda default.
- LOGS SIN SECRETOS: log_event descarta password/token/cookies,
  safe_url redacta queries, safe_auth_info redacta Authorization.
  INVARIANTE: ninguna ruta ni log nuevo puede exponer credenciales.
- Arsenal (`arsenal.py`): modo LAB por defecto; EXTREMO exige contrasena
  (orden permanente del operador). Ningun payload funcional se dispara sin
  token de desbloqueo.

## Dependencias y fallbacks (Termux-first)

Ver `requirements.txt` (base 100% instalable en armv7l) y
`requirements-pc.txt` (curl_cffi, solo PC). Tabla de degradacion:

| Si falta...   | El sistema...                         |
|---------------|---------------------------------------|
| httpx         | SLIPSTREAM cae a hilos (transparente)|
| websocket     | COV-BAIT WS se desactiva solo        |
| fpdf          | PDF off, informe TXT/JSON igual      |
| chromium      | VERITAS off, PDF via fpdf2           |
| curl_cffi     | GHOSTGATE usa cloudscraper o requests|
| cloudscraper  | GHOSTGATE usa requests puro         |

Verificar una instalacion: `curl localhost:8000/api/status` → campo `deps`.

REGLA: una dependencia nueva entra al requirements base SOLO si es
Python puro (instala en armv7l sin compilar). Si no, va a requirements-pc
con un guard try/except en el import y un fallback documentado arriba.

## Flujo de un job de caza (trazabilidad)

1. POST /api/hunter → `_create_hunt_job` (valida, arma opts booleanos,
   registra job con _register_job bajo lock)
2. Hilo: nodos HUNTER_NODES en orden, cada uno setea estado en
   job["pipeline"]["nodes"] via node_state()
3. Hallazgos crudos → TAINT-TRACE / GATES-AUDIT → EVIDENCE-CHAIN
   (abogados) → solo los vivos siguen → VERITAS si hay navegador
4. escalada.py sobre lo verificado → report via report_export.py
5. Job expuesto por /api/jobs/<id> (leaks aparte), export TXT/JSON/PDF

## Como editar sin romper (checklist)

1. Leer esta seccion + el modulo objetivo + sus callers (grep import).
2. Cambio de comportamiento: tocar UN modulo, correr su CLI local
   (`python3 core/<modulo>.py` casi todos tienen __main__ de prueba).
3. Mover codigo: verbatim + validar `python -c "import ..."` +
   `python -m pyflakes` (ignora unused-imports) + instanciacion offline.
4. Validacion anti-FP: un finding debe pasar EVIDENCE-CHAIN; si tocás
   evidence.py o taint_trace.py, correr los 4 casos del lab (ver
   CHANGELOG v0.47.0 y v0.49.1) antes de pushear.
5. Version bump en backend/app.py + entrada en CHANGELOG.md (detalle) +
   README solo hitos.
6. Push. En Termux el operador hace `git pull` (auto_update.sh vigila).

## Nomenclatura persistente

- GHOSTGATE = evasion CF delegando a navegador real (nombre del operador).
- El operador nunca aparece por nombre real en repo/docs/informes.
- Emojis: 💥 = hallazgo explotable real (la unica senal de interrupcion
  valida para el operador).

## Versiones/recursos

- Version actual en backend/app.py (VERSION). Detalle por version: CHANGELOG.
- El repo vive en github.com/Eliezer1817/codexRC (push directo autorizado).
- auto_update.sh (Termux): lock PID, resurreccion del server, anti-cuelgue,
  backoff. start_termux.sh para arranque manual.
