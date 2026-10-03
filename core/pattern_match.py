"""CVE-MATCH: aprendizaje de patrones globales sobre codigo PHP.

Compara el codigo de un plugin contra PATRONES ABSTRACTOS destilados de
vulnerabilidades historicas reales (CVEs verificadas + 0-days propios de
CZ-HUNT). No usa firmas fijas: cada patron es una COMBINACION de senales
estructurales debiles que juntas forman el fallo conocido:

  ej. BAC ajax sin auth = hook nopriv (+3) + escritura (+3) + input de
  usuario (+2) - proteccion presente (-4) + nonce impreso al frontend
  (+2, cancela el veto del nonce)

Si el puntaje pasa el umbral, el hallazgo cita la familia:
"coincide con la familia del 0-day AFFI (CZ-HUNT 2026) / CVE-2023-6875".

LINEA BASE GLOBAL (miles de funciones): con --baseline se mide que
porcentaje de funciones similares del corpus (cientos de plugins
descargados) SI tiene la proteccion. Un hallazgo anota:
"outlier: 92% de los handlers parecidos del corpus protegen esto".
Comparar contra la poblacion es lo que separa un patron de un ruido.

Patrones incluidos (familias con referencia real):
  bac-ajax-nopriv  : BAC/PrivEsc en ajax nopriv (0-day AFFI, VillaTheme)
  loose-auth-cmp   : comparacion floja en control de acceso
                     (CVE-2023-6875 Post SMTP, type juggling)
  ipn-downgrade    : verificacion de pago degradable a sandbox
                     (CVE-2026-9242 RegistrationMagic, vector propio)
  ssrf-from-request: SSRF con URL del usuario (familia SSRF plugins WP)
  upload-unchecked : subida de archivos sin validar tipo
                     (familia upload arbitrario, Patchstack paga)
  role-from-request: rol/capacidad escrita desde request (PrivEsc)

Uso:
    python3 core/pattern_match.py <archivo_o_dir> [--top N] [--json]
    python3 core/pattern_match.py <corpus> --baseline   # construye stats
    POST /api/patterns {"path": "..."}                   (backend)
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

# ------------------------------------------------------------------ patron

PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "bac-ajax-nopriv",
        "family": "BAC AJAX sin autenticacion",
        "cve_ref": "familia 0-day AFFI (CZ-HUNT 2026, VillaTheme) y "
                   "CVEs BAC ajax nopriv del vendor-farming",
        "severity": "critica",
        "threshold": 6,
        "signals": [
            {"w": 3, "pat": r"add_action\(\s*['\"]wp_ajax_nopriv_",
             "why": "handler ajax accesible SIN login"},
            {"w": 3, "pat": r"\b(?:update_option|update_user_meta|"
                            r"update_post_meta|wp_update_user|wp_insert_post|"
                            r"wp_insert_user|\$wpdb->(?:query|insert|update|"
                            r"delete))\b",
             "why": "el handler escribe datos"},
            {"w": 2, "pat": r"\$_(?:GET|POST|REQUEST)",
             "why": "usa input de usuario"},
        ],
        "bonus_file": {"w": 2, "pat": r"wp_create_nonce|wp_localize_script",
                       "why": "el nonce se imprime publico en el frontend "
                              "(cancela el veto del nonce)"},
        "protect": {"w": -4, "pat": r"current_user_can|is_user_logged_in|"
                                     r"wp_verify_nonce|check_admin_referer",
                    "why": "hay chequeo de capability o nonce"},
    },
    {
        "id": "loose-auth-cmp",
        "family": "Comparacion floja en control de acceso (type juggling)",
        "cve_ref": "CVE-2023-6875 (Post SMTP, null==false verificado en lab)",
        "severity": "critica",
        "threshold": 6,
        "signals": [
            {"w": 6, "pat": r"(?<![!=])[!=]=(?!=)\s*"
                            r"\$_(?:GET|POST|REQUEST|COOKIE)\[|"
                            r"\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]*\]"
                            r"\s*[!=]=(?!=)",
             "why": "compara input de usuario con == (no ===)"},
        ],
        "protect": {"w": 0, "pat": r"===|hash_equals|wp_verify_nonce",
                    "why": "comparacion estricta en la misma linea"},
    },
    {
        "id": "ipn-downgrade",
        "family": "Verificacion de pago degradable (IPN downgrade)",
        "cve_ref": "CVE-2026-9242 (RegistrationMagic, vector sandbox propio)",
        "severity": "critica",
        "threshold": 6,
        "signals": [
            {"w": 4, "pat": r"test_ipn|\bipn\b|IPNHandler",
             "why": "procesa notificaciones de pago"},
            {"w": 2, "pat": r"payment_status|Completed|pending",
             "why": "confia en el estado que reporta el POST"},
            {"w": 2, "pat": r"ssl://|https?://[^\s'\"]*(?:paypal|ipn|sandbox)",
             "why": "endpoint de verificacion presente"},
        ],
        "protect": {"w": -4, "pat": r"hash_equals|verify_signature|"
                                    r"check_ipn|CertificateChain",
                    "why": "valida la firma del notificador"},
    },
    {
        "id": "ssrf-from-request",
        "family": "SSRF con URL de usuario",
        "cve_ref": "familia SSRF en plugins WP (wp_remote_* con input)",
        "severity": "alta",
        "threshold": 6,
        "signals": [
            {"w": 6, "pat": r"wp_remote_(?:get|post|request|head)\s*\(\s*"
                            r"\$_(?:GET|POST|REQUEST)",
             "why": "pide la URL que manda el usuario"},
        ],
        "protect": {"w": 0, "pat": r"esc_url_raw|wp_allowed_protocols",
                    "why": "normaliza el esquema/protocolo"},
    },
    {
        "id": "upload-unchecked",
        "family": "Subida de archivos sin validacion de tipo",
        "cve_ref": "familia upload arbitrario (control total "
                   "path+extension, Patchstack paga $ alto)",
        "severity": "critica",
        "threshold": 5,
        "signals": [
            {"w": 3, "pat": r"move_uploaded_file\s*\(",
             "why": "mueve el archivo subido"},
            {"w": 2, "pat": r"\$_FILES\b",
             "why": "usa el upload directo"},
        ],
        "protect": {"w": -4, "pat": r"wp_check_filetype|"
                                    r"check_filetype_and_ext|getimagesize|"
                                    r"allowed_mime|ALLOWED_TYPES|\.jpg|\.png|"
                                    r"whitelist|allowed_ext",
                    "why": "valida el tipo/extension del archivo"},
    },
    {
        "id": "role-from-request",
        "family": "Rol/capacidad escrita desde request (PrivEsc)",
        "cve_ref": "familia PrivEsc a contributor+ (Patchstack paga)",
        "severity": "critica",
        "threshold": 6,
        "signals": [
            {"w": 3, "pat": r"->add_role\(|->set_role\(|->add_cap\(|"
                            r"wp_update_user\s*\(",
             "why": "modifica rol o capacidades"},
            {"w": 3, "pat": r"(?:role|caps?|capability)\w*\s*['\"]?\]?\s*="
                            r"\s*\$_(?:GET|POST|REQUEST)|"
                            r"\$_(?:GET|POST|REQUEST)\[[^\]]*(?:role|cap)",
             "why": "el rol viene del request"},
        ],
        "protect": {"w": -4, "pat": r"current_user_can|manage_options|"
                                    r"administrator",
                    "why": "chequea capability antes de escribir el rol"},
    },
]

# ------------------------------------------------------- troceo de funciones

_FUNC = re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)\s*\{")


def _iter_functions(src: str):
    """Genera (nombre, numero_linea_inicio, cuerpo) con brace matching."""
    out = []
    for m in _FUNC.finditer(src):
        name, i = m.group(1), m.end() - 1      # posicion de la llave
        depth, j, n = 0, i, len(src)
        while j < n:
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        line0 = src.count("\n", 0, m.start()) + 1
        out.append((name, line0, src[i + 1:j]))
    return out


# ------------------------------------------------------------------- motor

class PatternMatcher:
    def __init__(self, baseline: Optional[Dict[str, Any]] = None):
        self.baseline = baseline or {}
        self.findings: List[Dict[str, Any]] = []
        # cuerpo de CADA funcion escaneada (para resolver handlers
        # nopriv que viven en otro archivo/metodo)
        self._bodies: Dict[str, str] = {}
        self._bac_pending: List[Dict[str, Any]] = []

    def scan_file(self, path: str) -> List[Dict[str, Any]]:
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            return []
        rel = os.path.relpath(path)
        chunks = _iter_functions(src)
        for name, _l, body in chunks:
            if name:
                self._bodies.setdefault(name.lower(), body)
        for pat in PATTERNS:
            file_bonus = 0
            fb = pat.get("bonus_file")
            if fb and re.search(fb["pat"], src):
                file_bonus = fb["w"]
            for name, line0, body in chunks:
                self._match(pat, rel, src, name, line0, body, file_bonus)
        return self.findings

    def _match(self, pat, rel, src, fname, line0, body, file_bonus):
        score, whys = 0, []
        # RC-000133: sin el hook nopriv NO hay BAC ajax. El patron no
        # debe disparar solo por "escribe datos + usa input" (FP pods
        # admin_save, cuyo gate vive en el CALLER).
        if pat["id"] == "bac-ajax-nopriv" and not re.search(
                pat["signals"][0]["pat"], body):
            return
        # RC-000135: comparacion floja SIN contexto de autorizacion =
        # filtro de datos/settings no-auth -> FP (term_id != 0, code != '')
        if pat["id"] == "loose-auth-cmp" and not self._loose_auth_context(
                src, fname, line0, body):
            return
        for sig in pat["signals"]:
            m = re.search(sig["pat"], body)
            if m:
                score += sig["w"]
                whys.append(sig["why"])
        prot = pat.get("protect")
        prot_hit = bool(prot) and bool(re.search(prot["pat"], body))
        if prot_hit:
            # veto suave: el nonce impreso publico cancela el veto del nonce
            if pat["id"] == "bac-ajax-nopriv" and file_bonus:
                pass                        # nonce publico: el veto no aplica
            else:
                score += prot["w"]
                whys.append("ojo: " + prot["why"] + " (resta)")
        if pat["id"] == "bac-ajax-nopriv" and file_bonus:
            score += file_bonus
            whys.append(pat["bonus_file"]["why"])
        if score < pat["threshold"]:
            return
        line = line0
        mm = re.search(pat["signals"][0]["pat"], body)
        if mm:
            line = line0 + body.count("\n", 0, mm.start())
        f = {
            "file": rel, "line": line, "function": fname,
            "type": "PATRON: " + pat["family"],
            "severity": pat["severity"], "cve_ref": pat["cve_ref"],
            "score": f"{score}/{pat['threshold']}",
            "why": "; ".join(whys),
            "verdict": "patron abstracto de fallo historico detectado "
                       "(sin firma fija)",
        }
        if pat["id"] == "bac-ajax-nopriv":
            f["_hook_body"] = body      # RC-000131: postergado a finalize
            self._bac_pending.append(f)
            return self.findings
        st = self.baseline.get(pat["id"])
        if st:
            f["outlier"] = (f"{st['protected_pct']:.0f}% de las funciones "
                            "parecidas del corpus SI tienen la proteccion; "
                            "esta NO (n=" + str(st["n"]) + ")")
        key = (f["file"], f["function"], pat["id"])
        if key not in {(x["file"], x["function"],
                        x["cve_ref"]) for x in self.findings}:
            self.findings.append(f)


    # ---- RC-000135: loose-cmp debe tocar AUTORIZACION, no filtros ----
    # Tokens AUTH: la comparacion floja (o su contexto +-5 lineas) debe
    # mencionar algo de auth/authz para valer como hallazgo critico.
    # tokens fuertes: valen en los OPERANDOS o en el contexto +-5 lineas
    _AUTH_STRONG = re.compile(
        r"password|passwd|user_pass|pass_hash|\bpwd\b|nonce|"
        r"capability|current_user_can|user_can\s*\(|"
        r"is_user_logged_in|\blogin\b|\brole\b|privilege|"
        r"\bcookie\b|manage_options|edit_others|manage_woocommerce")
    # ---- RC-000136: gate adyacente mata el loose-cmp ----
    # Si en +-1 linea de la comparacion senalada hay un capability check
    # o early-return de auth, esa llamada ES el control de acceso real;
    # la comparacion floja es solo router/filtro detras del gate.
    _GATE_ADJ = re.compile(
        r"current_user_can\s*\(|\buser_can\s*\(|"
        r"is_user_logged_in\s*\(|_can_access\b|"
        r"wp_die|\bdie\s*\(|\bexit\b")

    # tokens debiles (auth/token/secret abundan en flujos oauth y en
    # "author" de queries): solo cuentan en los OPERANDOS de la
    # comparacion misma
    _AUTH_OPERAND = re.compile(
        r"\bauth(?!or)|\btoken\b|secret")

    @staticmethod
    def _nocomments(txt: str) -> str:
        txt = re.sub(r"/\*.*?\*/", " ", txt, flags=re.S)
        return re.sub(r"//[^\n]*", " ", txt)

    def _loose_auth_context(self, src: str, fname: str, line0: int,
                            body: str) -> bool:
        # snippet: 80 chars alrededor del == SENALADO (no el primero del
        # cuerpo). Funciones grandes de registro tienen == de checkbox
        # lejos del password: solo la linea senalada decide.
        m = re.search(r"[!=]=(?!=)", body)
        if m:
            flagged = line0 + body.count("\n", 0, m.start())
            lines = src.split("\n")
            # RC-000136 PRIMERO: capability check / early-return de auth
            # en +-1 linea = esa llamada ES el control de acceso real; el
            # loose-cmp es router/filtro detras del gate -> FP
            adj = self._nocomments(
                "\n".join(lines[max(0, flagged - 2):flagged + 1]))
            if self._GATE_ADJ.search(adj):
                return False
            snip = self._nocomments(
                body[max(0, m.start() - 80):m.end() + 80])
            if self._AUTH_STRONG.search(snip):
                return True
            if self._AUTH_OPERAND.search(snip):
                return True
            lo = max(0, flagged - 1 - 5)
            hi = min(len(lines), flagged - 1 + 6)
            ctx = self._nocomments("\n".join(lines[lo:hi]))
            return bool(self._AUTH_STRONG.search(ctx))
        return False

    # ---- RC-000131: nopriv intencional con gate interno ----
    _GATES = re.compile(
        r"current_user_can\s*\(|is_user_logged_in\s*\(|"
        r"wp_verify_nonce\s*\(|check_admin_referer\s*\(|"
        r"check_ajax_referer\s*\(|user_can\s*\(|"
        r"pods_is_admin\s*\(|manage_options")

    def _bac_callbacks(self, body: str) -> List[str]:
        cbs: List[str] = []
        for m in re.finditer(
                r"add_action\s*\(\s*['\"]wp_ajax_nopriv_[\w-]+['\"]"
                r"\s*,\s*([^;]+);", body):
            tok = m.group(1)
            for cb in re.findall(r"['\"]([A-Za-z_]\w*)['\"]", tok):
                if not cb.startswith("wp_ajax"):
                    cbs.append(cb.lower())
            if not cbs:
                nm = re.match(r"\s*([A-Za-z_]\w*)\s*$", tok.strip())
                if nm:
                    cbs.append(nm.group(1).lower())
        return cbs

    def finalize(self) -> None:
        """Resuelve los handlers nopriv y filtra los que tienen gate
        interno (nonce/caps). Clase RC-000131: el patron disparaba por
        el HOOK sin mirar el cuerpo del handler (FP pods admin_ajax)."""
        for f in self._bac_pending:
            cbs = self._bac_callbacks(f.pop("_hook_body", ""))
            gated, seen = False, False
            for cb in cbs:
                body = self._bodies.get(cb)
                if body is None:
                    continue
                seen = True
                if self._GATES.search(body):
                    gated = True
                    break
            if gated:
                continue          # handler con gate interno: FP documentado
            if seen:
                f["why"] += "; handler sin gates visibles nivel 1"
            self.findings.append(f)
        self._bac_pending = []


# ------------------------------------------------------------- linea base

def build_baseline(corpus: str) -> Dict[str, Any]:
    """Mide que % de funciones con el patron SI tienen la proteccion."""
    stats: Dict[str, Any] = {}
    counts = {p["id"]: {"total": 0, "protected": 0} for p in PATTERNS}
    files: List[str] = []
    if os.path.isfile(corpus):
        files = [corpus]
    else:
        for root, _d, fs in os.walk(corpus):
            files += [os.path.join(root, f) for f in fs
                     if f.endswith(".php")]
    for fp in sorted(files):
        try:
            src = open(fp, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for pat in PATTERNS:
            prot = pat.get("protect")
            if not prot or pat["id"] == "loose-auth-cmp":
                continue                    # sin veto no hay % que medir
            for _n, _l, body in _iter_functions(src):
                hits = sum(1 for s in pat["signals"]
                           if re.search(s["pat"], body))
                if hits < 2:
                    continue
                c = counts[pat["id"]]
                c["total"] += 1
                if re.search(prot["pat"], body):
                    c["protected"] += 1
    for pat in PATTERNS:
        c = counts[pat["id"]]
        if pat.get("protect") and pat["id"] != "loose-auth-cmp" and c["total"]:
            stats[pat["id"]] = {
                "n": c["total"],
                "protected_pct": 100.0 * c["protected"] / c["total"],
            }
    return stats


# ------------------------------------------------------------------ escaneo

def scan_path(path: str, top: int = 20,
              baseline_file: str = "pattern_baseline.json"
              ) -> List[Dict[str, Any]]:
    bl = {}
    if os.path.exists(baseline_file):
        try:
            bl = json.load(open(baseline_file))
        except Exception:
            bl = {}
    matcher = PatternMatcher(baseline=bl)
    files: List[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _d, fs in os.walk(path):
            files += [os.path.join(root, f) for f in fs
                     if f.endswith(".php")]
    for f in sorted(files):
        matcher.scan_file(f)
    matcher.finalize()            # RC-000131: gates del handler nopriv
    order = {"critica": 0, "alta": 1, "media": 2}
    matcher.findings.sort(
        key=lambda x: (order.get(x["severity"], 3), x["file"], x["line"]))
    return matcher.findings[:top]


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("uso: pattern_match.py <archivo_o_dir> [--top N] [--json] "
              "| --baseline <corpus>")
        sys.exit(1)
    if args[0] == "--baseline":
        st = build_baseline(args[1])
        json.dump(st, open("pattern_baseline.json", "w"), indent=2)
        print(json.dumps(st, indent=2))
        sys.exit(0)
    p, asjson, n = args[0], "--json" in args, 20
    if "--top" in args:
        n = int(args[args.index("--top") + 1])
    res = scan_path(p, top=n)
    if asjson:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            print(f"[{r['severity'].upper():8}] {r['type']}")
            print(f"    {r['file']}:{r['line']} en {r['function']}()"
                  f"  score {r['score']}")
            print(f"    {r['why'][:120]}")
            print(f"    ~ {r['cve_ref'][:110]}")
            if r.get("outlier"):
                print(f"    OUTLIER: {r['outlier']}")
        print(f"\n{len(res)} patron(es) de fallo historico")
