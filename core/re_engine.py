"""REVERSE: ingenieria inversa nivel 2 (sobre BIN-AUDIT).

Mientras BIN-AUDIT extrae la superficie (secrets, endpoints, imports),
REVERSE abre los formatos y lee la ESTRUCTURA interna del artefacto:

  DEX (APK/Android)   parse REAL del formato DEX: string_ids, type_ids,
   method_ids y class_defs con uleb128. Lista clases, metodos y todas
   las strings del bytecode → se les pasa el detector de secrets y
   endpoints de BIN-AUDIT. Detecta app OFUSCADA (nombres a/b/c estilo
   ProGuard/R8) y metodos con keywords de logica sensible
   (decrypt/license/sign/verify/token).

  CLASS (JAR/Java)    parse del constant pool del .class (CAFEBABE):
   nombre de la clase, superclase y todas las constantes Utf8 →
   secrets y referencias internas.

  ELF (nativo)        tabla de simbolos INTERNA (.symtab, no solo
   .dynsym): nombres de funciones estaticas que revelan como se
   organiza la logica (verify_*, decrypt_*, handle_*). Detecta binario
   STRIPPED, secciones .debug_* y ENTROPIA por seccion: una seccion
   ejecutable con entropia > 7.0 = empaquetado/ofuscado (UPX-like).

Nivel honesto: parse de formatos + simbolos + entropia. Desensamblado
de instrucciones queda como etapa futura (necesita binutils en el
dispositivo); esto ya revela la logica sin ejecutar nada.

Uso:
    python3 core/re_engine.py <archivo_o_dir> [--json] [--top N]
    POST /api/re {"path": "..."}                        (backend)
"""

import io
import json
import math
import os
import re
import struct
import sys
import zipfile
from typing import Any, Dict, List

try:
    from core.bin_audit import SECRET_PATTERNS
except ImportError:                        # corrida como script desde core/
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    from core.bin_audit import SECRET_PATTERNS

# ------------------------------------------------------------------ utilidades

SENSITIVE_METHOD_RE = re.compile(
    r"(?:decrypt|encrypt|license|activat|sign|verif|token|auth|login|"
    r"password|passwd|secret|api[_-]?key|checkout|payment|jwt)", re.I)


def _uleb128(data: bytes, off: int) -> tuple:
    """Uleb128 de DEX: devuelve (valor, nuevo_offset)."""
    result, shift = 0, 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7f) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def _entropy(data: bytes) -> float:
    """Bits de entropia por byte (0 = uniforme, 8 = aleatorio puro)."""
    if not data:
        return 0.0
    sample = data[:65536]
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    n = len(sample)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# ------------------------------------------------------------------------ DEX

def parse_dex(data: bytes, rel: str) -> List[Dict[str, Any]]:
    """Parse real de un .dex: strings, clases, metodos."""
    out: List[Dict[str, Any]] = []
    if data[:4] != b"dex\n":
        return out
    try:
        (string_size, string_off, type_size, type_off,
         _p_size, _p_off, _f_size, _f_off,
         method_size, method_off, class_size, class_off) = struct.unpack(
            "<12I", data[0x38:0x68])
    except Exception:
        return out
    # strings
    strings: List[str] = []
    for i in range(min(string_size, 20000)):
        s_off, = struct.unpack("<I", data[string_off + 4 * i:
                                         string_off + 4 * i + 4])
        try:
            _size, p = _uleb128(data, s_off)
            end = data.find(b"\0", p)
            strings.append(data[p:end].decode("utf-8", errors="replace"))
        except Exception:
            pass
    # types
    types = []
    for i in range(min(type_size, 5000)):
        t, = struct.unpack("<I", data[type_off + 4 * i:type_off + 4 * i + 4])
        types.append(strings[t] if t < len(strings) else "?")
    # methods (class_idx, proto_idx, name_idx)
    methods = []
    for i in range(min(method_size, 20000)):
        c_idx, p_idx, n_idx = struct.unpack(
            "<HHI", data[method_off + 8 * i:method_off + 8 * i + 8])
        cname = types[c_idx] if c_idx < len(types) else "?"
        mname = strings[n_idx] if n_idx < len(strings) else "?"
        methods.append((cname, mname))
    # class_defs
    classes = []
    for i in range(min(class_size, 5000)):
        c_idx, = struct.unpack("<I", data[class_off + 32 * i:
                                           class_off + 32 * i + 4])
        classes.append(types[c_idx] if c_idx < len(types) else "?")

    out.append({"type": "RE: APP ANDROID (DEX)", "severity": "info",
                "file": rel, "location": "header",
                "evidence": f"{len(classes)} clases, {len(methods)} metodos, "
                            f"{len(strings)} strings extraidas del bytecode",
                "verdict": "estructura interna del APK revelada"})
    # ofuscacion: proporcion de clases de 1-2 caracteres (a/b/c)
    short = sum(1 for c in classes
                if re.fullmatch(r"L[a-zA-Z]{1,2};", c))
    if classes and short / len(classes) > 0.5:
        out.append({"type": "RE: APP OFUSCADA", "severity": "media",
                    "file": rel, "location": "class_defs",
                    "evidence": f"{short}/{len(classes)} clases con nombres "
                                "de 1-2 letras (ProGuard/R8 renombro la app)",
                    "verdict": "logica deliberadamente oculta"})
    # metodos de logica sensible
    sens = sorted({f"{m}" for c, m in methods if SENSITIVE_METHOD_RE.search(m)})
    if sens:
        out.append({"type": "RE: METODOS DE LOGICA SENSIBLE", "severity":
                    "media", "file": rel, "location": "method_ids",
                    "evidence": ", ".join(sens[:25]),
                    "verdict": "metodos que manejan crypto/licencias/auth"})
    # secrets en las strings del bytecode
    for name, pat, sev in SECRET_PATTERNS:
        blob = "\n".join(strings)
        for m in re.findall(pat, blob)[:4]:
            if isinstance(m, tuple):
                m = m[0]
            out.append({"type": f"RE: SECRET: {name}", "severity": sev,
                        "file": rel, "location": "string_ids",
                        "evidence": m, "verdict":
                        "extraido del bytecode DEX (re)"})
    urls = sorted({u for s in strings
                   for u in re.findall(r"(?:https?|wss?)://[^\s'\"<>]+", s)})
    if urls:
        out.append({"type": "RE: ENDPOINTS EN BYTECODE", "severity": "alta",
                     "file": rel, "location": "string_ids",
                     "evidence": " ".join(urls[:10]),
                     "verdict": "rutas internas de la app"})
    return out


# ---------------------------------------------------------------------- CLASS

def parse_class_file(data: bytes, rel: str) -> List[Dict[str, Any]]:
    """Parse del constant pool de un .class (CAFEBABE)."""
    out: List[Dict[str, Any]] = []
    if data[:4] != b"\xca\xfe\xba\xbe":
        return out
    try:
        cp_count, = struct.unpack(">H", data[8:10])
        off = 10
        utf8s: List[str] = []
        class_idx = {}
        i = 1
        while i < cp_count:
            tag = data[off]
            off += 1
            if tag == 1:
                ln, = struct.unpack(">H", data[off:off + 2])
                off += 2
                utf8s.append(data[off:off + ln].decode(
                    "utf-8", errors="replace"))
                off += ln
            elif tag in (3, 4):
                off += 4
            elif tag in (5, 6):
                off += 8
                i += 1                      # long/double ocupan 2 slots
            elif tag in (7, 8, 16, 19, 20):
                if tag == 7:
                    class_idx[i] = off       # guarda offset del idx
                off += 2
            elif tag in (9, 10, 11, 12, 17, 18):
                off += 4
            elif tag == 15:
                off += 3
            else:
                return out                   # tag raro: aborta seguro
            i += 1
        this_class, = struct.unpack(">H", data[off + 4:off + 6])
        # resuelve el nombre de la clase por el indice en el pool
        name = utf8s[this_class - 1] if 0 < this_class <= len(utf8s) else "?"
        out.append({"type": "RE: CLASE JAVA", "severity": "info",
                    "file": rel, "location": "constant pool",
                    "evidence": f"{name} · {len(utf8s)} constantes Utf8 "
                                "extraidas",
                    "verdict": "estructura de la clase revelada"})
        for name2, pat, sev in SECRET_PATTERNS:
            blob = "\n".join(utf8s)
            for m in re.findall(pat, blob)[:3]:
                if isinstance(m, tuple):
                    m = m[0]
                out.append({"type": f"RE: SECRET: {name2}", "severity": sev,
                            "file": rel, "location": "constant pool",
                            "evidence": m,
                            "verdict": "extraido del bytecode Java (re)"})
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------- ELF

def parse_elf_deep(data: bytes, rel: str) -> List[Dict[str, Any]]:
    """Symtab interna, secciones debug, stripped y entropia por seccion."""
    out: List[Dict[str, Any]] = []
    if data[:4] != b"\x7fELF":
        return out
    end = ">" if data[5] == 2 else "<"
    is64 = data[4] == 2
    try:
        e_shoff, = struct.unpack(end + ("Q" if is64 else "I"),
                                  data[0x28:0x30] if is64 else
                                  data[0x20:0x24])
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(
            end + "HHH",
            data[0x3a:0x40] if is64 else data[0x2e:0x34])
    except Exception:
        return out

    def sh(i):
        o = e_shoff + i * e_shentsize
        if is64:
            nm, typ = struct.unpack(end + "II", data[o:o + 8])
            lnk, = struct.unpack(end + "I", data[o + 0x28:o + 0x2c])
            off, size = struct.unpack(end + "QQ", data[o + 0x18:o + 0x28])
        else:
            nm, typ = struct.unpack(end + "II", data[o:o + 8])
            lnk, = struct.unpack(end + "I", data[o + 0x18:o + 0x1c])
            off, size = struct.unpack(end + "II", data[o + 0x10:o + 0x18])
        return nm, typ, lnk, off, size

    try:
        _, _, _, strtab_off, strtab_size = sh(e_shstrndx)
        shstr = data[strtab_off:strtab_off + strtab_size]
    except Exception:
        return out

    def name_of(nm):
        b = shstr[nm:shstr.find(b"\0", nm)]
        return b.decode("latin1", errors="replace")

    syms: List[str] = []
    has_debug = False
    packed: List[str] = []
    for i in range(e_shnum):
        nm, typ, lnk, off, size = sh(i)
        sname = name_of(nm)
        if sname.startswith(".debug"):
            has_debug = True
        if typ == 2:                       # SHT_SYMTAB
            stro, strsz = sh(lnk)[3], sh(lnk)[4]
            strtab = data[stro:stro + strsz]
            ent = 24 if is64 else 16
            for j in range(size // ent):
                st_name, = struct.unpack(end + "I",
                                          data[off + j * ent:off + j * ent + 4])
                b = strtab[st_name:strtab.find(b"\0", st_name)]
                if b and re.match(rb"[A-Za-z_]", b):
                    syms.append(b.decode("latin1"))
        # entropia de secciones ejecutables / grandes
        if size > 4096 and (typ in (1, 8, 11)):   # PROGBITS, NOBITS excluido
            ent = _entropy(data[off:off + size])
            if ent > 7.2:
                packed.append(f"{sname}={ent:.2f}")

    if not syms:
        out.append({"type": "RE: BINARIO STRIPPED", "severity": "info",
                    "file": rel, "location": ".symtab",
                    "evidence": "sin tabla de simbolos internos "
                    "(solo .dynsym publico)",
                    "verdict": "logica de nombres removida por el vendor"})
    else:
        sens = sorted({s for s in syms if SENSITIVE_METHOD_RE.search(s)})
        out.append({"type": "RE: SIMBOLOS INTERNOS", "severity": "media",
                    "file": rel, "location": ".symtab",
                    "evidence": f"{len(syms)} funciones internas; "
                    f"logica sensible: {', '.join(sens[:20]) or 'ninguna'}",
                    "verdict": "nombres estaticos revelan la organizacion"})
    if has_debug:
        out.append({"type": "RE: SIMBOLOS DEBUG PRESENTES", "severity":
                    "media", "file": rel, "location": ".debug_*",
                    "evidence": "secciones .debug_* sin limpiar: el binario "
                    "trae info de compilacion completa",
                    "verdict": "filtracion de informacion interna"})
    if packed:
        out.append({"type": "RE: SECCION EMPAQUETADA/OBFUSCADA", "severity":
                    "media", "file": rel, "location": "entropia",
                    "evidence": " ".join(packed),
                    "verdict": "entropia > 7.2 bits/byte: codigo comprimido "
                    "u ofuscado (UPX-like)"})
    return out


# -------------------------------------------------------------------- nucleo

def _fingerprint_quick(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"PK":
        return "zip"
    return "?"


def analyze_artifact(data: bytes, rel: str, depth: int = 0) -> list:
    out: List[Dict[str, Any]] = []
    if depth > 2 or len(data) > 100 * 1024 * 1024:
        return out
    kind = _fingerprint_quick(data)
    if kind == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return out
        for info in zf.infolist()[:600]:
            if info.is_dir():
                continue
            inner = rel + "!" + info.filename
            try:
                blob = zf.read(info)
            except Exception:
                continue
            fn = info.filename.lower()
            if fn.endswith(".dex"):
                out += parse_dex(blob, inner)
            elif fn.endswith(".class"):
                out += parse_class_file(blob, inner)
            elif fn.endswith((".so", ".bin", ".o")):
                out += analyze_artifact(blob, inner, depth + 1)
            elif fn.endswith((".jar", ".zip", ".apk")):
                out += analyze_artifact(blob, inner, depth + 1)
    elif kind == "elf":
        out += parse_elf_deep(data, rel)
    return out


def analyze_path(path: str, top: int = 30) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if os.path.isfile(path):
        try:
            findings = analyze_artifact(open(path, "rb").read(), path)
        except Exception:
            pass
    else:
        for root, _d, fs in os.walk(path):
            for f in sorted(fs):
                fp = os.path.join(root, f)
                try:
                    if os.path.getsize(fp) > 100 * 1024 * 1024:
                        continue
                    findings += analyze_artifact(open(fp, "rb").read(), fp)
                except Exception:
                    continue
    order = {"critica": 0, "alta": 1, "media": 2, "info": 3}
    findings.sort(key=lambda x: (order.get(x["severity"], 4), x["file"]))
    seen, out = set(), []
    for f in findings:
        key = (f["type"], f["file"], f["evidence"][:70])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:top]


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("uso: re_engine.py <archivo_o_dir> [--json] [--top N]")
        sys.exit(1)
    p, asjson, n = args[0], "--json" in args, 30
    if "--top" in args:
        n = int(args[args.index("--top") + 1])
    res = analyze_path(p, top=n)
    if asjson:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            mark = " 💥" if r["severity"] == "critica" else ""
            print(f"[{r['severity'].upper():8}] {r['type']}{mark}")
            print(f"    {r['file'][:90]} ({r['location']})")
            print(f"    {r['evidence'][:110]}")
        print(f"\n{len(res)} hallazgo(s) de ingenieria inversa")
