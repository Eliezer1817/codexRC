"""DECOMPILE: descompilacion parcial nivel 3 (bytecode DEX -> pseudocodigo).

REVERSE (v0.36) leyo la ESTRUCTURA (clases, metodos, strings). DECOMPILE
baja un nivel mas: abre el CODE_ITEM de cada metodo y DESensambla sus
instrucciones reales (opcode dalvik) resolviendo lo que referencian:

  const-string v0 = "AKIA..."        (strings de la tabla)
  invoke-static Lcom/sdk/Lic;->verify  (metodos por nombre y clase)
  if-eqz, goto, return...             (flujo de control)

Resultado: pseudocodigo legible de los METODOS DE LOGICA SENSIBLE
(decrypt/license/sign/verify/auth/checkout) sin ejecutar nada y sin
necesitar JRE/dex2jar (que no existen para armv7l). Un secret que
aparece como const-string dentro del flujo de un metodo se reporta
como critica "secret EN EJECUCION".

Nivel honesto: desensamblado resuelto del subset comun de dalvik
(~45 opcodes: constantes, strings, fields, invokes, saltos, retornos).
Opcoes fuera del subset se marcan y el metodo se corta ahi. No es
Java fuente 100%; es lo que un reverser lee primero.

Uso:
    python3 core/decompile.py <apk|dex> [--all] [--top N] [--json]
    POST /api/decompile {"path": "..."}                    (backend)
"""

import io
import json
import os
import re
import struct
import sys
import zipfile
from typing import Any, Dict, List

try:
    from core.re_engine import SENSITIVE_METHOD_RE
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    from core.re_engine import SENSITIVE_METHOD_RE

try:
    from core.bin_audit import SECRET_PATTERNS
except ImportError:
    from core.bin_audit import SECRET_PATTERNS


def _uleb(data: bytes, off: int) -> tuple:
    result, shift = 0, 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7f) << shift
        if not b & 0x80:
            return result, off
        shift += 7


# ------------------------------------------------- subset de opcodes dalvik
# op -> (nombre, formato)
OPS = {
    0x00: ("nop", "10x"), 0x01: ("move", "12x"), 0x02: ("move/from16", "22x"),
    0x0a: ("move-result", "11x"), 0x0c: ("move-result-object", "11x"),
    0x0d: ("move-exception", "11x"),
    0x0e: ("return-void", "10x"), 0x0f: ("return", "11x"),
    0x11: ("return-object", "11x"),
    0x12: ("const/4", "11n"), 0x13: ("const/16", "21s"),
    0x14: ("const", "31i"), 0x15: ("const/high16", "21h"),
    0x1a: ("const-string", "21c"), 0x1b: ("const-string/jumbo", "31c"),
    0x1c: ("const-class", "21c"), 0x1f: ("check-cast", "21c"),
    0x20: ("instance-of", "22c"), 0x21: ("array-length", "12x"),
    0x22: ("new-instance", "21c"), 0x23: ("new-array", "22c"),
    0x27: ("throw", "11x"),
    0x28: ("goto", "10t"), 0x29: ("goto/16", "20t"),
    0x2b: ("filled-new-array", "35c"),
    0x52: ("iget", "22c"), 0x53: ("iget-wide", "22c"),
    0x54: ("iget-object", "22c"), 0x55: ("iget-boolean", "22c"),
    0x57: ("iput", "22c"), 0x59: ("iput-object", "22c"),
    0x60: ("sget", "21c"), 0x62: ("sget-object", "21c"),
    0x67: ("sput", "21c"), 0x69: ("sput-object", "21c"),
    0x32: ("if-eq", "22t"), 0x33: ("if-ne", "22t"), 0x34: ("if-lt", "22t"),
    0x35: ("if-ge", "22t"), 0x36: ("if-gt", "22t"), 0x37: ("if-le", "22t"),
    0x38: ("if-eqz", "21t"), 0x39: ("if-nez", "21t"),
    0x3a: ("if-ltz", "21t"), 0x3d: ("if-lez", "21t"),
    0x44: ("aget", "23x"), 0x45: ("aget-wide", "23x"),
    0x46: ("aget-object", "23x"), 0x4a: ("aput", "23x"),
    0x4c: ("aput-object", "23x"),
    0x6e: ("invoke-virtual", "35c"), 0x6f: ("invoke-super", "35c"),
    0x70: ("invoke-direct", "35c"), 0x71: ("invoke-static", "35c"),
    0x72: ("invoke-interface", "35c"),
    0x74: ("invoke-virtual/range", "3rc"),
    0x77: ("invoke-static/range", "3rc"),
}


class DexLoader:
    """Carga las tablas de un .dex (header, strings, types, methods)."""

    def __init__(self, data: bytes):
        self.data = data
        (self.s_size, self.s_off, self.t_size, self.t_off,
         _ps, _po, _fs, _fo, self.m_size, self.m_off,
         self.c_size, self.c_off) = struct.unpack("<12I", data[0x38:0x68])
        self.strings = []
        for i in range(min(self.s_size, 150000)):
            o, = struct.unpack("<I", data[self.s_off + 4 * i:
                                          self.s_off + 4 * i + 4])
            _sz, p = _uleb(data, o)
            end = data.find(b"\0", p)
            self.strings.append(data[p:end].decode("utf-8", errors="replace"))
        self.types = []
        for i in range(min(self.t_size, 30000)):
            t, = struct.unpack("<I", data[self.t_off + 4 * i:
                                         self.t_off + 4 * i + 4])
            self.types.append(self.strings[t] if t < len(self.strings) else "?")
        self.methods = []          # (clase, nombre)
        for i in range(min(self.m_size, 150000)):
            c, _p, n = struct.unpack("<HHI", data[self.m_off + 8 * i:
                                                  self.m_off + 8 * i + 8])
            cls = self.types[c] if c < len(self.types) else "?"
            nm = self.strings[n] if n < len(self.strings) else "?"
            self.methods.append((cls, nm))

    def class_defs(self):
        for i in range(min(self.c_size, 20000)):
            off = self.c_off + 32 * i
            c_idx, = struct.unpack("<I", self.data[off:off + 4])
            cd_off, = struct.unpack("<I", self.data[off + 0x18:off + 0x1c])
            yield self.types[c_idx] if c_idx < len(self.types) else "?", cd_off

    def encoded_methods(self, cd_off: int):
        """class_data_item -> [(method_id, access, code_off), ...]."""
        if not cd_off:
            return []
        d = self.data
        sf, p = _uleb(d, cd_off)
        inf, p = _uleb(d, p)
        dm, p = _uleb(d, p)
        vm, p = _uleb(d, p)
        for _ in range(sf + inf):          # saltea fields
            _, p = _uleb(d, p)
            _, p = _uleb(d, p)
        out = []
        for _ in range(dm + vm):
            midx, p = _uleb(d, p)
            acc, p = _uleb(d, p)
            code_off, p = _uleb(d, p)
            out.append((midx, acc, code_off))
        return out


def decode_insns(loader: DexLoader, code_off: int,
                 max_lines: int = 60) -> List[str]:
    """Desensambla el code_item resuelviendo strings/tipos/metodos."""
    if not code_off:
        return []
    d = loader.data
    regs, ins, outs, tries = struct.unpack("<HHHH", d[code_off:code_off + 8])
    insns_size, = struct.unpack("<I", d[code_off + 12:code_off + 16])
    units = [struct.unpack("<H", d[code_off + 16 + 2 * i:
                                  code_off + 16 + 2 * i + 2])[0]
             for i in range(insns_size)]
    lines: List[str] = []
    i = 0
    while i < len(units) and len(lines) < max_lines:
        u = units[i]
        op = u & 0xFF
        hi = u >> 8
        if op not in OPS:
            lines.append(f"    {i:4}: [op 0x{op:02x} fuera del subset]")
            break
        name, fmt = OPS[op]
        if fmt == "10x":
            lines.append(f"    {i:4}: {name}")
            i += 1
        elif fmt in ("11x", "11n"):
            if name == "const/4":
                val = (hi & 0xF) - 16 if (hi & 0xF) & 8 else (hi & 0xF)
                lines.append(f"    {i:4}: v{hi >> 4} = #{val}")
            else:
                lines.append(f"    {i:4}: {name} v{hi}")
            i += 1
        elif fmt in ("12x",):
            lines.append(f"    {i:4}: {name} v{hi >> 4}, v{hi & 0xF}")
            i += 1
        elif fmt in ("21c", "21s", "21h", "21t"):
            arg = units[i + 1] if i + 1 < len(units) else 0
            if name == "const-string":
                s = loader.strings[arg] if arg < len(loader.strings) else "?"
                lines.append(f'    {i:4}: v{hi} = "{s[:70]}"')
            elif name == "new-instance":
                t = loader.types[arg] if arg < len(loader.types) else "?"
                lines.append(f"    {i:4}: v{hi} = new {t}")
            elif name in ("sget-object", "sput-object", "sget", "sput"):
                lines.append(f"    {i:4}: {name} v{hi}, field@{arg}")
            elif fmt == "21t":
                tgt = i + (arg - 0x10000 if arg >= 0x8000 else arg)
                lines.append(f"    {i:4}: {name} v{hi}, ->{tgt:d}")
            elif fmt == "21s":
                sval = arg - 0x10000 if arg >= 0x8000 else arg
                lines.append(f"    {i:4}: v{hi} = #{sval}")
            else:
                lines.append(f"    {i:4}: {name} v{hi}, @{arg}")
            i += 2
        elif fmt in ("22c", "22t", "23x"):
            arg = units[i + 1] if i + 1 < len(units) else 0
            if fmt == "22t":
                lines.append(f"    {i:4}: {name} v{hi >> 4}, v{hi & 0xF}, "
                             f"->{i + (arg - 0x10000 if arg >= 0x8000 else arg):d}")
            elif fmt == "23x":
                lines.append(f"    {i:4}: {name} v{hi}, v{arg >> 8}, "
                             f"v{arg & 0xFF}")
            else:
                lines.append(f"    {i:4}: {name} v{hi >> 4} = "
                             f"[v{hi & 0xF}][field@{arg}]")
            i += 2
        elif fmt in ("31i", "31c"):
            b2 = units[i + 1] if i + 1 < len(units) else 0
            b3 = units[i + 2] if i + 2 < len(units) else 0
            arg = b2 | (b3 << 16)
            if name in ("const-string/jumbo",):
                s = loader.strings[arg] if arg < len(loader.strings) else "?"
                lines.append(f'    {i:4}: v{hi} = "{s[:70]}"')
            else:
                sval = arg - 0x100000000 if arg >= 0x80000000 else arg
                lines.append(f"    {i:4}: v{hi} = #{sval} (0x{arg:x})")
            i += 3
        elif fmt in ("35c",):
            b2 = units[i + 1] if i + 1 < len(units) else 0
            b3 = units[i + 2] if i + 2 < len(units) else 0
            count = hi >> 4
            regs_ = [b3 & 0xF, (b3 >> 4) & 0xF, (b3 >> 8) & 0xF,
                     (b3 >> 12) & 0xF, hi & 0xF][:count]
            if b2 < len(loader.methods):
                cls, nm = loader.methods[b2]
                lines.append(f"    {i:4}: {name} "
                             f"{cls}->{nm}({', '.join('v%d' % r for r in regs_)})")
            else:
                lines.append(f"    {i:4}: {name} method@{b2}")
            i += 3
        elif fmt in ("3rc", "20t"):
            b2 = units[i + 1] if i + 1 < len(units) else 0
            b3 = units[i + 2] if i + 2 < len(units) else 0
            if fmt == "20t":
                tgt = i + (b2 - 0x10000 if b2 >= 0x8000 else b2)
                lines.append(f"    {i:4}: {name} ->{tgt:d}")
                i += 2
            else:
                if b2 < len(loader.methods):
                    cls, nm = loader.methods[b2]
                    lines.append(f"    {i:4}: {name} {cls}->{nm}(v{b3}..)")
                else:
                    lines.append(f"    {i:4}: {name} method@{b2}")
                i += 3
        elif fmt == "10t":
            tgt = i + (hi - 0x100 if hi >= 0x80 else hi)
            lines.append(f"    {i:4}: {name} ->{tgt:d}")
            i += 1
        else:
            lines.append(f"    {i:4}: {name}")
            i += 1
    if i < len(units) and len(lines) >= max_lines:
        lines.append(f"    ... (truncado, quedan {len(units) - i} unidades)")
    return lines


def decompile_dex(data: bytes, rel: str, all_methods: bool = False) -> list:
    out: List[Dict[str, Any]] = []
    if data[:4] != b"dex\n":
        return out
    try:
        loader = DexLoader(data)
    except Exception:
        return out
    for cls, cd_off in loader.class_defs():
        for midx, _acc, code_off in loader.encoded_methods(cd_off):
            if midx >= len(loader.methods):
                continue
            mcls, mname = loader.methods[midx]
            if not all_methods and not SENSITIVE_METHOD_RE.search(mname):
                continue
            lines = decode_insns(loader, code_off)
            if not lines:
                continue
            body = "\n".join(lines)
            out.append({
                "type": "RE: PSEUDOCODIGO DE METODO", "severity": "media",
                "file": rel, "location": f"{cls}->{mname}",
                "evidence": f"{mcls}->{mname}()\n" + body,
                "verdict": "bytecode desensamblado a pseudocodigo legible"})
            # secrets que aparecen en el FLUJO del metodo (const-string)
            for line in lines:
                m = re.search(r'= "([^"]{6,})"', line)
                if m:
                    for sname, pat, sev in SECRET_PATTERNS:
                        if re.search(pat, m.group(1)):
                            out.append({
                                "type": f"RE: SECRET EN EJECUCION: {sname}",
                                "severity": sev, "file": rel,
                                "location": f"{cls}->{mname}",
                                "evidence": m.group(1)[:120],
                                "verdict": "secret asignado como constante "
                                           "dentro del flujo del metodo"})
    return out


def decompile_artifact(data: bytes, rel: str, all_m: bool = False,
                       depth: int = 0) -> list:
    out: list = []
    if depth > 2 or len(data) > 100 * 1024 * 1024:
        return out
    if data[:4] == b"dex\n":
        return decompile_dex(data, rel, all_m)
    if data[:2] == b"PK":
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
                out += decompile_dex(blob, inner, all_m)
            elif fn.endswith((".apk", ".jar", ".zip")):
                out += decompile_artifact(blob, inner, all_m, depth + 1)
    return out


def decompile_path(path: str, all_methods: bool = False,
                   top: int = 25) -> list:
    try:
        data = open(path, "rb").read()
    except Exception:
        return []
    out = decompile_artifact(data, path, all_methods)
    order = {"critica": 0, "alta": 1, "media": 2, "info": 3}
    out.sort(key=lambda x: (order.get(x["severity"], 4), x["file"]))
    seen, res = set(), []
    for f in out:
        key = (f["type"], f["location"], f["evidence"][:60])
        if key not in seen:
            seen.add(key)
            res.append(f)
    return res[:top]


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("uso: decompile.py <apk|dex> [--all] [--top N] [--json]")
        sys.exit(1)
    p, asjson, n = args[0], "--json" in args, 25
    if "--top" in args:
        n = int(args[args.index("--top") + 1])
    res = decompile_path(p, all_methods="--all" in args, top=n)
    if asjson:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            mark = " 💥" if r["severity"] == "critica" else ""
            print(f"[{r['severity'].upper():8}] {r['type']}{mark}")
            print(f"    {r['file'][:70]} :: {r['location']}")
            print(r["evidence"][:400])
            print()
        print(f"{len(res)} metodo(s) descompilado(s)")
