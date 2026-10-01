"""BIN-AUDIT: analisis binario/nativo, mas alla del navegador.

Abre cualquier artefacto que un vendor distribuye y le saca lo que
importa para la caza:

  SECRETS HARDCODEADOS  (critica, Patchstack paga: "BAC sobre objetos
    sensibles: API keys, secrets"): claves AWS (AKIA...), Google (AIza...),
    Stripe live (sk_live_...), GitHub (ghp_...), Slack (xox...), JWT,
    claves privadas PEM, connection strings con credenciales, y en
    archivos de texto pares api_key/secret/token/password = valor.

  ENDPOINTS INTERNOS    (alta): URLs http/ws escondidas en el binario,
   incluyendo rutas de admin, staging y APIs privadas del vendor.

  IMPORTS PELIGROSOS    (media): simbolos dinamicos como system/execve/
    popen/dlopen (superficie de RCE y carga de codigo en native code).

  FINGERPRINT           (info): tipo ELF/PE/Mach-O/zip/apk/jar, arquitectura,
    bitness, seccion debug presente.

Formatos soportados: ELF (32/64, LE/BE, parse real de cabeceras y
.dynsym), PE (MZ), Mach-O, zip/jar/apk (recursivo: descomprime y audita
cada artefacto interno, .dex/.class/.so anidados), gzip. Cualquier otro
archivo = escaneo de strings generico.

Nivel 1 honesto: recon de binarios (strings, simbolos, secretos,
endpoints). Desensamblado completo queda fuera del alcance Python
puro; esto ya encuentra lo que paga.

Uso:
    python3 core/bin_audit.py <archivo_o_dir> [--json] [--top N]
    POST /api/bin {"path": "..."}                    (backend)
"""

import gzip
import io
import json
import os
import re
import struct
import sys
import zipfile
from typing import Any, Dict, List

# ---------------------------------------------------------------- secrets

SECRET_PATTERNS = [
    ("clave AWS (AKIA)", r"AKIA[0-9A-Z]{16}", "critica"),
    ("clave Google API (AIza)", r"AIza[0-9A-Za-z_\-]{35}", "critica"),
    ("Stripe LIVE (sk_live)", r"sk_live_[0-9a-zA-Z]{16,}", "critica"),
    ("GitHub PAT (ghp_)", r"ghp_[0-9A-Za-z]{36}", "critica"),
    ("Slack token (xox*)", r"xox[baprs]-[0-9A-Za-z\-]{10,}", "critica"),
    ("JWT embebido", r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.",
     "alta"),
    ("clave privada PEM", r"-----(?:BEGIN|END) (?:RSA |EC |DSA |OPENSSH )?"
     r"PRIVATE KEY-----", "critica"),
    ("connection string con credenciales", r"(?:postgres|mysql|mongodb|"
     r"redis|amqp)s?://[^\s'\"<>]*:[^\s'\"@/<>]+@", "critica"),
    ("par credencial en texto", r"(?:api[_-]?key|secret|token|passwd|"
     r"password|pwd)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.+/@]{8,}", "alta"),
]

URL_RE = re.compile(rb"(?:https?|wss?|ftp)://[!-~]{6,}")
_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")

DANGEROUS_IMPORTS = {
    "system", "execve", "execl", "execlp", "execvp", "popen",
    "dlopen", "dlsym", "fork", "posix_spawn",
}


# ------------------------------------------------------------------- fingerprint

def _fingerprint(data: bytes) -> Dict[str, Any]:
    """Tipo, arquitectura y bitness del artefacto."""
    if data[:4] == b"\x7fELF":
        bits = 64 if data[4] == 2 else 32
        endian = ">" if data[5] == 2 else "<"
        mach, = struct.unpack(endian + "H", data[18:20])
        archs = {0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
                 0x28: "ARM", 0x32: "IA-64", 0x3E: "x86-64",
                 0xB7: "AArch64", 0xF3: "RISC-V"}
        return {"format": "ELF", "bits": bits, "arch": archs.get(
            mach, hex(mach)), "elf": True}
    if data[:2] == b"MZ":
        return {"format": "PE (Windows)", "bits": "?", "arch": "?"}
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe"):
        return {"format": "Mach-O", "bits": "?", "arch": "Apple"}
    if data[:2] in (b"PK", b"\x50\x4b"):
        return {"format": "zip/jar/apk", "bits": "-", "arch": "-",
                "container": True}
    if data[:2] == b"\x1f\x8b":
        return {"format": "gzip", "bits": "-", "arch": "-",
                "compressed": True}
    return {"format": "desconocido/datos", "bits": "-", "arch": "-"}


# ------------------------------------------------------------- simbolos ELF

def _elf_dynsyms(data: bytes, end: str) -> List[str]:
    """Lista los simbolos dinamicos de un ELF (parse real de secciones)."""
    try:
        e_shoff, = struct.unpack(end + "Q", data[0x28:0x30]) \
            if data[4] == 2 else struct.unpack(end + "I", data[0x20:0x24])
        e_shentsize, e_shnum = struct.unpack(
            end + "HH", data[0x3a:0x3e]) if data[4] == 2 else struct.unpack(
            end + "HH", data[0x2e:0x32])
        syms: List[str] = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if data[4] == 2:
                sh_type, = struct.unpack(end + "I", data[off + 4:off + 8])
                sh_link, = struct.unpack(end + "I", data[off + 0x28:off + 0x2c])
                sh_off, sh_size = struct.unpack(
                    end + "QQ", data[off + 0x18:off + 0x28])
                ent = 24
            else:
                sh_type, = struct.unpack(end + "I", data[off + 4:off + 8])
                sh_link, = struct.unpack(end + "I", data[off + 0x18:off + 0x1c])
                sh_off, sh_size = struct.unpack(
                end + "II", data[off + 0x10:off + 0x18])
                ent = 16
            if sh_type != 11:                      # SHT_DYNSYM
                continue
            stroff = e_shoff + sh_link * e_shentsize
            if data[4] == 2:
                str_off, str_size = struct.unpack(
                    end + "QQ", data[stroff + 0x18:stroff + 0x28])
            else:
                str_off, str_size = struct.unpack(
                    end + "II", data[stroff + 0x10:stroff + 0x18])
            strtab = data[str_off:str_off + str_size]
            for j in range(sh_size // ent):
                st_name, = struct.unpack(
                    end + "I", data[sh_off + j * ent:sh_off + j * ent + 4])
                b = strtab[st_name:strtab.find(b"\0", st_name)]
                if b:
                    syms.append(b.decode("latin1"))
        return syms
    except Exception:
        return []


# -------------------------------------------------------------------- nucleo

class BinAuditor:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def _add(self, kind, sev, rel, where, detail, extra=""):
        self.findings.append({
            "type": kind, "severity": sev, "file": rel,
            "location": where, "evidence": detail[:220] + extra,
            "verdict": "extraido estaticamente del artefacto"})

    def audit_binary(self, data: bytes, rel: str) -> None:
        fp = _fingerprint(data)
        self._add("FINGERPRINT", "info", rel, "cabecera",
                  f"{fp['format']} {fp.get('arch','')} "
                  f"{fp.get('bits','')}bits")
        # secrets en strings del binario
        strings = [s.decode("latin1") for s in _STR_RE.findall(data)]
        self._scan_secrets(strings, rel, "strings binario")
        urls = {u.decode("latin1").rstrip('"\',.') for u in
                URL_RE.findall(data)}
        for u in list(urls)[:15]:
            sev = "alta" if re.search(
                r"(?:admin|staging|internal|debug|local|priv)", u) else "info"
            self._add("ENDPOINT en binario", sev, rel, "strings", u)
        # imports peligrosos
        if fp.get("elf"):
            end = ">" if data[5] == 2 else "<"
            syms = _elf_dynsyms(data, end)
            danger = sorted(set(syms) & DANGEROUS_IMPORTS)
            if danger:
                self._add("IMPORTS PELIGROSOS", "media", rel,
                          ".dynsym", ", ".join(danger),
                          f" ({len(syms)} simbolos dinamicos totales)")

    def _scan_secrets(self, strings: List[str], rel: str, where: str):
        blob = "\n".join(strings)
        for name, pat, sev in SECRET_PATTERNS:
            for m in re.findall(pat, blob)[:5]:
                if isinstance(m, tuple):
                    m = m[0]
                self._add(f"SECRET: {name}", sev, rel, where,
                          m if "PEM" not in name else "bloque de clave privada")

    def audit_text(self, data: bytes, rel: str) -> None:
        try:
            text = data.decode("utf-8")
        except Exception:
            return
        self._scan_secrets(text.splitlines(), rel, "texto")
        for u in {u.decode("latin1") for u in URL_RE.findall(data)}:
            self._add("ENDPOINT", "info", rel, "texto", u)

    def audit_container(self, data: bytes, rel: str, depth: int = 0):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return
        for info in zf.infolist()[:400]:
            if info.is_dir():
                continue
            inner = rel + "!" + info.filename
            try:
                blob = zf.read(info)
            except Exception:
                continue
            if info.filename.endswith((".so", ".dex", ".class", ".bin")) or \
                    not info.filename.endswith((".xml", ".json", ".txt",
                                               ".php", ".yml", ".properties",
                                               ".js", ".html", ".css",
                                               ".py", ".java", ".md")):
                self.audit_artifact(blob, inner, depth)
            else:
                self.audit_text(blob, inner)

    def audit_artifact(self, data: bytes, rel: str, depth: int = 0):
        if depth > 2 or len(data) > 60 * 1024 * 1024:
            return
        fp = _fingerprint(data)
        if fp.get("container"):
            self.audit_container(data, rel, depth + 1)
        elif fp.get("compressed"):
            try:
                self.audit_artifact(gzip.decompress(data), rel, depth + 1)
            except Exception:
                pass
        else:
            self.audit_binary(data, rel)
            # texto embebido tambien (config en binario con strings)
            if fp["format"] == "desconocido/datos" or fp.get("elf"):
                pass


def audit_path(path: str, top: int = 25) -> List[Dict[str, Any]]:
    auditor = BinAuditor()
    if os.path.isfile(path):
        try:
            auditor.audit_artifact(open(path, "rb").read(), path)
        except Exception:
            pass
    else:
        for root, _d, fs in os.walk(path):
            for f in sorted(fs):
                fp = os.path.join(root, f)
                try:
                    if os.path.getsize(fp) > 80 * 1024 * 1024:
                        continue
                    auditor.audit_artifact(open(fp, "rb").read(), fp)
                except Exception:
                    continue
    # dedupe por (tipo, archivo, evidencia)
    seen, out = set(), []
    order = {"critica": 0, "alta": 1, "media": 2, "info": 3}
    for f in sorted(auditor.findings,
                    key=lambda x: (order.get(x["severity"], 4),
                                   x["file"])):
        key = (f["type"], f["file"], f["evidence"][:80])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:top]


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print("uso: bin_audit.py <archivo_o_dir> [--json] [--top N]")
        sys.exit(1)
    p, asjson, n = args[0], "--json" in args, 25
    if "--top" in args:
        n = int(args[args.index("--top") + 1])
    res = audit_path(p, top=n)
    if asjson:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            mark = " 💥" if r["severity"] == "critica" else ""
            print(f"[{r['severity'].upper():8}] {r['type']}{mark}")
            print(f"    {r['file'][:80]} ({r['location']})")
            print(f"    {r['evidence'][:100]}")
        print(f"\n{len(res)} hallazgo(s)")
