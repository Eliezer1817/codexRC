"""Reportes exportables del Hunter: TXT, JSON y PDF.

PDF de alta calidad: se arma un documento HTML+CSS y se imprime con el
navegador real en modo headless (Chrome/Chromium/Edge, la misma deteccion
multiplataforma que usa VERITAS). Si no hay navegador disponible, fallback
a fpdf2 (python puro, `pip install fpdf2`, funciona en Termux/armv7l).

Orden del informe (regla del operador): filtraciones de datos de usuarios
ARRIBA y en rojo; hallazgos tecnicos abajo por severidad.
"""

import html
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEV_COLORS = {"alta": "#e11d48", "media": "#f59e0b",
              "baja": "#64748b", "info": "#475569"}
SEV_ORDER = {"alta": 0, "media": 1, "baja": 2, "info": 3}


def _ver(job: Dict[str, Any]) -> str:
    return job.get("version") or "?"


def summarize(job: Dict[str, Any]) -> Dict[str, Any]:
    fs = job.get("findings") or []
    return {
        "total": len(fs),
        "alta": len([f for f in fs if f.get("severity") == "alta"]),
        "media": len([f for f in fs if f.get("severity") == "media"]),
        "baja": len([f for f in fs if f.get("severity") == "baja"]),
        "info": len([f for f in fs if f.get("severity") == "info"]),
        "leaks": len([f for f in fs if f.get("leak")]),
        "verificados": len([f for f in fs if f.get("verificado")]),
        "descartados_fp": len([f for f in fs if f.get("descartado_fp")]),
    }


# --------------------------------------------- verificacion del sistema ----
# El sistema verifica solo en vivo lo que puede verificar; el informe
# muestra el VEREDICTO automatico de cada hallazgo. Sin comandos: nada
# que el operador tenga que ejecutar a mano.


def _veredicto_de(f: Dict[str, Any]) -> Dict[str, str]:
    if f.get("descartado_fp"):
        estado = "DESCARTADO POR EL SISTEMA (falso positivo)"
    elif f.get("verificado"):
        estado = "VERIFICADO EN VIVO POR EL SISTEMA"
    else:
        estado = "PENDIENTE (no verificable en automatico)"
    det = (f.get("verdict") or f.get("evidence")
           or f.get("reason") or "")[:300]
    como = f.get("auto_check") or ("cabecera respuesta analizada en vivo"
                                  if "csp" in (f.get("type") or "").lower() else "")
    return {"estado": estado, "detalle": det, "como": como}


def auto_verification(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in job.get("findings") or []:
        v = _veredicto_de(f)
        if v["estado"].startswith("PENDIENTE") and not v["detalle"]:
            continue
        out.append({
            "hallazgo": f.get("type"),
            "severidad": f.get("severity"),
            "target": f.get("target"),
            "estado": v["estado"],
            "como_verifico": v["como"],
            "detalle": v["detalle"],
        })
    return out


def _leaks(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [f for f in (job.get("findings") or []) if f.get("leak")]


def _tech(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    return sorted([f for f in (job.get("findings") or []) if not f.get("leak")],
                  key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                 f.get("type", "")))


def build_json(job: Dict[str, Any]) -> str:
    out = dict(job)
    out["leaks"] = _leaks(job)
    out["tech_findings"] = _tech(job)
    out["export_summary"] = summarize(job)
    out["verificacion_automatica"] = auto_verification(job)
    return json.dumps(out, indent=2, ensure_ascii=False, default=str)


def build_txt(job: Dict[str, Any]) -> str:
    s = summarize(job)
    L: List[str] = []
    bar = "=" * 64
    sub = "-" * 64
    L.append(bar)
    L.append(" CODEXRC HUNTER  ·  INFORME DE CAZA")
    L.append(bar)
    L.append(f" Version   : {_ver(job)}")
    L.append(f" Objetivo  : {job.get('url', '?')}")
    L.append(f" Estado    : {job.get('status', '?')}")
    L.append(f" Fecha     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    L.append("")
    L.append(f" RESUMEN: {s['total']} hallazgos · {s['alta']} altos · "
             f"{s['media']} medios · {s['baja']} bajos · {s['info']} info")
    L.append(f" Verificados en navegador real (VERITAS): {s['verificados']}")
    L.append(f" Falsos positivos descartados            : {s['descartados_fp']}")
    L.append(bar)

    leaks = _leaks(job)
    if leaks:
        L.append("")
        L.append(" !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        L.append(" !!  FILTRACION DE DATOS DE USUARIOS - CRITICO  !!")
        L.append(" !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        for f in leaks:
            fields = ", ".join(f.get("leak_fields") or []) or "?"
            ident = f.get("leak_identity") or "?"
            L.append(f" [LEAK] {f.get('type', '?')} · campos: {fields} · identidad: {ident}")
            L.append(f"        blanco: {f.get('target', '?')}")
            L.append(f"        razon : {f.get('reason', '')[:150]}")

    chains = (job.get("results", {}).get("chain", {})
              .get("data", {}).get("chains", []))
    if chains:
        L.append("")
        L.append(" !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        L.append(" !!  CADENAS DE IMPACTO COMBINADO - CRITICO        !!")
        L.append(" !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        for c in chains:
            L.append(f" [CADENA] {c.get('name', '?')} · severidad: {c.get('severity', '?').upper()}")
            L.append(f"          piezas: {', '.join(c.get('parts', []))}")
            L.append(f"          porque: {c.get('reason', '')[:150]}")

    esc = (job.get("results", {}).get("escalada", {})
           .get("data", {}).get("escalations", []))
    if esc:
        L.append("")
        L.append(" ================================================================")
        L.append("  ESCALADA - QUE HACER DESPUES DEL AVISO (paso a paso)")
        L.append(" ================================================================")
        for e in esc:
            L.append(f" [ESCALADA] {e.get('chain', '?')} · veredicto: {e.get('verdict', '?')}")
            if e.get("poc"):
                L.append(f"            kit PoC local: {e.get('poc')}")
            for i, paso in enumerate(e.get("playbook", []), 1):
                L.append(f"            {i}. {paso[:160]}")

    L.append("")
    L.append(" HALLAZGOS TECNICOS")
    L.append(sub)
    for f in _tech(job):
        sev = (f.get("severity") or "info").upper()
        ver = "  [VERIFICADO]" if f.get("verificado") else ""
        fp = "  [falso positivo descartado]" if f.get("descartado_fp") else ""
        L.append(f" [{sev}] {f.get('type', '?')}{ver}{fp}")
        L.append(f"        blanco: {f.get('target', '?')}")
        if f.get("param"):
            L.append(f"        param  : {f.get('param')} ({f.get('method', 'GET')})")
        L.append(f"        razon : {f.get('reason', '')[:160]}")
        L.append("")

    av = auto_verification(job)
    if av:
        L.append(bar)
        L.append(" VERIFICACION DEL SISTEMA (automatica, sin pasos manuales)")
        L.append(bar)
        for item in av:
            L.append("")
            L.append(f" [{item['estado']}]")
            L.append(f"    hallazgo : {item['hallazgo']} ({(item['severidad'] or 'info').upper()})")
            L.append(f"    blanco   : {item.get('target', '?')}")
            if item.get("como_verifico"):
                L.append(f"    sistema  : {item['como_verifico']}")
            if item.get("detalle"):
                L.append(f"    detalle  : {item['detalle'][:220]}")
    L.append(bar)
    L.append(" LOG COMPLETO DE LA CAZA")
    L.append(bar)
    for e in job.get("live_log") or []:
        L.append(f" [{e.get('ts', '')}] {e.get('msg', '')}")
    L.append("")
    L.append(bar)
    L.append(" Generado por CODEXRC HUNTER " + _ver(job))
    L.append(bar)
    return "\n".join(L)


# ----------------------------------------------------------------- PDF ----

_CSS = """
@page { size: A4; margin: 0; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
       margin: 0; color: #1e293b; font-size: 12px; }
.cover { background: #0b1220; color: #e2e8f0; padding: 34px 44px 26px; }
.cover h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: 1px; color: #4ade80; }
.cover .sub { color: #94a3b8; font-size: 12px; }
.meta { display: table; width: 100%; margin-top: 18px; border-collapse: collapse; }
.meta div { display: table-cell; padding: 4px 0; font-size: 11.5px; color: #cbd5e1; }
.meta b { color: #f1f5f9; font-weight: 600; }
.wrap { padding: 26px 44px 40px; }
.cards { width: 100%; border-spacing: 8px 0; display: table; margin: 0 -8px 18px; }
.card { display: table-cell; width: 20%; background: #f8fafc; border: 1px solid #e2e8f0;
        border-radius: 10px; padding: 12px 10px; text-align: center; }
.card .n { font-size: 22px; font-weight: 700; }
.card .t { font-size: 9.5px; color: #64748b; text-transform: uppercase; letter-spacing: .6px; }
h2 { font-size: 14px; margin: 22px 0 8px; padding-bottom: 4px;
     border-bottom: 2px solid #e2e8f0; }
h2.leak { color: #be123c; border-bottom-color: #be123c; }
h2.leak::before { content: "!! "; }
.f { border: 1px solid #e2e8f0; border-left-width: 4px; border-radius: 8px;
     padding: 8px 12px; margin: 6px 0; page-break-inside: avoid; }
.f .top { margin: 0 0 3px; font-size: 12.5px; font-weight: 600; }
.f .row { color: #475569; font-size: 10.5px; margin: 1px 0; word-break: break-all; }
.tag { display: inline-block; font-size: 9px; font-weight: 700; color: #fff;
       border-radius: 4px; padding: 1px 7px; margin-right: 6px; vertical-align: 1px; }
.ok { background: #16a34a; } .fp { background: #94a3b8; }
.leakbox { border: 2px solid #be123c; background: #fff1f2; border-radius: 10px;
           padding: 10px 12px; margin: 6px 0; page-break-inside: avoid; }
.leakbox .top { font-weight: 700; color: #9f1239; }
h2.pb { color: #0f766e; border-bottom-color: #14b8a6; }
.pb { border: 1px solid #ccfbf1; background: #f0fdfa; border-radius: 8px;
      padding: 8px 12px; margin: 6px 0; page-break-inside: avoid; }
.pb .top { font-weight: 700; font-size: 12px; color: #134e4a; }
.pb .step { font-size: 10.5px; color: #1e293b; margin: 5px 0 1px; }
.pb .cmd { font-family: 'Consolas', monospace; font-size: 9.5px; color: #4ade80;
           background: #0b1220; border-radius: 6px; padding: 6px 8px;
           margin: 3px 0; white-space: pre-wrap; word-break: break-all; }
.pb .esp { font-size: 9.5px; color: #475569; margin: 2px 0 6px; }
.foot { margin-top: 26px; border-top: 1px solid #e2e8f0; padding-top: 8px;
        color: #94a3b8; font-size: 9.5px; }
"""


def _esc(x: Any) -> str:
    return html.escape(str(x if x is not None else ""))


def _fblock(f: Dict[str, Any], leak: bool = False) -> str:
    sev = (f.get("severity") or "info").lower()
    color = "#be123c" if leak else SEV_COLORS.get(sev, "#475569")
    tags = (f'<span class="tag" style="background:{color}">{_esc(sev.upper())}</span>')
    if f.get("verificado"):
        tags += '<span class="tag ok">VERIFICADO EN NAVEGADOR</span>'
    if f.get("descartado_fp"):
        tags += '<span class="tag fp">FALSO POSITIVO</span>'
    param = (f'<div class="row">param: {_esc(f.get("param"))} · {_esc(f.get("method", "GET"))}</div>'
             if f.get("param") else "")
    extra = ""
    if leak:
        fields = ", ".join(f.get("leak_fields") or []) or "?"
        extra = (f'<div class="row"><b>campos filtrados:</b> {_esc(fields)} · '
                 f'<b>identidad:</b> {_esc(f.get("leak_identity") or "?")}</div>')
    box = "leakbox" if leak else "f"
    return (f'<div class="{box}"><p class="top">{tags}{_esc(f.get("type", "?"))}</p>'
            f'<div class="row">blanco: {_esc(f.get("target", "?"))}</div>{param}{extra}'
            f'<div class="row">razon: {_esc((f.get("reason") or "")[:220])}</div></div>')


def _pdf_html(job: Dict[str, Any]) -> str:
    s = summarize(job)
    leaks, tech = _leaks(job), _tech(job)
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{c}">{s[k]}</div>'
        f'<div class="t">{t}</div></div>'
        for k, t, c in [("total", "hallazgos", "#0f172a"), ("alta", "altos", "#e11d48"),
                        ("verificados", "verificados", "#16a34a"),
                        ("descartados_fp", "falsos pos.", "#94a3b8"),
                        ("leaks", "filtraciones", "#be123c")])
    meta = "".join(f'<div><b>{l}:</b> {_esc(v)}</div>' for l, v in [
        ("Objetivo", job.get("url", "?")), ("Estado", job.get("status", "?")),
        ("Version", _ver(job)),
        ("Fecha", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))])
    leak_html = "".join(_fblock(f, leak=True) for f in leaks) or \
        '<p class="row">Ninguna filtracion de datos de usuarios detectada.</p>'
    tech_html = "".join(_fblock(f) for f in tech) or \
        '<p class="row">Sin hallazgos tecnicos.</p>'
    av = auto_verification(job)
    pb_html = ""
    for item in av:
        como = (f'<div class="step">sistema: {_esc(item["como_verifico"])}</div>'
                if item.get("como_verifico") else "")
        det = (f'<div class="esp">{_esc(item["detalle"])}</div>'
               if item.get("detalle") else "")
        pb_html += (f'<div class="pb"><div class="top">{_esc(item["estado"])} · '
                    f'{_esc(item["hallazgo"])} '
                    f'({_esc((item.get("severity") or "info")).upper()})</div>'
                    f'<div class="step">blanco: {_esc(item.get("target") or "?")}</div>'
                    f'{como}{det}</div>')
    pb_html = pb_html or '<p class="row">Sin hallazgos que verificar.</p>'
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{_CSS}</style></head>
<body><div class="cover"><h1>&gt;_ CODEXRC HUNTER</h1>
<div class="sub">Informe de caza · generacion automatica</div>
<div class="meta">{meta}</div></div>
<div class="wrap"><div class="cards">{cards}</div>
<h2 class="leak">FILTRACION DE DATOS DE USUARIOS (critico)</h2>{leak_html}
<h2>HALLAZGOS TECNICOS</h2>{tech_html}
<h2 class="pb">VERIFICACION DEL SISTEMA (automatica)</h2>{pb_html}
<div class="foot">CODEXRC HUNTER v{_ver(job)} · informe de solo lectura ·
hallazgos verificados con navegador real cuando VERITAS esta activo ·
pagina 1 de N</div></div></body></html>"""


def _browser() -> Optional[str]:
    try:
        from core.veritas import _find_browser
        return _find_browser()
    except Exception:
        for n in ("google-chrome", "google-chrome-stable", "chromium",
                  "chromium-browser", "msedge", "microsoft-edge"):
            p = shutil.which(n)
            if p:
                return p
    return None


def _pdf_chrome(job: Dict[str, Any]) -> Optional[bytes]:
    exe = _browser()
    if not exe:
        return None
    with tempfile.TemporaryDirectory(prefix="codexrc_pdf_") as td:
        src = Path(td) / "report.html"
        out = Path(td) / "report.pdf"
        src.write_text(_pdf_html(job), encoding="utf-8")
        try:
            subprocess.run([exe, "--headless=new", "--no-sandbox", "--disable-gpu",
                            "--no-first-run", "--print-to-pdf=" + str(out),
                            "--print-to-pdf-no-header",
                            src.as_uri()],
                           capture_output=True, timeout=90)
        except Exception:
            return None
        if out.exists() and out.stat().st_size > 500:
            return out.read_bytes()
    return None


def _pdf_fpdf2(job: Dict[str, Any]) -> Optional[bytes]:
    try:
        from fpdf import FPDF  # fpdf2: python puro
    except Exception:
        return None
    s = summarize(job)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    # banda superior
    pdf.set_fill_color(11, 18, 32)
    pdf.rect(0, 0, 210, 30, "F")
    pdf.set_xy(12, 8)
    pdf.set_text_color(74, 222, 128)
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 6, ">_ CODEXRC HUNTER")
    pdf.set_xy(12, 16)
    pdf.set_text_color(226, 232, 240)
    pdf.set_font("helvetica", "", 9)
    pdf.cell(0, 5, f"Informe de caza  ·  v{_ver(job)}  ·  {job.get('url', '?')}")
    pdf.set_y(34)
    pdf.set_text_color(15, 23, 42)
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 6, f"RESUMEN: {s['total']} hallazgos · {s['alta']} altos · "
                   f"{s['verificados']} verificados · {s['leaks']} filtraciones")
    pdf.ln(9)

    def section(title: str, color, items, leak=False):
        if not items and not leak:
            return
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(*color)
        pdf.cell(0, 7, title)
        pdf.ln(8)
        pdf.set_text_color(51, 65, 85)
        pdf.set_font("helvetica", "", 9)
        for f in items:
            pdf.set_font("helvetica", "B", 9.5)
            pdf.multi_cell(0, 5, f"[{(f.get('severity') or 'info').upper()}] "
                                   f"{f.get('type', '?')}"
                                   + ("  [VERIFICADO]" if f.get("verificado") else "")
                                   + ("  [FALSO POSITIVO]" if f.get("descartado_fp") else ""))
            pdf.set_font("helvetica", "", 8.5)
            pdf.multi_cell(0, 4.5, f"blanco: {f.get('target', '?')}")
            if f.get("param"):
                pdf.multi_cell(0, 4.5, f"param: {f['param']} ({f.get('method', 'GET')})")
            pdf.multi_cell(0, 4.5, f"razon: {(f.get('reason') or '')[:200]}")
            pdf.ln(3)

    section("FILTRACION DE DATOS DE USUARIOS (critico)",
            (190, 18, 60), _leaks(job), leak=True)
    section("HALLAZGOS TECNICOS", (30, 41, 59), _tech(job))

    # verificacion del sistema (automatica)
    av = auto_verification(job)
    if av:
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 118, 110)
        pdf.ln(4)
        pdf.cell(0, 7, "VERIFICACION DEL SISTEMA (automatica)")
        pdf.ln(8)
        for item in av:
            pdf.set_font("helvetica", "B", 9.5)
            pdf.set_text_color(19, 78, 74)
            pdf.multi_cell(0, 5, f"[{item['estado']}] {item['hallazgo']} "
                                f"({(item['severidad'] or 'info').upper()})")
            pdf.set_text_color(51, 65, 85)
            pdf.set_font("helvetica", "", 8.5)
            pdf.multi_cell(0, 4.5, f"blanco: {item.get('target', '?')}")
            if item.get("como_verifico"):
                pdf.multi_cell(0, 4.5, f"sistema: {item['como_verifico']}")
            if item.get("detalle"):
                pdf.multi_cell(0, 4.5, f"detalle: {item['detalle'][:200]}")
            pdf.ln(3)
    return bytes(pdf.output())


# ---------- NIVEL 3: PDF nativo en Python puro (cero dependencias) ----------

def _pdf_pstr(txt: str) -> str:
    t = str(txt if txt is not None else "").encode("cp1252", "replace").decode("cp1252")
    return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(job: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Estructura del informe, critico primero: filtraciones arriba."""
    s = summarize(job)
    leaks, tech = _leaks(job), _tech(job)
    out: List[Tuple[str, str]] = []
    out.append(("h1", ">_ CODEXRC HUNTER — INFORME DE CAZA"))
    out.append(("sub", "generacion automatica · solo lectura · veredictos del sistema"))
    out.append(("b", f"OBJETIVO: {job.get('url', '?')}"))
    out.append(("b", f"ESTADO: {job.get('status', '?')}  ·  {_ver(job)}"))
    out.append(("b", f"FECHA: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"))
    _nchains = len((job.get("results", {}).get("chain", {}).get("data", {}).get("chains", [])))
    out.append(("b", f"RESUMEN: {s.get('total', 0)} hallazgos · {s.get('alta', 0)} altos · "
                     f"{s.get('verificados', 0)} verificados · {s.get('leaks', 0)} FILTRACIONES"
                     + (f" · {_nchains} CADENAS DE IMPACTO" if _nchains else "")))
    out.append(("sp", ""))

    # 1) LO PRIMERO: filtraciones de usuarios
    out.append(("h2", "1. FILTRACION DE DATOS DE USUARIOS (CRITICO)"))
    if not leaks:
        out.append(("plain", "   Ninguna filtracion de datos de usuarios detectada."))
    for f in leaks:
        out.append(("leak", f"   [{ (f.get('severity') or '?').upper() }] {f.get('type', '?')}"))
        out.append(("plain", f"   blanco: {f.get('target', '?')}"))
        if f.get("param"):
            out.append(("plain", f"   param: {f.get('param')} · {f.get('method', 'GET')}"))
        out.append(("b", f"   DATOS FILTRADOS: {', '.join(f.get('leak_fields') or []) or '?'}"))
        if f.get("leak_identity"):
            out.append(("b", f"   IDENTIDAD VISTA: {f.get('leak_identity')}"))
        ev = (f.get("evidence") or "")[:600]
        for ln in ev.splitlines():
            out.append(("mono", f"   {ln}"))
        out.append(("sp", ""))

    # 1.5) CADENAS: el valor real -- severidad combinada que NO cuenta el summary base
    chains = (job.get("results", {}).get("chain", {}).get("data", {}).get("chains", []))
    if chains:
        out.append(("h2", "1.5 CADENAS DE IMPACTO COMBINADO (severidad propia, no cuenta en el total base)"))
        for c in chains:
            out.append(("leak", f"   [{(c.get('severity') or '?').upper()}] {c.get('name', '?')}"))
            out.append(("plain", f"   piezas: {', '.join(c.get('parts', []))}"))
            out.append(("plain", f"   porque: {(c.get('reason') or '')[:220]}"))
            out.append(("sp", ""))

    esc = (job.get("results", {}).get("escalada", {}).get("data", {}).get("escalations", []))
    if esc:
        out.append(("h2", "1.6 ESCALADA — QUE HACER DESPUES (paso a paso)"))
        for e in esc:
            out.append(("sev", f"   [{e.get('verdict', '?')}] {e.get('chain', '?')}"))
            if e.get("poc"):
                out.append(("plain", f"   kit PoC local: {e.get('poc')}"))
            for i, paso in enumerate(e.get("playbook", []), 1):
                out.append(("plain", f"   {i}. {paso[:180]}"))
            out.append(("sp", ""))

    # 2) hallazgos por severidad, encadenados: hallazgo -> veredicto -> verificacion
    out.append(("h2", "2. HALLAZGOS ENCADENADOS (gravedad -> veredicto -> verificacion)"))
    order = {"alta": 0, "media": 1, "baja": 2, "info": 3}
    todo = sorted(tech, key=lambda f: order.get((f.get("severity") or "info").lower(), 9))
    if not todo:
        out.append(("plain", "   Sin hallazgos tecnicos."))
    for f in todo:
        v = f.get("veredicto") or {}
        marks = []
        if f.get("verificado"):
            marks.append("VERIFICADO EN NAVEGADOR")
        if f.get("descartado_fp"):
            marks.append("FALSO POSITIVO")
        out.append(("sev", f"   [{(f.get('severity') or 'info').upper()}] {f.get('type', '?')}"
                    + (f"  [{' · '.join(marks)}]" if marks else "")))
        out.append(("plain", f"   blanco: {f.get('target', '?')}"
                    + (f" · param: {f.get('param')}" if f.get("param") else "")))
        out.append(("plain", f"   razon: {(f.get('reason') or '')[:200]}"))
        if v:
            out.append(("plain", f"   VEREDICTO: gravedad={v.get('gravedad', '?')} · "
                                 f"primeros={v.get('primeros', '?')} · reglas={v.get('reglas', '?')}"))
        ev = (f.get("evidence") or "")[:400]
        if ev:
            for ln in ev.splitlines()[:6]:
                out.append(("mono", f"     {ln}"))
        out.append(("sp", ""))

    # 3) verificacion automatica del sistema
    out.append(("h2", "3. VERIFICACION DEL SISTEMA (AUTOMATICA)"))
    av = auto_verification(job)
    if not av:
        out.append(("plain", "   Sin hallazgos que verificar."))
    for item in av:
        out.append(("b", f"   {item['estado']} · {item['hallazgo']} "
                         f"({(item.get('severity') or 'info').upper()})"))
        out.append(("plain", f"   blanco: {item.get('target') or '?'}"))
        if item.get("como_verifico"):
            out.append(("plain", f"   sistema: {item['como_verifico']}"))
        if item.get("detalle"):
            out.append(("plain", f"   detalle: {item['detalle']}"))
        out.append(("sp", ""))

    out.append(("foot", f"CODEXRC HUNTER {_ver(job)} · sondas de lectura A->B · "
                        f"veredictos automaticos, sin verificacion manual del operador"))
    return out


_STYLES = {
    "h1":     (16, "F2", (0.05, 0.06, 0.03), 6),
    "sub":    (9,  "F2", (0.45, 0.55, 0.45), 4),
    "b":      (9,  "F2", (0.1, 0.15, 0.1), 4),
    "h2":     (12, "F2", (0.6, 0.07, 0.25), 8),
    "leak":   (10, "F2", (0.6, 0.07, 0.25), 4),
    "sev":    (9,  "F2", (0.55, 0.36, 0.02), 4),
    "plain":  (8,  "F1", (0.15, 0.15, 0.15), 3),
    "mono":   (8,  "F1", (0.25, 0.25, 0.25), 3),
    "sp":     (1,  "F1", (0, 0, 0), 8),
    "foot":   (7,  "F1", (0.45, 0.45, 0.45), 4),
}


def _pdf_native(job: Dict[str, Any]) -> Optional[bytes]:
    """PDF minimo generado a mano: cero dependencias (Termux OK).
    Fuente Helvetica embebida por el visor, paginacion automatica."""
    lines = _pdf_lines(job)
    W, H, M = 595.0, 842.0, 42.0
    pages, cur, y = [], [], H - M
    for style, txt in lines:
        size, font, color, gap = _STYLES.get(style, _STYLES["plain"])
        need = size + gap
        if y - need < M:
            pages.append(cur)
            cur, y = [], H - M
        y -= size + 2
        cur.append(f"BT /{font} {size} Tf {color[0]} {color[1]} {color[2]} rg "
                   f"1 0 0 1 {M} {y:.1f} Tm ({_pdf_pstr(txt)}) Tj ET")
        y -= gap
    pages.append(cur)
    objs = {}
    n_pages = len(pages)
    # 1 catalogo, 2 pages, 3 F1 (helvetica), 4 F2 (helvetica-bold)
    for i, content in enumerate(pages):
        cobj = 5 + i * 2
        pobj = cobj + 1
        objs[pobj] = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W:.0f} {H:.0f}] "
                      f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cobj} 0 R >>")
        objs[cobj] = ("<< /Length " + str(len("\n".join(content).encode("latin-1", "replace"))) +
                      " >>\nstream\n" + "\n".join(content) + "\nendstream")
    kids = " ".join(f"{5 + i * 2 + 1} 0 R" for i in range(n_pages))
    objs[1] = "<< /Type /Catalog /Pages 2 0 R >>"
    objs[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>"
    objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    buf = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num in sorted(objs):
        offsets[num] = len(buf)
        body = objs[num].encode("latin-1", "replace")
        buf += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(buf)
    mx = max(objs)
    buf += f"xref\n0 {mx + 1}\n".encode()
    buf += b"0000000000 65535 f \n"
    for num in range(1, mx + 1):
        buf += f"{offsets.get(num, 0):010d} 00000 n \n".encode()
    buf += (f"trailer\n<< /Size {mx + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF").encode()
    return bytes(buf)


def build_pdf(job: Dict[str, Any]) -> Tuple[Optional[bytes], str]:
    """Devuelve (bytes, metodo). metodo: chrome | fpdf2 | nativo (siempre disponible)."""
    data = _pdf_chrome(job)
    if data:
        return data, "chrome"
    data = _pdf_fpdf2(job)
    if data:
        return data, "fpdf2"
    data = _pdf_native(job)
    if data:
        return data, "nativo"
    return None, "none"
