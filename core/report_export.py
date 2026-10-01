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
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{_CSS}</style></head>
<body><div class="cover"><h1>&gt;_ CODEXRC HUNTER</h1>
<div class="sub">Informe de caza · generacion automatica</div>
<div class="meta">{meta}</div></div>
<div class="wrap"><div class="cards">{cards}</div>
<h2 class="leak">FILTRACION DE DATOS DE USUARIOS (critico)</h2>{leak_html}
<h2>HALLAZGOS TECNICOS</h2>{tech_html}
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
    return bytes(pdf.output())


def build_pdf(job: Dict[str, Any]) -> Tuple[Optional[bytes], str]:
    """Devuelve (bytes, metodo). metodo: chrome | fpdf2 | none."""
    data = _pdf_chrome(job)
    if data:
        return data, "chrome"
    data = _pdf_fpdf2(job)
    if data:
        return data, "fpdf2"
    return None, "none"
