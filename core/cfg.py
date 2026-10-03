#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SEMANTIC CORE (v0.58.1) — Nivel 1: CFG intra-funcion + dominancia.

Tokenizer PHP-lite -> arbol de statements -> grafo de control de flujo
-> dominadores (algoritmo iterativo) -> consultas semanticas:

  dominates(cfg, gate_node, sink_node)   ¿todo camino a sink pasa gate?
  gate_dominates_sink(...)               el gate protege el sink?
  router_noise(...)                      gate domina todos los sinks
                                         sensibles => la comparacion
                                         'auth' es solo router (FP)

Jerarquia de precision: una consulta de este modulo SIEMPRE gana a
una ventana de texto (+-1, +-5 lineas). Si el parseo falla, el llamador
debe caer a su heuristica textual previa (fallback).

Nivel honesto 1: intra-funcion. No resuelve includes ni herencia.
Python puro, Termux/armv7l OK.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------- tokenizer

_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_]*")
_SYM_INTEREST = "{}();:"


def tokenize_php(src: str) -> List[Tuple[str, str, int]]:
    """Tokens (kind, text, line). kind: word|sym|str|op.
    Comentarios fuera; strings heredoc soportados (minimo)."""
    out: List[Tuple[str, str, int]] = []
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\v\f":
            i += 1
            continue
        if src.startswith("//", i) or c == "#":
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                break
            line += src.count("\n", i, j + 2)
            i = j + 2
            continue
        if src.startswith("<<<", i):
            m = re.match(r"<<<['\"]?([A-Za-z_]\w*)['\"]?\r?\n", src[i:])
            if m:
                term = m.group(1)
                j = re.search(r"^" + term + r"\b", src[i + m.end():],
                              re.M)
                end = (i + m.end() + j.start()) if j else n
                line += src.count("\n", i, end)
                out.append(("str", src[i:end], line))
                i = end
                continue
        if c in "'\"":
            k = i + 1
            while k < n:
                if src[k] == "\\":
                    k += 2
                    continue
                if src[k] == c or src[k] == "\n" and c == "'":
                    break
                k += 1
            out.append(("str", src[i:k + 1], line))
            line += src.count("\n", i, min(k + 1, n))
            i = k + 1
            continue
        if c in _SYM_INTEREST:
            out.append(("sym", c, line))
            i += 1
            continue
        m = _WORD.match(src, i)
        if m:
            out.append(("word", m.group(0), line))
            i = m.end()
            continue
        out.append(("op", c, line))
        i += 1
    return out


# ------------------------------------------------------------- arbol de
#                                                             statements

class Stmt:
    __slots__ = ("kind", "text", "line", "body", "elses", "label")

    def __init__(self, kind: str, text: str, line: int):
        self.kind = kind      # if|while|for|foreach|switch|do|try|stmt
        self.text = text      # header completo (condiciones incluidas)
        self.line = line
        self.body: List["Stmt"] = []      # bloque principal
        self.elses: List["Stmt"] = []     # else / elseif (como Stmts if)
        self.label = ""      # case/default/endif info


_CTRL_HEADS = {"if", "elseif", "while", "for", "foreach", "switch"}


def _classify(text: str) -> str:
    w = text.strip().split(None, 1)
    first = w[0] if w else ""
    if first in _CTRL_HEADS or first in ("else", "do", "try"):
        return first if first != "elseif" else "elseif"
    return "stmt"


def _is_terminal(text: str) -> bool:
    t = text.lstrip()
    return bool(re.match(r"(return\b|exit\b|die\b|throw\b)", t))


def _is_jump(text: str) -> Tuple[bool, bool]:
    """(es_break, es_continue)"""
    t = text.lstrip()
    return bool(re.match(r"break\b", t)), bool(re.match(r"continue\b", t))


class _ParseErr(Exception):
    pass


def parse_block(toks: List[Tuple[str, str, int]], i: int,
                stop_depth: int = 0) -> Tuple[List[Stmt], int]:
    """Parsea hasta agotar tokens o encontrar cierre de bloque actual.
    Maneja: {} anidados, if sin llaves, alt-syntax (: ... endif)."""
    items: List[Stmt] = []
    cur: List[str] = []
    cur_line = 0
    pd = 0  # paren depth dentro del statement actual
    n = len(toks)
    while i < n:
        kind, text, line = toks[i]

        if not cur:
            cur_line = line

        if kind == "word" and pd == 0 and text in (
                "endif", "endwhile", "endfor", "endforeach"):
            if cur:
                items.append(Stmt("stmt", " ".join(cur), cur_line))
                cur = []
            return items, i  # el caller decide

        if kind == "sym" and text == "(":
            pd += 1
            cur.append(text)
            i += 1
            continue
        if kind == "sym" and text == ")":
            pd -= 1
            cur.append(text)
            i += 1
            if pd == 0 and cur and _classify(" ".join(cur)) in _CTRL_HEADS:
                # header completo sin llaves todavia
                hdr = Stmt(_classify(" ".join(cur)), " ".join(cur),
                           cur_line)
                cur = []
                i = _parse_after_header(toks, i, hdr, stop_depth)
                items.append(hdr)
            continue
        if kind == "sym" and text == ";":
            if pd <= 0:
                if cur:
                    t = " ".join(cur)
                    items.append(Stmt(_classify(t), t, cur_line))
                    cur = []
                pd = 0
            i += 1
            continue
        if kind == "sym" and text == "{":
            if cur:
                t = " ".join(cur)
                kindh = _classify(t)
                if kindh in _CTRL_HEADS or kindh in ("else", "do",
                                                     "try"):
                    hdr = Stmt(kindh, t, cur_line)
                    cur = []
                    body, i = parse_block(toks, i + 1, stop_depth + 1)
                    hdr.body = body
                    # else / elseif encadenados tras }
                    i = _parse_chain_tail(toks, i, hdr, stop_depth)
                    items.append(hdr)
                    continue
                # no-control: statement suelto antes de { (raro)
                items.append(Stmt("stmt", t, cur_line))
                cur = []
            body, i = parse_block(toks, i + 1, stop_depth + 1)
            blk = Stmt("block", "{block}", cur_line)
            blk.body = body
            items.append(blk)
            continue
        if kind == "sym" and text == "}":
            if cur:
                items.append(Stmt("stmt", " ".join(cur), cur_line))
                cur = []
            return items, i + 1
        if kind == "sym" and text == ":" and pd == 0:
            # alt-syntax: header: ... endif|else|...
            t = " ".join(cur)
            if t and _classify(t) in _CTRL_HEADS or t.strip() == "else" \
                    or t.strip().startswith("else"):
                hdr = Stmt(_classify(t), t, cur_line)
                cur = []
                body, i = _parse_alt_block(toks, i + 1, hdr,
                                            stop_depth + 1)
                i = _parse_chain_tail(toks, i, hdr, stop_depth)
                items.append(hdr)
                continue
            cur.append(":")
            i += 1
            continue
        cur.append(text)
        i += 1
    if cur:
        items.append(Stmt("stmt", " ".join(cur), cur_line))
    return items, i


def _parse_after_header(toks, i, hdr, stop_depth) -> int:
    """Cuerpo de un header completado por ')': { ... } o 1 statement."""
    n = len(toks)
    # saltar whitespace implicito: el siguiente token decide
    if i < n and toks[i][0] == "sym" and toks[i][1] == "{":
        body, i2 = parse_block(toks, i + 1, stop_depth + 1)
        hdr.body = body
        return _parse_chain_tail(toks, i2, hdr, stop_depth)
    if i < n and toks[i][0] == "sym" and toks[i][1] == ":":
        body, i2 = _parse_alt_block(toks, i + 1, hdr, stop_depth + 1)
        hdr.body = body
        return _parse_chain_tail(toks, i2, hdr, stop_depth)
    # statement simple como cuerpo (if sin llaves)
    # parseamos 1 statement
    if hdr.kind in ("do", "else", "try"):
        pass
    body, i2 = _one_stmt(toks, i, stop_depth)
    hdr.body = body
    return _parse_chain_tail(toks, i2, hdr, stop_depth)


def _one_stmt(toks, i, stop_depth) -> Tuple[List[Stmt], int]:
    """Un solo statement (posiblemente un header con su propio cuerpo)."""
    n = len(toks)
    cur: List[str] = []
    pd = 0
    cur_line = toks[i][2] if i < n else 0
    while i < n:
        kind, text, line = toks[i]
        if not cur:
            cur_line = line
        if kind == "sym" and text == "(":
            pd += 1
        if kind == "sym" and text == ")":
            pd -= 1
        cur.append(text)
        i += 1
        if pd == 0 and kind == "sym" and text == ";":
            t = " ".join(cur)
            return [Stmt(_classify(t), t, cur_line)], i
        if pd == 0 and kind == "sym" and text == "{":
            # header con llaves inmediato
            t = " ".join(cur[:-1])
            hdr = Stmt(_classify(t), t, cur_line)
            body, i = parse_block(toks, i, stop_depth + 1)
            hdr.body = body
            return [hdr], i
        if pd == 0 and kind == "sym" and text == ":" \
                and _classify(" ".join(cur[:-1])) in _CTRL_HEADS:
            t = " ".join(cur[:-1])
            hdr = Stmt(_classify(t), t, cur_line)
            body, i = _parse_alt_block(toks, i, hdr, stop_depth + 1)
            hdr.body = body
            return [hdr], i
    if cur:
        return [Stmt("stmt", " ".join(cur), cur_line)], i
    return [], i


def _parse_alt_block(toks, i, hdr, depth):
    """Bloque alt-syntax hasta endX / else / elseif del mismo nivel."""
    kind = hdr.kind
    ends = {"if": ("endif",), "while": ("endwhile",),
            "for": ("endfor",), "foreach": ("endforeach",),
            "switch": ("endswitch",)}
    end_words = ends.get(kind, ("endif",))
    items: List[Stmt] = []
    n = len(toks)
    while i < n:
        # mirar si el proximo statement es un end/else de este nivel
        save = i
        block, i = parse_block(toks, i, depth)
        items.extend(block)
        # parse_block corta en endX/else: ver que token nos detuvo
        if i < n:
            k, t, _ = toks[i]
            if k == "word" and t in end_words:
                i += 1
                return items, i
            if k == "word" and t in ("else", "elseif"):
                # consumir la parte else del if-chain
                cur: List[str] = [t]
                i += 1
                pd = 0
                while i < n:
                    k2, t2, _ = toks[i]
                    if k2 == "sym" and t2 == "(":
                        pd += 1
                    if k2 == "sym" and t2 == ")":
                        pd -= 1
                    cur.append(t2)
                    i += 1
                    if pd == 0 and (t2 == "{" or t2 == ":"):
                        txt = " ".join(cur)
                        ehdr = Stmt("else" if t == "else" else "if",
                                    txt, 0)
                        if t2 == "{":
                            body, i = parse_block(toks, i, depth + 1)
                        else:
                            body, i = _parse_alt_block(toks, i, ehdr,
                                                       depth + 1)
                        ehdr.body = body
                        hdr.elses.append(ehdr)
                        break
                    if pd == 0 and t2 == ";":
                        break
                else:
                    break
                continue
            # token de cierre de nivel externo: devolver
            return items, i
        return items, i
    return items, i


def _parse_chain_tail(toks, i, hdr, stop_depth) -> int:
    """Tras cerrar un if: consumir else/elseif del chain."""
    n = len(toks)
    while i < n and hdr.kind in ("if", "elseif"):
        k, t, _line = toks[i]
        if k != "word":
            break
        if t in ("else", "elseif"):
            cur = [t]
            i += 1
            pd = 0
            while i < n:
                k2, t2, _l2 = toks[i]
                if k2 == "sym" and t2 == "(":
                    pd += 1
                if k2 == "sym" and t2 == ")":
                    pd -= 1
                cur.append(t2)
                i += 1
                if pd == 0 and t2 in ("{", ":", ";"):
                    txt = " ".join(cur[:-1]) if t2 in ("{", ":") \
                        else " ".join(cur)
                    ehdr = Stmt("if" if t == "elseif" else "else", txt,
                                _line)
                    if t2 == "{":
                        body, i = parse_block(toks, i, stop_depth + 1)
                    elif t2 == ":":
                        body, i = _parse_alt_block(toks, i, ehdr,
                                                   stop_depth + 1)
                    else:
                        body, i = _one_stmt(toks, i, stop_depth)
                    ehdr.body = body
                    if t == "elseif":
                        ehdr.kind = "if"
                    hdr.elses.append(ehdr)
                    break
            else:
                break
            continue
        break
    return i


# ------------------------------------------------------------- funciones

_FUNC_RE = re.compile(
    r"(?:public|protected|private|static|abstract|final|\s)*"
    r"function\s+&?\s*([A-Za-z_]\w*)\s*\(")


_FUNCS_CACHE: Dict[int, List[Dict]] = {}


def functions(src: str) -> List[Dict]:
    """[{name, start, body_start, end}] con llaves por conteo real
    (strings/comentarios fuera del tokenizer). Cacheado por src."""
    key = id(src)
    hit = _FUNCS_CACHE.get(key)
    if hit is not None:
        return hit
    out = []
    for m in _FUNC_RE.finditer(src):
        open_i = src.find("{", m.end())
        if open_i < 0:
            continue
        depth, i = 1, open_i + 1
        in_str = None
        esc = False
        line = src.count("\n", 0, m.start()) + 1
        while i < len(src) and depth > 0:
            c = src[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == in_str:
                    in_str = None
            elif c in "'\"":
                in_str = c
            elif src.startswith("//", i) or c == "#":
                j = src.find("\n", i)
                i = (len(src) if j < 0 else j)
                continue
            elif src.startswith("/*", i):
                j = src.find("*/", i + 2)
                i = (len(src) - 2 if j < 0 else j)
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        out.append({"name": m.group(1), "start": m.start(),
                    "body_start": open_i + 1, "end": i, "line": line})
    _FUNCS_CACHE.clear()  # una sola entrada viva: el src en uso
    _FUNCS_CACHE[key] = out
    return out


def function_of_line(src: str, line: int) -> Optional[Dict]:
    best = None
    for f in functions(src):
        if f["line"] <= line:
            if best is None or f["start"] >= best["start"]:
                best = f
    # confirmar que line cae dentro del cuerpo
    if best is None:
        return None
    return best


# ------------------------------------------------------------- CFG

class CFG:
    def __init__(self):
        self.kind: List[str] = []      # entry/exit/stmt/cond/join
        self.text: List[str] = []
        self.line: List[int] = []
        self.succ: List[List[int]] = []
        self.pred: List[List[int]] = []
        self.entry = 0
        self.exit = 1
        self.ok = False

    def _node(self, kind: str, text: str, line: int) -> int:
        self.kind.append(kind)
        self.text.append(text)
        self.line.append(line)
        self.succ.append([])
        self.pred.append([])
        return len(self.kind) - 1

    def _edge(self, a: int, b: int):
        self.succ[a].append(b)
        self.pred[b].append(a)

    # dominadores (iterativo)
    def dominators(self) -> List[set]:
        n = len(self.kind)
        reach = self._reachable()
        dom = [set(range(n)) for _ in range(n)]
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for v in range(n):
                if v == self.entry or v not in reach:
                    continue
                ps = [p for p in self.pred[v] if p in reach]
                if not ps:
                    dom[v] = {v}
                    continue
                new = set.intersection(*(dom[p] for p in ps))
                new = {v} | new
                if new != dom[v]:
                    dom[v] = new
                    changed = True
        return dom

    def _reachable(self) -> set:
        seen = {self.entry}
        stack = [self.entry]
        while stack:
            u = stack.pop()
            for v in self.succ[u]:
                if v not in seen:
                    seen.add(v)
                    stack.append(v)
        return seen

    def dominates(self, a: int, b: int, dom: List[set]) -> bool:
        return a in dom[b]


_SENSITIVE_RE = re.compile(
    r"update_option|update_site_option|add_option|delete_option|"
    r"update_user_meta|update_post_meta|wp_insert_post|wp_update_post|"
    r"wp_delete_post|wp_insert_user|wp_delete_user|->query|->insert|"
    r"->update|->delete|->replace|file_put_contents|unlink|"
    r"fwrite|fopen|move_uploaded_file|wp_handle_upload|"
    r"include|require|echo|print|wp_send_json|wp_die|die|exit",
    re.I)

_GATE_CAP_RE = re.compile(
    r"current_user_can\s*\(|\buser_can\s*\(|is_user_logged_in\s*\(|"
    r"_can_access\b|wp_verify_nonce|check_ajax_referer|"
    r"check_admin_referer|is_admin\s*\(|manage_options", re.I)


def build_cfg(items: List[Stmt]) -> CFG:
    """Construye el CFG desde el arbol de statements."""
    cfg = CFG()
    cfg._node("entry", "", 0)
    cfg._node("exit", "", 0)

    # contexto para breaks/continues
    loop_stack: List[List[int]] = []   # targets de continue (cond)
    brk_stack: List[List[int]] = []    # targets de break (join)
    brk_stack.append([cfg.exit])       # break global -> exit? no: tras fn

    def seq(block: List[Stmt], entries: List[int],
            exits: List[int]):
        """Conecta entries -> block, deja exits del bloque."""
        cur = entries
        for it in block:
            cur, _exits = emit(it, cur)
            if _exits is not None:
                cur = _exits
        exits.extend(cur)  # type: ignore

    # emit devuelve (entradas del siguiente, salidas)
    def emit(it: Stmt, incoming: List[int]) -> Tuple[List[int],
                                                    Optional[List[int]]]:
        if not incoming:
            incoming = []
        if it.kind == "stmt" or it.kind == "block":
            if it.kind == "block":
                inner_in = []
                inner_ex: List[int] = []
                sub_in = incoming
                for s in it.body:
                    sub_in, _ = emit(s, sub_in)
                return sub_in, None
            nd = cfg._node("stmt", it.text, it.line)
            for p in incoming:
                cfg._edge(p, nd)
            if _is_terminal(it.text):
                cfg._edge(nd, cfg.exit)
                return [], None
            brk, cont = _is_jump(it.text)
            if brk and brk_stack:
                for t in brk_stack[-1]:
                    cfg._edge(nd, t)
                return [], None
            if cont and loop_stack:
                for t in loop_stack[-1]:
                    cfg._edge(nd, t)
                return [], None
            return [nd], None
        if it.kind in ("if", "elseif"):
            # cadena if/elseif/else
            parts = [(it, it.body)] + [
                (e, e.body) for e in it.elses]
            cur_in = incoming
            after: List[int] = []
            for idx, (part, body) in enumerate(parts):
                cond = cfg._node("cond", part.text, part.line)
                for p in cur_in:
                    cfg._edge(p, cond)
                body_out: List[int] = []
                sub_in = [cond]
                for s in body:
                    sub_in, _ = emit(s, sub_in)
                body_out = sub_in
                if idx < len(parts) - 1:
                    cur_in = [cond]      # falso -> siguiente cond
                    after.extend(body_out)
                else:
                    # ultima parte: si es else, sin falso
                    if part.kind == "else":
                        after.extend(body_out)
                    else:
                        after.extend(body_out)
                        after.append(cond)   # falso -> after
            return after, None
        if it.kind in ("while", "for", "foreach"):
            cond = cfg._node("cond", it.text, it.line)
            for p in incoming:
                cfg._edge(p, cond)
            loop_stack.append([cond])
            brk_stack.append([])
            brk_target: List[int] = []
            sub_in = [cond]
            for s in it.body:
                sub_in, _ = emit(s, sub_in)
            for t in sub_in:
                cfg._edge(t, cond)   # loop back
            for b in brk_stack.pop():
                cfg._edge(b, cond)   # -> salida (via cond false)
            loop_stack.pop()
            # los breaks apuntan al cond; salir del loop = cond->after
            return [cond], None
        if it.kind == "do":
            body_in = incoming
            sub_in = body_in
            for s in it.body:
                sub_in, _ = emit(s, sub_in)
            cond = cfg._node("cond", it.text or "while", it.line)
            for t in sub_in:
                cfg._edge(t, cond)
            cfg._edge(cond, cond)  # placeholder: se repara abajo
            # cond -> after (falso); cond -> primera stmt del body (true)
            # aproximacion: true -> body_in[0]
            if body_in:
                cfg._edge(cond, body_in[0])
            else:
                cfg._edge(cond, cond)
            return [cond], None
        if it.kind == "switch":
            sw = cfg._node("cond", it.text, it.line)
            for p in incoming:
                cfg._edge(p, sw)
            brk_stack.append([])
            cases = [s for s in it.body
                     if s.text.strip().startswith(("case", "default"))]
            others = [s for s in it.body
                      if not s.text.strip().startswith(("case", "default"))]
            # cada case accesible desde switch
            cur = [sw]
            case_conds: List[int] = []
            for cs in cases:
                cnd = cfg._node("cond", cs.text, cs.line)
                for p in cur:
                    cfg._edge(p, cnd)
                case_conds.append(cnd)
                cur = [cnd]
            # cuerpos de los case (fallthrough)
            body_start: List[int] = []
            after: List[int] = []
            sub_in: List[int] = []
            started = False
            for s in it.body:
                if s.text.strip().startswith(("case", "default")):
                    if started:
                        pass
                    cnd = case_conds[cases.index(s)] if s in cases else sw
                    sub_in = [cnd] + (sub_in if started else [])
                    continue
                started = True
                sub_in, _ = emit(s, sub_in)
            after.extend(sub_in)
            for b in brk_stack.pop():
                after.append(b)
            for s in others:
                pass
            if not after:
                after = [sw]
            return after, None
        if it.kind == "try":
            sub_in = incoming
            for s in it.body:
                sub_in, _ = emit(s, sub_in)
            for e in it.elses:   # catch / finally
                sub_in, _ = emit(e, sub_in)
            return sub_in, None
        if it.kind == "else":
            sub_in = incoming
            for s in it.body:
                sub_in, _ = emit(s, sub_in)
            return sub_in, None
        # desconocido: transparente
        return incoming, None

    cur = [cfg.entry]
    for it in items:
        cur, _ = emit(it, cur)
    for t in cur:
        cfg._edge(t, cfg.exit)
    # conectar exits sueltos
    cfg.ok = True
    return cfg


_CFG_CACHE: Dict[Tuple[int, int], Optional[Tuple[CFG, Dict]]] = {}
_CFG_MAX_LINES = 4000  # funciones mas grandes: fallback a ventanas


def cfg_for_function(src: str, line: int) -> Optional[Tuple[CFG, Dict]]:
    f = function_of_line(src, line)
    if not f:
        return None
    ck = (id(src), f["start"])
    if _CFG_CACHE and all(k[0] != id(src) for k in _CFG_CACHE):
        _CFG_CACHE.clear()  # nuevo src: evict del anterior
    if ck in _CFG_CACHE:
        return _CFG_CACHE[ck]
    if src.count("\n", f["body_start"], f["end"]) > _CFG_MAX_LINES:
        _CFG_CACHE[ck] = None
        return None
    body = src[f["body_start"]:f["end"]]
    off = src.count("\n", 0, f["body_start"])  # linea absoluta = off + tok
    toks = tokenize_php(body)
    try:
        items, _ = parse_block(toks, 0)
    except _ParseErr:
        return None
    if not items:
        return None
    g = build_cfg(items)
    if len(g.kind) <= 2:
        return None
    for k in range(len(g.line)):
        if g.line[k]:
            g.line[k] += off
    # validar balance aproximado: todo alcanzable desde entry
    reach = g._reachable()
    if len(reach) <= 2:
        _CFG_CACHE[ck] = None
        return None
    _CFG_CACHE[ck] = (g, f)
    return g, f


# ------------------------------------------------------------- consultas

def nodes_matching(g: CFG, rx: re.Pattern) -> List[int]:
    return [i for i, t in enumerate(g.text) if rx.search(t)]


def line_node(g: CFG, line: int) -> Optional[int]:
    """Nodo que contiene la linea (el mas especifico: cond > stmt)."""
    cands = [i for i, l in enumerate(g.line)
             if i not in (g.entry, g.exit) and l == line]
    if not cands:
        cands = [i for i, l in enumerate(g.line)
                 if i not in (g.entry, g.exit) and l and abs(l - line) <= 2]
    for c in cands:
        if g.kind[c] == "cond":
            return c
    return cands[0] if cands else None


def gate_dominates_sink(g: CFG, gate_rx: re.Pattern, sink_line: int) -> bool:
    """Existe un gate cuyo cond domina el nodo de sink_line."""
    sink = line_node(g, sink_line)
    if sink is None:
        return False
    gates = nodes_matching(g, gate_rx)
    if not gates:
        return False
    dom = g.dominators()
    return any(g2 != sink and g.dominates(g2, sink, dom)
               for g2 in gates)


def cmp_router(g: CFG, cmp_line: int, gate_rx: re.Pattern = _GATE_CAP_RE,
              sens_rx: re.Pattern = _SENSITIVE_RE) -> bool:
    """La comparacion senalada solo rotea hacia region protegida:
    todo sink sensible que depende de ella (dominado por su cond)
    esta a su vez dominado por un gate => la comparacion no es el
    control de acceso, es router (FP de loose-auth-cmp)."""
    cmpn = line_node(g, cmp_line)
    if cmpn is None:
        return False
    gates = [x for x in nodes_matching(g, gate_rx)
             if x not in (g.entry, g.exit)]
    if not gates:
        return False
    dom = g.dominators()
    sens = [i for i in nodes_matching(g, sens_rx)
            if i not in (g.entry, g.exit) and g.kind[i] == "stmt"]
    downstream = [s2 for s2 in sens if s2 != cmpn
                  and g.dominates(cmpn, s2, dom)]
    if not downstream:
        return False
    return all(any(gg != s2 and g.dominates(gg, s2, dom)
                   for gg in gates) for s2 in downstream)


def router_noise(g: CFG, gate_rx: re.Pattern = _GATE_CAP_RE,
                 sens_rx: re.Pattern = _SENSITIVE_RE) -> bool:
    """Todos los statements sensibles estan dominados por algun gate =>
    una comparacion 'auth' dentro de la funcion es puro routing."""
    sens = [i for i in nodes_matching(g, sens_rx)
            if i not in (g.entry, g.exit) and g.kind[i] == "stmt"]
    if not sens:
        return False
    gates = nodes_matching(g, gate_rx)
    if not gates:
        return False
    dom = g.dominators()
    for s in sens:
        if not any(g.dominates(gg, s, dom) for gg in gates if gg != s):
            return False
    return True
