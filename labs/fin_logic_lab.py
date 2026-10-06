#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab FIN-LOGIC v0.97.0: 6 escenarios deterministas de logica
financiera (companero de fin_logic_probe.py).

Simula el backend minimo de una tienda: UN pedido (order) con precio,
cantidad, descuento y estado. Python puro (http.server), sin
dependencias externas, facil de levantar en Termux.

Roles (header X-Fin-Role + X-Fin-User, simulando sesiones multi-rol
igual que BAC-PROOF: admin / subscriber / anon):
  admin       puede modificar cualquier pedido.
  subscriber  SOLO puede modificar el pedido que posee (ownership
              SIEMPRE correctamente validado en este lab: el bug que
              probamos aqui es de VALOR, no de autorizacion cruzada;
              eso ya lo cubre bac_proof.py).
  anon        nunca puede modificar, solo rutas publicas si existieran.
  gateway     rol interno que simula al pasarela de pago real: es el
              UNICO que puede mover status -> paid/completed/refunded
              en los escenarios correctos.

Pedido semilla (determinista en cada arranque):
  id=5001  owner_id=7 (subscriber)  price=100.0  qty=2
  discount_pct=0  status=pending  total=200.0

Escenarios (cada uno vulnerable en UN solo campo, los demas
correctamente validados, para que la señal quede aislada):

  19801 price_negative     -> acepta price fuera de rango (incluye
                              negativo) sin clamp ni rechazo.
  19802 qty_negative       -> acepta qty fuera de rango (incluye
                              negativo/cero/decimal) sin clamp.
  19803 discount_over_100  -> acepta discount_pct fuera de 0-100.
  19804 status_force_paid  -> acepta status=paid/completed/refunded
                              por PATCH directo del dueno, sin pasar
                              por el endpoint /pay (rol gateway).
  19805 validated_control  -> TODO correctamente validado: control
                              negativo obligatorio, NO debe disparar
                              ningun hallazgo.
  19806 coupon_race        -> cupon de un solo uso con ventana TOCTOU
                              (check-then-act con sleep) redimible 2
                              veces si se dispara en paralelo. Opcional
                              / documentado como limitacion en v1 del
                              probe (ver fin_logic_probe.py).

  19807 multi_field        -> endpoint combinado /order/<id>/bulk_update
                              (price+quantity JUNTOS) valida con un AND
                              en vez de un OR ("rechazar solo si AMBOS
                              son negativos"): price=-1+quantity=2 pasa,
                              aunque /price solo ya lo rechaza (bug L1:
                              solo se ve combinando parametros).
  19808 invariant_subtotal -> acepta un 'total_override' del cliente y
                              lo usa TAL CUAL en vez de recalcular
                              price*qty*(1-discount) (bug L2: rompe el
                              invariante subtotal==price*quantity).
  19809 replay_claim       -> /order/<id>/claim_reward sin bandera de
                              "ya reclamado": cada llamada identica
                              vuelve a acreditar el reward (bug replay:
                              no es idempotente).

Uso:
    python3 labs/fin_logic_lab.py <escenario> [puerto]
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCENARIOS = {
    "price_negative": 19801,
    "qty_negative": 19802,
    "discount_over_100": 19803,
    "status_force_paid": 19804,
    "validated_control": 19805,
    "coupon_race": 19806,
    "multi_field": 19807,
    "invariant_subtotal": 19808,
    "replay_claim": 19809,
}

ESTADOS_PROTEGIDOS = ("paid", "completed", "refunded")
ESTADOS_VALIDOS = ("pending", "paid", "completed", "refunded", "cancelled")


def _seed_order():
    return {"id": 5001, "owner_id": 7, "price": 100.0, "qty": 2,
            "discount_pct": 0, "status": "pending",
            "claimed": False, "reward_balance": 0}


def _total(order):
    if "_total_override" in order:
        return order["_total_override"]
    sub = order["price"] * order["qty"]
    return round(sub * (1 - order["discount_pct"] / 100.0), 4)


class Store:
    """Estado en memoria del lab, un pedido + un cupon de un solo uso."""

    def __init__(self, scenario):
        self.scenario = scenario
        self.lock = threading.Lock()
        self.order = _seed_order()
        self.coupons = {"SAVE10": {"uses_left": 1}}

    def snapshot(self):
        o = dict(self.order)
        o["total"] = _total(self.order)
        o.pop("_total_override", None)
        return o


def _role_of(headers):
    role = headers.get("X-Fin-Role", "anon")
    user = headers.get("X-Fin-User", "")
    return role, user


def _owns(store, role, user):
    if role == "admin":
        return True
    if role == "subscriber":
        try:
            return int(user) == store.order["owner_id"]
        except (TypeError, ValueError):
            return False
    return False


def _coerce_number(raw):
    """Intenta castear a numero; devuelve (valor, es_numero_valido)."""
    if raw is None:
        return None, False
    if isinstance(raw, list):
        return raw, False  # array: nunca es numero valido
    try:
        if isinstance(raw, str) and raw.strip() == "":
            return raw, False
        f = float(raw)
        return f, True
    except (TypeError, ValueError):
        return raw, False


def _reject(handler, code, error):
    handler._send(code, {"ok": False, "error": error})


class Handler(BaseHTTPRequestHandler):
    server_version = "FinLogicLab/0.97"

    def log_message(self, fmt, *args):  # silencio: lab determinista
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return {}

    # ------------------------------------------------------------ GET
    def do_GET(self):
        store = self.server.store
        if self.path.startswith("/order/"):
            self._send(200, {"ok": True, "order": store.snapshot()})
            return
        self._send(404, {"ok": False, "error": "not_found"})

    # ----------------------------------------------------------- POST
    def do_POST(self):
        store = self.server.store
        role, user = _role_of(self.headers)
        body = self._read_json()

        if self.path.startswith("/order/") and self.path.endswith("/price"):
            self._mutate_amount(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith("/qty"):
            self._mutate_qty(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/discount"):
            self._mutate_discount(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/status"):
            self._mutate_status(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith("/pay"):
            self._pay_gateway(store, role, body)
        elif self.path.startswith("/coupon/") and self.path.endswith(
                "/redeem"):
            self._redeem_coupon(store, body)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/reset"):
            self._reset_order(store)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/bulk_update"):
            self._bulk_update(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/subtotal_override"):
            self._subtotal_override(store, role, user, body)
        elif self.path.startswith("/order/") and self.path.endswith(
                "/claim_reward"):
            self._claim_reward(store, role, user, body)
        else:
            self._send(404, {"ok": False, "error": "not_found"})

    def _reset_order(self, store):
        """Solo arnes de pruebas: vuelve el pedido Y el cupon al estado
        semilla, para que cada bateria de mutaciones (o cada ronda de
        FIN-RACE-ENGINE) arranque limpia y no contamine la siguiente."""
        with store.lock:
            store.order = _seed_order()
            store.coupons = {"SAVE10": {"uses_left": 1}}
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    # ------------------------------------------------------- mutations
    def _mutate_amount(self, store, role, user, body):
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        raw = body.get("price")
        val, is_num = _coerce_number(raw)
        if not is_num:
            return _reject(self, 400, "invalid_type")
        vulnerable = store.scenario == "price_negative"
        if not vulnerable and val <= 0:
            return _reject(self, 400, "price_must_be_positive")
        with store.lock:
            store.order["price"] = val
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _mutate_qty(self, store, role, user, body):
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        raw = body.get("qty")
        val, is_num = _coerce_number(raw)
        if not is_num:
            return _reject(self, 400, "invalid_type")
        vulnerable = store.scenario == "qty_negative"
        if not vulnerable:
            if val < 1 or val != int(val) or val > 10000:
                return _reject(self, 400, "qty_out_of_range")
            val = int(val)
        with store.lock:
            store.order["qty"] = val
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _mutate_discount(self, store, role, user, body):
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        raw = body.get("discount_pct")
        val, is_num = _coerce_number(raw)
        if not is_num:
            return _reject(self, 400, "invalid_type")
        vulnerable = store.scenario == "discount_over_100"
        if not vulnerable and not (0 <= val <= 100):
            return _reject(self, 400, "discount_out_of_range")
        with store.lock:
            store.order["discount_pct"] = val
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _mutate_status(self, store, role, user, body):
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        raw = body.get("status")
        if isinstance(raw, list) or not isinstance(raw, str):
            return _reject(self, 400, "invalid_type")
        vulnerable = store.scenario == "status_force_paid"
        if raw in ESTADOS_PROTEGIDOS and not vulnerable:
            return _reject(self, 403,
                           "status_change_requires_payment_gateway")
        if raw not in ESTADOS_VALIDOS:
            return _reject(self, 400, "invalid_status_enum")
        with store.lock:
            store.order["status"] = raw
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _bulk_update(self, store, role, user, body):
        """L1: endpoint COMBINADO. En el escenario 'multi_field' valida
        con un AND en vez de un OR (bug clasico de logica booleana
        invertida): solo rechaza si AMBOS campos son negativos. En
        cualquier otro escenario valida cada campo por separado
        (igual que /price y /qty), asi que el bug SOLO se ve aca."""
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        price, is_num_p = _coerce_number(body.get("price"))
        qty, is_num_q = _coerce_number(body.get("quantity"))
        if not is_num_p or not is_num_q:
            return _reject(self, 400, "invalid_type")
        if store.scenario == "multi_field":
            # BUG: AND en vez de OR -> price=-1 + qty=2 pasa de largo
            if price < 0 and qty < 0:
                return _reject(self, 400, "bulk_values_invalid")
        else:
            if price < 0:
                return _reject(self, 400, "price_must_be_positive")
            if qty < 1 or qty != int(qty):
                return _reject(self, 400, "qty_out_of_range")
            qty = int(qty)
        with store.lock:
            store.order["price"] = price
            store.order["qty"] = qty
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _subtotal_override(self, store, role, user, body):
        """L2: en el escenario 'invariant_subtotal' confia en un
        'total_override' enviado por el cliente SIN recalcular desde
        price*qty*(1-discount). En cualquier otro escenario el campo
        se ignora: el total SIEMPRE se recalcula server-side."""
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        override, is_num = _coerce_number(body.get("total_override"))
        with store.lock:
            if store.scenario == "invariant_subtotal" and is_num:
                store.order["_total_override"] = override
            else:
                store.order.pop("_total_override", None)
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _claim_reward(self, store, role, user, body):
        """REPLAY: en el escenario 'replay_claim' no hay bandera de
        'ya reclamado': cada llamada identica vuelve a acreditar el
        reward (bug de idempotencia). En cualquier otro escenario,
        la segunda llamada es un no-op (ya reclamado)."""
        if role == "anon":
            return _reject(self, 401, "auth_required")
        if not _owns(store, role, user):
            return _reject(self, 403, "not_owner")
        REWARD = 50
        with store.lock:
            if store.scenario == "replay_claim":
                store.order["reward_balance"] += REWARD
                store.order["claimed"] = True
            else:
                if not store.order["claimed"]:
                    store.order["reward_balance"] += REWARD
                    store.order["claimed"] = True
                else:
                    snap = store.snapshot()
                    self._send(409, {"ok": False, "error":
                                     "already_claimed", "order": snap})
                    return
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _pay_gateway(self, store, role, _body):
        """Flujo LEGITIMO: solo el rol 'gateway' puede confirmar pago."""
        if role != "gateway":
            return _reject(self, 403, "gateway_only")
        with store.lock:
            store.order["status"] = "paid"
            snap = store.snapshot()
        self._send(200, {"ok": True, "order": snap})

    def _redeem_coupon(self, store, body):
        """coupon_race: ventana TOCTOU deliberada (check, sleep, act)."""
        code = body.get("code", "")
        coupon = store.coupons.get(code)
        if not coupon:
            return _reject(self, 404, "coupon_not_found")
        if store.scenario != "coupon_race":
            with store.lock:
                if coupon["uses_left"] <= 0:
                    return _reject(self, 409, "coupon_already_used")
                coupon["uses_left"] -= 1
            return self._send(200, {"ok": True, "uses_left":
                                    coupon["uses_left"]})
        # vulnerable: check y decremento SIN lock, con ventana de carrera
        if coupon["uses_left"] <= 0:
            return _reject(self, 409, "coupon_already_used")
        time.sleep(0.05)  # ventana deliberada para la carrera
        coupon["uses_left"] -= 1
        self._send(200, {"ok": True, "uses_left": coupon["uses_left"]})


def run(scenario: str, port: int = 0):
    if scenario not in SCENARIOS:
        print("escenarios validos: %s" % ", ".join(SCENARIOS))
        sys.exit(1)
    port = port or SCENARIOS[scenario]
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.store = Store(scenario)
    print("fin_logic_lab[%s] escuchando en http://127.0.0.1:%d "
          "(pedido semilla id=5001 owner=7 price=100 qty=2)" %
          (scenario, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_logic_lab.py <escenario> [puerto]")
        print("escenarios: %s" % ", ".join(SCENARIOS))
        sys.exit(1)
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    run(sys.argv[1], p)
