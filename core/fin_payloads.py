#!/usr/bin/env python3
"""FIN-PAYLOADS (v0.97.0): catalogo CERRADO de mutaciones de logica
financiera, una bateria por tipo semantico (AMOUNT/QTY/DISCOUNT/STATUS/
OBJECT_ID).

Esto NO es un fuzzer: cada mutacion es una hipotesis de vulnerabilidad
concreta y declarada, con su contraparte "si el target valida bien".
fin_logic_probe.py nunca manda un valor que no este en este catalogo.

Cada entrada:
  nombre            id corto (sirve para logs y para casos RC-000xxx)
  valor             el valor mutado. Representaciones especiales:
                       None          -> campo ausente/null
                       list [x]      -> encodear como array:
                                        "campo[]=x" (confusion de tipo)
  hipotesis         que pasaria si el target es vulnerable
  esperado_seguro   que deberia pasar si el target VALIDA bien
                     (rechazo 4xx, clamp, o veto por rol/estado)
  riesgo            BENEFICIO_ATACANTE | ESTADO_ROTO | CONTROL
                     (CONTROL = no es ataque, es la vara de comparacion:
                     un valor benigno que SIEMPRE deberia aceptarse)

El oraculo de impacto (fin_logic_probe._evaluate_benefit) solo escala
a hallazgo las mutaciones con riesgo BENEFICIO_ATACANTE o ESTADO_ROTO
cuyo efecto observado calce con la hipotesis declarada. Un ESTADO_ROTO
nunca sube a FIN-IMPACT-DEMO solo (puede confundir, no corrompe un
balance); solo BENEFICIO_ATACANTE puede llegar a ese techo.

Uso:
    python3 core/fin_payloads.py [--json]
"""
import json
import sys
from typing import Any, Dict, List

# ------------------------------------------------------------------ AMOUNT
AMOUNT: List[Dict[str, Any]] = [
    {"nombre": "amount_negative", "valor": -1,
     "hipotesis": "el servidor acepta un monto negativo y lo resta "
                  "del total final, beneficiando al atacante",
     "esperado_seguro": "rechazo (4xx) o clamp a 0, total sin cambio "
                        "favorable",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "amount_zero", "valor": 0,
     "hipotesis": "el servidor acepta precio 0 y confirma el objeto "
                  "como si estuviera pagado/cerrado",
     "esperado_seguro": "rechazo (4xx) si el precio minimo valido es > 0",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "amount_tiny_decimal", "valor": 0.001,
     "hipotesis": "redondeo interno trunca a 0 en moneda entera, "
                  "regalando el objeto",
     "esperado_seguro": "redondeo seguro o rechazo de precision invalida",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "amount_huge", "valor": 999999999999,
     "hipotesis": "overflow/float impreciso corrompe el total "
                  "(desborde silencioso)",
     "esperado_seguro": "rechazo por rango invalido",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "amount_string", "valor": "abc",
     "hipotesis": "coercion de tipo insegura castea el string a 0, "
                  "rompiendo el calculo del total",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "amount_array", "valor": ["10"],
     "hipotesis": "el framework castea el array a 1 o crashea, "
                  "abriendo un bypass de validacion de tipo",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "amount_null", "valor": None,
     "hipotesis": "la ausencia del campo cae a un default inseguro "
                  "(0 o gratis) en vez de rechazar la operacion",
     "esperado_seguro": "rechazo por campo requerido (4xx)",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "amount_control_valid", "valor": 100,
     "hipotesis": "N/A (control)",
     "esperado_seguro": "el servidor SIEMPRE debe aceptar un monto "
                        "valido normal; si esto falla, el endpoint "
                        "esta roto y el resto de la bateria no es "
                        "confiable",
     "riesgo": "CONTROL"},
]

# --------------------------------------------------------------------- QTY
QTY: List[Dict[str, Any]] = [
    {"nombre": "qty_negative", "valor": -5,
     "hipotesis": "cantidad negativa invierte el signo del total "
                  "(el atacante termina debiendo menos o recibiendo "
                  "credito)",
     "esperado_seguro": "rechazo (4xx) o clamp a un minimo >= 1",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "qty_zero", "valor": 0,
     "hipotesis": "cantidad 0 aceptada permite 'cerrar' el pedido sin "
                  "comprometer unidades reales",
     "esperado_seguro": "rechazo (4xx) si el minimo valido es 1",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "qty_decimal", "valor": 0.5,
     "hipotesis": "cantidad fraccionaria rompe la logica de stock/"
                  "unidades enteras (inventario inconsistente)",
     "esperado_seguro": "rechazo de tipo o redondeo seguro hacia arriba",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "qty_overflow", "valor": 2147483648,
     "hipotesis": "overflow de entero de 32 bits hace que la cantidad "
                  "se interprete como negativa internamente",
     "esperado_seguro": "rechazo por rango invalido",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "qty_array", "valor": ["2"],
     "hipotesis": "confusion de tipo array bypasea la validacion "
                  "numerica de cantidad",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "qty_control_valid", "valor": 2,
     "hipotesis": "N/A (control)",
     "esperado_seguro": "el servidor SIEMPRE debe aceptar una "
                        "cantidad valida normal",
     "riesgo": "CONTROL"},
]

# --------------------------------------------------------------- DISCOUNT
DISCOUNT: List[Dict[str, Any]] = [
    {"nombre": "discount_over_100", "valor": 150,
     "hipotesis": "descuento > 100% deja el total final NEGATIVO: "
                  "el sistema le 'debe' dinero al atacante",
     "esperado_seguro": "clamp a 100% o rechazo (4xx)",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "discount_negative", "valor": -20,
     "hipotesis": "un descuento negativo se interpreta como recargo "
                  "o invierte signo y aumenta el descuento real "
                  "aplicado",
     "esperado_seguro": "rechazo (4xx) o clamp a 0%",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "discount_string", "valor": "free",
     "hipotesis": "coercion insegura interpreta el string como 100% "
                  "o como verdadero booleano de 'gratis'",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "discount_array", "valor": ["50"],
     "hipotesis": "confusion de tipo array bypasea el tope de "
                  "descuento",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "discount_control_valid", "valor": 10,
     "hipotesis": "N/A (control)",
     "esperado_seguro": "el servidor SIEMPRE debe aceptar un "
                        "descuento valido dentro de rango (0-100)",
     "riesgo": "CONTROL"},
]

# ----------------------------------------------------------------- STATUS
# Lista cerrada de estados "protegidos": solo deberian alcanzarse via
# el endpoint interno de gateway de pago, nunca por PATCH directo del
# dueno del objeto.
ESTADOS_PROTEGIDOS = ("paid", "completed", "refunded")

STATUS: List[Dict[str, Any]] = [
    {"nombre": "status_paid", "valor": "paid",
     "hipotesis": "el endpoint publico acepta la transicion directa a "
                  "'paid' sin pasar por el gateway de pago real",
     "esperado_seguro": "rechazo (403/409): solo el gateway interno "
                        "puede setear este estado",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "status_completed", "valor": "completed",
     "hipotesis": "igual a status_paid, con el nombre alternativo de "
                  "estado final usado por otros plugins",
     "esperado_seguro": "rechazo (403/409)",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "status_refunded", "valor": "refunded",
     "hipotesis": "el atacante fuerza un estado de reembolso para "
                  "disparar logica downstream (reembolso real, stock "
                  "repuesto) sin que haya ocurrido un reembolso",
     "esperado_seguro": "rechazo (403/409)",
     "riesgo": "BENEFICIO_ATACANTE"},
    {"nombre": "status_invalid_enum", "valor": "xyz_estado_invalido",
     "hipotesis": "el backend no valida contra una lista cerrada de "
                  "estados y acepta cualquier string, corrompiendo la "
                  "maquina de estados",
     "esperado_seguro": "rechazo (400) por estado fuera del enum",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "status_array", "valor": ["paid"],
     "hipotesis": "confusion de tipo array bypasea la validacion de "
                  "estado",
     "esperado_seguro": "rechazo de tipo (4xx)",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "status_control_valid", "valor": "pending",
     "hipotesis": "N/A (control)",
     "esperado_seguro": "el servidor SIEMPRE debe aceptar el estado "
                        "inicial/neutral valido",
     "riesgo": "CONTROL"},
]

# -------------------------------------------------------------- OBJECT_ID
# Nota de alcance (ver limitaciones en el modulo probe): estas mutaciones
# son de CONTEXTO, no de ataque BAC en si (eso lo prueba bac_proof.py).
# Aqui solo sirven para que el probe confirme que esta operando sobre el
# objeto correcto y para dejar sembrado el gancho de una integracion
# futura con bac_proof (candidato IDOR + candidato logico = mismo
# endpoint, doble impacto).
OBJECT_ID: List[Dict[str, Any]] = [
    {"nombre": "id_nonexistent", "valor": 999999999,
     "hipotesis": "el servidor crashea o filtra un error interno con "
                  "un id que no existe (information disclosure menor)",
     "esperado_seguro": "404/400 limpio sin traza ni stacktrace",
     "riesgo": "ESTADO_ROTO"},
    {"nombre": "id_self", "valor": "__SELF_ID__",
     "hipotesis": "N/A (control)",
     "esperado_seguro": "usar el propio id debe comportarse igual que "
                        "el baseline: si esto falla, el endpoint esta "
                        "roto y el resto de la bateria no es confiable",
     "riesgo": "CONTROL"},
]

CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "AMOUNT": AMOUNT,
    "QTY": QTY,
    "DISCOUNT": DISCOUNT,
    "STATUS": STATUS,
    "OBJECT_ID": OBJECT_ID,
}


def payloads_for(tipo: str, max_ataques: int = 4) -> List[Dict[str, Any]]:
    """Mutaciones priorizadas para un tipo: hasta `max_ataques` con
    riesgo != CONTROL + SIEMPRE el/los controles (no cuentan contra el
    presupuesto de ataque, son obligatorios).
    """
    todas = CATALOG.get(tipo, [])
    ataques = [p for p in todas if p["riesgo"] != "CONTROL"][:max_ataques]
    controles = [p for p in todas if p["riesgo"] == "CONTROL"]
    return ataques + controles


if __name__ == "__main__":
    if "--json" in sys.argv:
        print(json.dumps(CATALOG, indent=1, ensure_ascii=False))
    else:
        for tipo, payloads in CATALOG.items():
            print("== %s (%d mutaciones) ==" % (tipo, len(payloads)))
            for p in payloads:
                print("  [%s] valor=%r riesgo=%s" % (
                    p["nombre"], p["valor"], p["riesgo"]))
