#!/usr/bin/env python3
# ============================================================
# codexRC - ROUTER LAB (v0.98.0)
# ------------------------------------------------------------
# Fixtures sinteticas de routers distintos para probar
# UNIVERSAL ENDPOINT GRAPH sin depender de un plugin real.
# Ningun fixture representa codigo real de Amelia Booking u
# otro plugin: son arquitecturas sinteticas inspiradas en el
# PATRON observado (custom router + controller + middleware).
# ============================================================
import os
import shutil
import tempfile
from typing import Dict

FIXTURES: Dict[str, str] = {}

FIXTURES["case1_slim.php"] = """<?php
// Caso 1: router estilo Slim, handler [Clase::class, 'metodo']
class BookingController {
    public function create($request, $response) {
        $price = $request->getParsedBody()['price'];
        $qty = $request->getParsedBody()['qty'];
        return $response;
    }
}

$app->post('/api/bookings', [BookingController::class, 'create']);
"""

FIXTURES["case2_psr7.php"] = """<?php
// Caso 2: router PSR-7 custom con ->map('METODO', path, handler)
class PayController {
    public function charge($request) {
        $amount = $request->getParam('amount');
        return $amount;
    }
}

$router->map('POST', '/api/pay', [PayController::class, 'charge']);
"""

FIXTURES["case3_array.php"] = """<?php
// Caso 3: array router, $routes['METODO']['/path'] = handler
class RefundController {
    public function process($request) {
        $total = $request->getAttribute('total');
        return $total;
    }
}

$routes['POST']['/api/refund'] = [RefundController::class, 'process'];
"""

FIXTURES["case4_alias.php"] = """<?php
// Caso 4: dos rutas distintas apuntan al MISMO handler (alias)
class BookingController2 {
    public function create($request) {
        return true;
    }
}

$app->post('/api/book', [BookingController2::class, 'create']);
$app->post('/v1/bookings', [BookingController2::class, 'create']);
"""

FIXTURES["case5_middleware.php"] = """<?php
// Caso 5: ruta con cadena de middleware antes del handler real
class SecureController {
    public function go($request) {
        return true;
    }
}

$app->post('/api/secure', [AuthMiddleware::class, RoleMiddleware::class],
    [SecureController::class, 'go']);
"""

FIXTURES["case6_unresolved.php"] = """<?php
// Caso 6: endpoint detectable pero callback imposible de resolver
// (la variable proviene de un factory externo, sin evidencia local)
$handler = SomeExternalFactory::build();
$app->get('/api/ghost', $handler);
"""

FIXTURES["case7_false.php"] = """<?php
// Caso 7: patron parecido a una ruta pero NO es un endpoint real.
// Logger::post() es un getter/metodo de dominio sin argumento
// que parezca un path -- no debe descubrirse como ruta.
class Logger {
    public function post($message) {
        echo "LOG: " . $message;
    }
}

$logger = new Logger();
$logger->post("User logged in successfully");

// variante: getter comun que casualmente se llama get()
class Cache {
    public function get($key) {
        return $key;
    }
}
$cache = new Cache();
$cache->get("user_123");
"""

FIXTURES["case8_dynamic.php"] = """<?php
// Caso 8 (REGLA 24): ruta con path construido dinamicamente.
// No debe inventarse el valor final del path.
class StatsController {
    public function show($request) {
        return true;
    }
}

$prefix = '/api/v2';
$app->get($prefix . '/stats', [StatsController::class, 'show']);
"""

FIXTURES["case9_dedup.php"] = """<?php
// Caso 9: la MISMA ruta (method+path+handler) es declarada por dos
// fuentes estructurales distintas: llamada ->post() y array router.
class DupController {
    public function go($request) {
        return true;
    }
}

$app->post('/api/dup', [DupController::class, 'go']);
$routes['POST']['/api/dup'] = [DupController::class, 'go'];
"""

FIXTURES["amelia_like.php"] = """<?php
// Fixture SINTETICO inspirado en la CLASE de arquitectura observada
// en Amelia Booking (router custom + controller + contenedor). NO
// representa el codigo real de Amelia: es un patron generico de
// "router propio no-hook" usado para probar REGLA 30 (test especial
// Amelia-like).
class BookingApiController {
    public function create($request) {
        $price = $request->getParsedBody()['price'];
        $qty = $request->getParsedBody()['qty'];
        $discount = $request->getParsedBody()['discount'];
        return $price * $qty - $discount;
    }

    public function cancel($request) {
        $bookingId = $request->getAttribute('bookingId');
        return $bookingId;
    }
}

class Routes {
    public static function routes($app, $container) {
        $app->post('/bookings', [BookingApiController::class, 'create']);
        $app->post('/bookings/{bookingId}/cancel',
            [AuthMiddleware::class],
            [BookingApiController::class, 'cancel']);
    }
}
"""


def build_lab(base_dir: str = None) -> str:
    """Materializa los fixtures en un directorio temporal y devuelve
    su ruta. Si base_dir se omite, crea uno nuevo bajo tempfile."""
    root = base_dir or tempfile.mkdtemp(prefix="codexrc_router_lab_")
    for name, content in FIXTURES.items():
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


def cleanup_lab(root: str) -> None:
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    r = build_lab()
    print(f"lab construido en {r}")
