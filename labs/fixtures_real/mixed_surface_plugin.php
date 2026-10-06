<?php
/* Plugin Name: Mixed Surface Test */
// Fixture REAL (no sintetica-simplificada): plugin WP que combina
// superficie clasica (hook wp_ajax, la ve GATES-AUDIT) con un router
// custom embebido en el mismo archivo (Slim-style, NO lo ve
// GATES-AUDIT). Es la misma clase de arquitectura que motivo
// v0.98.0 (hallazgo Amelia Booking, v0.97.0): plugins que mezclan
// WP hooks con su propio router interno.

// --- superficie clasica WP ---
add_action('wp_ajax_do_thing', 'do_thing_handler');
function do_thing_handler() {
    check_ajax_referer('do_thing_nonce');
    $amount = $_POST['amount'];
    echo json_encode(['ok' => true]);
    wp_die();
}

// --- router custom embebido (no es sintaxis WP) ---
class MixedController {
    public function show($request) {
        return true;
    }
}
$app = new \Slim\App();
$app->get('/mixed-plugin/custom/{id}', [MixedController::class, 'show'])
    ->add(new RequireAuth());
