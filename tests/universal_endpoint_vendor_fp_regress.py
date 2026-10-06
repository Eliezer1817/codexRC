#!/usr/bin/env python3
# ============================================================
# codexRC - UNIVERSAL ENDPOINT: FP de codigo vendoreado real (v0.99.1)
# ------------------------------------------------------------
# Cada caso reproduce, minimizado, un falso positivo MEDIDO el
# 2026-10-06 al correr v0.99.0 sobre 10 plugins reales de
# wordpress.org (194 "custom_router", 149 reales -> 45 FP):
#   - Braintree SDK (paid-memberships-pro): clientes HTTP salientes
#   - Give: ScriptAsset::get(DIR . 'build/x.php')
#   - LearnPress: LP_Object_Cache::get('k-' . $id . '/' . $k, 'grupo/x')
#   - Bookly / Tutor / Razorpay: $d['options']['x'] = 'wp' (claves de array)
# Y un contraejemplo que DEBE seguir siendo ruta (no sobre-corregir).
# ============================================================
import os, shutil, sys, tempfile
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from core import universal_endpoint as ue

SHOULD_REJECT = {
 "braintree_http_client.php": """<?php
class G { function a($p){ $r = $this->_http->post('/oauth/access_tokens', $p);
  $r = $this->_http->get($this->_config->merchantPath() . '/merchant_accounts?page=' . $p);
  $r = $this->_http->post($u, ['search' => $q]); } }""",
 "asset_loader_static_get.php": """<?php
$a = ScriptAsset::get(GIVE_PLUGIN_DIR . 'build/adminBlocks.asset.php');""",
 "cache_get_two_args.php": """<?php
return LP_Object_Cache::get('question-' . $this->get_id() . '/' . $key, 'learn-press/answer-checked');""",
 "array_keys_options.php": """<?php
$data['options']['bookly_email_gateway'] = 'wp';
$conditions['post']['fields'] = array();
$opts['options']['type'] = $x;""",
}
SHOULD_KEEP = {
 "real_route_variable_handler.php": ("GET", "/api/ghost", """<?php
$app->get('/api/ghost', $handler);"""),
 "real_route_class_handler.php": ("POST", "/categories", """<?php
$app->post('/categories', AddCategoryController::class);"""),
 "real_route_laravel_string.php": ("GET", "/admin/x", """<?php
$router->get('/admin/x', 'DashboardController@index');"""),
}

def run() -> int:
    fails = 0
    for name, code in SHOULD_REJECT.items():
        d = tempfile.mkdtemp(prefix="ue_vfp_")
        try:
            open(os.path.join(d, name), "w").write(code)
            eps = [e for e in ue.discover(d, include_wordpress=False)["endpoints"]]
            ok = len(eps) == 0
            print(f"[reject:{name}] -> {'PASS' if ok else 'FAIL'} "
                  f"{[(e['method'], e['path_raw']) for e in eps]}")
            fails += 0 if ok else 1
        finally:
            shutil.rmtree(d, ignore_errors=True)
    for name, (meth, path, code) in SHOULD_KEEP.items():
        d = tempfile.mkdtemp(prefix="ue_vfp_")
        try:
            open(os.path.join(d, name), "w").write(code)
            eps = ue.discover(d, include_wordpress=False)["endpoints"]
            ok = any(e["method"] == meth and e["path"] == path for e in eps)
            print(f"[keep:{name}] -> {'PASS' if ok else 'FAIL'}")
            fails += 0 if ok else 1
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print(f"\nUniversal Endpoint vendor-FP regress: {fails} fallo(s)")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(run())
