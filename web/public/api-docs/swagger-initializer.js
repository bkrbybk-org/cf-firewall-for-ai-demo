// Points Swagger UI at the Worker's own OpenAPI document — the 3.0.3 rendering,
// so the page shows exactly the file API Shield Schema Validation accepts (it
// rejects 3.1). The URL is relative, so the same page works on prod, on `wrangler
// dev`, and behind Cloudflare Access (the browser already holds the Access
// session, so Try it out is authorised).
//
// `servers` is overwritten with this page's own origin before rendering. The
// Worker fills it from the request URL, which is right on prod, but under
// `wrangler dev` that URL is rewritten to the route's host over http — so an
// unpatched Try it out on localhost would have sent real requests to prod.
window.addEventListener("load", async function () {
  const spec = await fetch("/api/openapi-3.0.json").then((r) => r.json());
  spec.servers = [{ url: window.location.origin }];
  window.ui = SwaggerUIBundle({
    spec,
    dom_id: "#swagger-ui",
    deepLinking: true,
    docExpansion: "list",
    defaultModelsExpandDepth: 0,
    // Do not stash a pasted service-token secret in localStorage.
    persistAuthorization: false,
  });
});
