// Points Swagger UI at the Worker's own OpenAPI document. The URL is relative,
// so the same page works on prod, on `wrangler dev`, and behind Cloudflare Access
// (the browser already holds the Access session, so Try it out is authorised).
window.addEventListener("load", function () {
  window.ui = SwaggerUIBundle({
    url: "/api/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    docExpansion: "list",
    defaultModelsExpandDepth: 0,
    // Do not stash a pasted service-token secret in localStorage.
    persistAuthorization: false,
  });
});
