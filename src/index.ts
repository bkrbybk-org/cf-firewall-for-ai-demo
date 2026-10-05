// Worker entry point: route dispatch only. Handler logic lives in handlers.ts.

import {
  handleAnalytics,
  handleChat,
  handleExternalGuardrails,
  handleExternalGuardrailsTest,
  handleGuardrailPipeline,
  handleExternalGuardrailReport,
  handleGatewayAnalytics,
  handleModels,
  handleNeurons,
  handlePromptAnalytics,
  handlePromptLog,
  handleRedTeamRuns,
  handleVerdict,
  handleZoneRules,
} from "./handlers";
import { openapi } from "./openapi";
import { openapi30For } from "./openapi30";
import type { Env } from "./types";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
      case "/api/openapi.json":
        // Short cache: the document only changes on deploy, but a stale copy
        // after one would make Swagger UI describe the previous API.
        return Response.json(openapi, { headers: { "cache-control": "public, max-age=300" } });
      case "/api/openapi-3.0.json":
        // For Cloudflare API Shield Schema Validation, which only parses OAS 3.0
        // and rejects relative server URLs — so the server is this request's origin.
        return Response.json(openapi30For(url.origin), { headers: { "cache-control": "public, max-age=300" } });
      case "/api/models":
        return handleModels(env);
      case "/api/verdict":
        return handleVerdict(url, env);
      case "/api/zone-rules":
        return handleZoneRules(env);
      case "/api/neurons":
        return handleNeurons(env);
      case "/api/analytics":
        return handleAnalytics(url, env);
      case "/api/gateway-analytics":
        return handleGatewayAnalytics(url, env);
      case "/api/prompt-log":
        return handlePromptLog(request, url, env);
      case "/api/prompt-analytics":
        return handlePromptAnalytics(url, env);
      case "/api/redteam-runs":
        return handleRedTeamRuns(request, url, env);
      case "/api/external-guardrails":
        return handleExternalGuardrails(request, env);
      case "/api/external-guardrails/test":
        return handleExternalGuardrailsTest(request, env);
      case "/api/external-guardrails/pipeline":
        return handleGuardrailPipeline(request, env);
      case "/api/external-guardrails/report":
        return handleExternalGuardrailReport(request, url, env);
      case "/api/chat":
        // ctx lets the prompt-log write run without blocking the reply.
        return handleChat(request, env, ctx);
      default:
        return env.ASSETS.fetch(request);
    }
  },
} satisfies ExportedHandler<Env>;
