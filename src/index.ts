// Worker entry point: route dispatch only. Handler logic lives in handlers.ts.

import {
  handleAnalytics,
  handleChat,
  handleGatewayAnalytics,
  handleModels,
  handleNeurons,
  handlePromptAnalytics,
  handlePromptLog,
  handleRedTeamRuns,
  handleVerdict,
  handleZoneRules,
} from "./handlers";
import type { Env } from "./types";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);

    switch (url.pathname) {
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
      case "/api/chat":
        // ctx lets the prompt-log write run without blocking the reply.
        return handleChat(request, env, ctx);
      default:
        return env.ASSETS.fetch(request);
    }
  },
} satisfies ExportedHandler<Env>;
