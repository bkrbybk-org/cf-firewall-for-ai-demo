// Static configuration: pricing constants and demo defaults.
// Model registry lives in models.ts.

// Reply length cap. Reasoning models (Gemma 4, DeepSeek R1) burn tokens on
// their reasoning phase first — 512 truncated them before any final answer.
export const MAX_REPLY_TOKENS = 2048;

export const DEFAULT_SYSTEM_PROMPT =
  "You are a helpful assistant in a Cloudflare security demo. " +
  "Answer briefly (a few sentences at most). Never repeat back personal data.";
export const MAX_SYSTEM_PROMPT_LEN = 2000;

// Multi-turn conversation caps (server-enforced on the history[] field).
export const MAX_HISTORY_TURNS = 10;
export const MAX_HISTORY_CHARS = 8000;

// Workers AI Neuron pricing, from the pricing page above.
export const FREE_DAILY_NEURONS = 10_000;
export const OVERAGE_USD_PER_1K_NEURONS = 0.011;

export const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
export const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// AI Gateway fallback name if CF_AI_GATEWAY_ID isn't set. "default" auto-creates.
export const DEFAULT_AI_GATEWAY_ID = "default";

// AI Gateway Dynamic Routing. A route is addressed by putting its name in the
// `model` field of the OpenAI-compatible endpoint, prefixed with "dynamic/".
// The Workers AI binding only accepts "@cf/…" or "author/model" model ids, so
// routes are unreachable through env.AI.run() — they need this REST path.
export const DYNAMIC_ROUTE_PREFIX = "dynamic/";
export const OPENAI_CHAT_PATH = "/ai/v1/chat/completions";
// Same charset the gateway-id checks use.
export const ROUTE_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
