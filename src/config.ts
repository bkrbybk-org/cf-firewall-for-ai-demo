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

// AI Gateway fallback name if CF_AI_GATEWAY_ID isn't set. "default" auto-creates.
export const DEFAULT_AI_GATEWAY_ID = "default";
