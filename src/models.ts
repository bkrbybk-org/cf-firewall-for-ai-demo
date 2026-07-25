// Model registry: the single source of truth for both the UI dropdown and
// per-request cost estimation — one row per model, so label + price can never
// drift apart. To add/remove a model, edit this list only.

export interface ModelEntry {
  id: string; // Workers AI model id
  label: string; // shown in the UI dropdown
  priceIn: number; // USD per 1,000,000 input tokens
  priceOut: number; // USD per 1,000,000 output tokens
}

// Pricing from https://developers.cloudflare.com/workers-ai/platform/pricing/ (2026-07).
// Order = display order in the dropdown; first entry is the default.
export const MODEL_REGISTRY: ModelEntry[] = [
  { id: "@cf/meta/llama-3.2-3b-instruct", label: "Llama 3.2 3B", priceIn: 0.027, priceOut: 0.201 },
  { id: "@cf/google/gemma-4-26b-a4b-it", label: "Gemma 4 26B", priceIn: 0.1, priceOut: 0.3 },
  { id: "@cf/mistral/mistral-7b-instruct-v0.1", label: "Mistral 7B", priceIn: 0.110, priceOut: 0.190 },
  // { id: "@cf/openai/gpt-oss-20b", label: "GPT-OSS 20B", priceIn: 0.200, priceOut: 0.300 },
  { id: "@cf/qwen/qwen3-30b-a3b-fp8", label: "Qwen3 30B", priceIn: 0.051, priceOut: 0.335 },
  // { id: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b", label: "DeepSeek R1 Distill 32B", priceIn: 0.497, priceOut: 4.881 },
  // { id: "@cf/meta/llama-guard-3-8b", label: "Llama Guard 3 8B", priceIn: 0.484, priceOut: 0.030 },

];

export const DEFAULT_MODEL = MODEL_REGISTRY[0].id;
export const ALLOWED_IDS = new Set(MODEL_REGISTRY.map((m) => m.id));
export const MODEL_BY_ID = new Map(MODEL_REGISTRY.map((m) => [m.id, m]));
