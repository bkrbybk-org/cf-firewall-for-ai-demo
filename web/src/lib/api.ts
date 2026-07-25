// Typed wrappers around the Worker's JSON endpoints.
import type {
  Analytics,
  ChatResponse,
  ChatTurn,
  ExtractResponse,
  GatewayAnalytics,
  GatewayMeta,
  ModelsResponse,
  Neurons,
  PromptAnalytics,
  PromptLog,
  Usage,
  Verdict,
} from "./types";

export async function getModels(): Promise<ModelsResponse> {
  const r = await fetch("/api/models");
  return r.json();
}

export async function getVerdict(ray: string): Promise<Verdict> {
  const r = await fetch("/api/verdict?ray=" + encodeURIComponent(ray));
  return r.json();
}

export async function getNeurons(): Promise<Neurons> {
  const r = await fetch("/api/neurons");
  return r.json();
}

export async function getAnalytics(hours: number): Promise<Analytics> {
  const r = await fetch("/api/analytics?hours=" + hours);
  return r.json();
}

export async function getGatewayAnalytics(gatewayId: string, hours: number): Promise<GatewayAnalytics> {
  const qs = new URLSearchParams({ hours: String(hours) });
  if (gatewayId) qs.set("gatewayId", gatewayId);
  const r = await fetch("/api/gateway-analytics?" + qs);
  return r.json();
}

export async function getPromptLog(opts: { route?: string; outcome?: string; limit?: number } = {}): Promise<PromptLog> {
  const qs = new URLSearchParams();
  if (opts.route) qs.set("route", opts.route);
  if (opts.outcome) qs.set("outcome", opts.outcome);
  if (opts.limit) qs.set("limit", String(opts.limit));
  const r = await fetch("/api/prompt-log?" + qs);
  return r.json();
}

export async function getPromptAnalytics(hours = 0): Promise<PromptAnalytics> {
  const r = await fetch("/api/prompt-analytics?hours=" + hours);
  return r.json();
}

export async function clearPromptLog(): Promise<{ cleared?: boolean; error?: string }> {
  const r = await fetch("/api/prompt-log", { method: "DELETE" });
  return r.json();
}

export interface ChatRequest {
  prompt: string;
  model?: string;
  systemPrompt?: string;
  history?: ChatTurn[];
  stream?: boolean;
  gateway?: boolean; // route inference through AI Gateway
  gatewayId?: string; // gateway only — which configured gateway to use
  skipCache?: boolean; // gateway only
  cacheTtl?: number; // gateway only
}

// Non-stream result: status + raw text + parsed JSON (block pages aren't JSON).
export interface ChatJsonResult {
  mode: "json";
  status: number;
  contentType: string;
  raw: string;
  data: ChatResponse | null;
}

// Stream result: the fully assembled text plus usage if the model emitted it,
// and gateway metadata if the trailing gateway event was present.
export interface ChatStreamResult {
  mode: "stream";
  status: number;
  ray: string | null;
  text: string;
  usage: Usage | null;
  gateway: GatewayMeta | null;
}

export type ChatResult = ChatJsonResult | ChatStreamResult;

// POST /api/chat. With stream:true the server passes through the model's SSE
// stream; tokens are delivered via onToken as they arrive. Blocked requests
// (WAF acts before the Worker) come back as HTML/JSON regardless of the
// stream flag, so the content-type decides which path parses the response.
export async function postChat(
  body: ChatRequest,
  onToken?: (token: string) => void,
): Promise<ChatResult> {
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const contentType = res.headers.get("content-type") || "";
  const rayHeader = res.headers.get("cf-ray");

  if (!contentType.includes("text/event-stream")) {
    const raw = await res.text();
    let data: ChatResponse | null = null;
    try {
      data = JSON.parse(raw);
    } catch {
      /* not JSON (block page) */
    }
    if (data && rayHeader && !data.ray) data.ray = rayHeader;
    return {
      mode: "json",
      status: res.status,
      contentType,
      raw,
      data: data ?? (rayHeader ? { ray: rayHeader } : null),
    };
  }

  // SSE: lines of `data: {...}` ending with `data: [DONE]`. Token lives in
  // `response` (most models) or `choices[0].delta.content|reasoning`
  // (OpenAI-shape + reasoning models). Some models emit usage in a late chunk.
  const reader = res.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let text = "";
  let usage: Usage | null = null;
  let gateway: GatewayMeta | null = null;
  const handleLine = (line: string) => {
    if (!line.startsWith("data:")) return;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") return;
    try {
      const j = JSON.parse(payload) as {
        response?: unknown;
        choices?: { delta?: { content?: unknown; reasoning?: unknown } }[];
        usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
        gateway?: GatewayMeta; // trailing event appended by the Worker for gateway routes
      };
      if (j.gateway) gateway = j.gateway;
      const delta = j.choices?.[0]?.delta;
      const tok =
        typeof j.response === "string"
          ? j.response
          : typeof delta?.content === "string"
            ? delta.content
            : typeof delta?.reasoning === "string"
              ? delta.reasoning
              : "";
      if (tok) {
        text += tok;
        onToken?.(tok);
      }
      if (j.usage && typeof j.usage.prompt_tokens === "number") {
        usage = {
          prompt_tokens: j.usage.prompt_tokens,
          completion_tokens: j.usage.completion_tokens ?? 0,
          total_tokens: j.usage.total_tokens ?? 0,
          estimated: false,
        };
      }
    } catch {
      /* ignore partial / non-JSON lines */
    }
  };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) handleLine(line);
  }
  if (buffer) handleLine(buffer);

  return { mode: "stream", status: res.status, ray: rayHeader, text, usage, gateway };
}

// POST /api/extract — file → text (unscanned; see ExtractResponse).
export async function postExtract(file: File): Promise<{ status: number; data: ExtractResponse }> {
  const form = new FormData();
  form.append("file", file, file.name);
  const res = await fetch("/api/extract", { method: "POST", body: form });
  let data: ExtractResponse;
  try {
    data = await res.json();
  } catch {
    data = { error: `HTTP ${res.status}` };
  }
  return { status: res.status, data };
}

