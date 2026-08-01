import { useEffect, useState } from "react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { NeuronChip } from "../components/NeuronChip";
import { SystemPromptPanel } from "../components/SystemPromptPanel";
import { GatewaySettingsPanel, type GatewaySettingsValue } from "../components/GatewaySettingsPanel";
import { AttackLibrary } from "../components/AttackLibrary";
import { Chat } from "../components/Chat";
import { DemoMode } from "../components/DemoMode";
import { useChat, type Route } from "../hooks/useChat";
import { useNeurons } from "../hooks/useNeurons";
import { getModels } from "../lib/api";
import type { GatewayLimits, GatewayOption, Model } from "../lib/types";

const numOrUndef = (s: string, min?: number, max?: number): number | undefined => {
  if (s.trim() === "") return undefined;
  const n = Number(s);
  if (Number.isNaN(n)) return undefined;
  const rounded = Math.round(n);
  return Math.max(min ?? -Infinity, Math.min(max ?? Infinity, rounded));
};

const DEFAULT_GATEWAY_SETTINGS: GatewaySettingsValue = {
  metadata: "",
  skipCache: false,
  cacheTtl: "",
  cacheKey: "",
  collectLog: "",
  requestTimeoutMs: "",
  maxAttempts: "",
  retryDelayMs: "",
  backoff: "",
};

export function FirewallPage() {
  const [models, setModels] = useState<Model[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [defaultPrompt, setDefaultPrompt] = useState("");
  const [maxLen, setMaxLen] = useState(2000);
  const [stream, setStream] = useState(true);
  const [multiTurn, setMultiTurn] = useState(false);
  const [route, setRoute] = useState<Route>("direct");
  const [gateways, setGateways] = useState<GatewayOption[]>([]);
  const [gatewayId, setGatewayId] = useState("");
  // Dynamic Routing: a route name configured in the gateway dashboard.
  const [dynamicRoute, setDynamicRoute] = useState("");
  // Every other per-request AI Gateway REST setting, edited as one group in
  // the sidebar panel (see GatewaySettingsPanel).
  const [gatewaySettings, setGatewaySettings] = useState<GatewaySettingsValue>(DEFAULT_GATEWAY_SETTINGS);
  // Numeric caps for those settings, served by /api/models so the Worker stays
  // the only place they are defined. Undefined until it loads — the Worker
  // clamps every value server-side regardless, so nothing can slip through.
  const [limits, setLimits] = useState<GatewayLimits | undefined>();
  // Skip writing a turn to the D1 prompt_log table (redacted prompt/reply
  // history) — independent of AI Gateway's own request log.
  const [excludeFromLog, setExcludeFromLog] = useState(false);
  const [input, setInput] = useState("");
  const { state: neurons, refresh } = useNeurons();
  const chat = useChat({
    models,
    model: selectedModel,
    systemPrompt,
    stream,
    multiTurn,
    route,
    gatewayId,
    skipCache: gatewaySettings.skipCache,
    dynamicRoute,
    routeMetadata: gatewaySettings.metadata,
    gatewaySettings: {
      cacheTtl: numOrUndef(gatewaySettings.cacheTtl, 1),
      cacheKey: gatewaySettings.cacheKey.trim().slice(0, 128) || undefined,
      collectLog: gatewaySettings.collectLog === "" ? undefined : gatewaySettings.collectLog === "on",
      requestTimeoutMs: numOrUndef(gatewaySettings.requestTimeoutMs, 1),
      maxAttempts: numOrUndef(gatewaySettings.maxAttempts, 1, limits?.maxAttempts),
      retryDelayMs: numOrUndef(gatewaySettings.retryDelayMs, 0, limits?.retryDelayMs),
      backoff: gatewaySettings.backoff || undefined,
    },
    excludeFromLog,
    onSent: refresh,
  });

  useEffect(() => {
    getModels()
      .then((data) => {
        setModels(data.models);
        setSelectedModel(data.default);
        setDefaultPrompt(data.defaultSystemPrompt);
        setSystemPrompt(data.defaultSystemPrompt);
        setMaxLen(data.maxSystemPromptLen);
        setGateways(data.gateways ?? []);
        setGatewayId(data.defaultGateway ?? data.gateways?.[0]?.id ?? "");
        setLimits(data.limits);
      })
      .catch(() => {});
  }, []);

  return (
    <div className="flex h-full flex-col">
      <Header
        title="Cloudflare AI Security for Apps"
        subtitle={
          <>
            Chat inspected at the edge · WAF fields <code className="font-mono">cf.llm.*</code> · route via Workers AI or
            AI Gateway
          </>
        }
        actions={
          <>
            <DemoMode sendPrompt={chat.sendPrompt} chatBusy={chat.busy} onStart={chat.clear} />
            <ThemeToggle />
            <NeuronChip state={neurons} />
          </>
        }
      />

      {/* Three fixed panes side by side only survive at lg, where each owns
          its own scroll. Stacked below that they cannot all fit one viewport
          — the sidebar and library are shrink-0 with far more content than
          the screen — so the column scrolls as a whole instead. */}
      <main className="flex min-h-0 flex-1 flex-col overflow-y-auto lg:flex-row lg:overflow-hidden">
        {/* Left column: session-level setup. The wrapper owns the width,
            border and scrolling so the panels inside are plain sections. */}
        <div className="flex w-full shrink-0 flex-col overflow-y-auto border-b border-line bg-surface lg:w-[300px] lg:border-b-0 lg:border-r">
          <SystemPromptPanel
            value={systemPrompt}
            onChange={setSystemPrompt}
            defaultPrompt={defaultPrompt}
            maxLen={maxLen}
          />
          <GatewaySettingsPanel
            active={route === "gateway"}
            value={gatewaySettings}
            onChange={setGatewaySettings}
            limits={limits}
          />
        </div>
        <Chat
          models={models}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
          stream={stream}
          onStreamChange={setStream}
          multiTurn={multiTurn}
          onMultiTurnChange={setMultiTurn}
          excludeFromLog={excludeFromLog}
          onExcludeFromLogChange={setExcludeFromLog}
          route={route}
          onRouteChange={setRoute}
          gateways={gateways}
          gatewayId={gatewayId}
          onGatewayIdChange={setGatewayId}
          dynamicRoute={dynamicRoute}
          onDynamicRouteChange={setDynamicRoute}
          messages={chat.messages}
          busy={chat.busy}
          turnCount={chat.turnCount}
          onSend={chat.sendPrompt}
          onClear={chat.clear}
          input={input}
          setInput={setInput}
          systemPrompt={systemPrompt}
        />
        <AttackLibrary onPick={setInput} />
      </main>

      <footer className="shrink-0 border-t border-line bg-surface px-5 py-2 text-[11.5px] text-muted">
        Served on <code className="font-mono">cf-ai-waf-demo.nttlab.org</code> · detections fire only on the{" "}
        <code className="font-mono">cf-llm</code>-labeled endpoint · view hits in Security → Analytics/Events.
      </footer>
    </div>
  );
}
