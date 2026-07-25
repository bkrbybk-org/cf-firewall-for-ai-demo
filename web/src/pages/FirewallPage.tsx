import { useEffect, useState } from "react";
import { Header } from "../components/Header";
import { ThemeToggle } from "../components/ThemeToggle";
import { NeuronChip } from "../components/NeuronChip";
import { SystemPromptPanel } from "../components/SystemPromptPanel";
import { AttackLibrary } from "../components/AttackLibrary";
import { Chat } from "../components/Chat";
import { DemoMode } from "../components/DemoMode";
import { useChat, type Route } from "../hooks/useChat";
import { useNeurons } from "../hooks/useNeurons";
import { getModels } from "../lib/api";
import type { GatewayOption, Model } from "../lib/types";

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
  const [skipCache, setSkipCache] = useState(false);
  // Dynamic Routing (AI Gateway). Empty = today's binding path.
  const [dynamicRoute, setDynamicRoute] = useState("");
  const [routeMetadata, setRouteMetadata] = useState("");
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
    skipCache,
    dynamicRoute,
    routeMetadata,
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

      <main className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <SystemPromptPanel value={systemPrompt} onChange={setSystemPrompt} defaultPrompt={defaultPrompt} maxLen={maxLen} />
        <Chat
          models={models}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
          stream={stream}
          onStreamChange={setStream}
          multiTurn={multiTurn}
          onMultiTurnChange={setMultiTurn}
          route={route}
          onRouteChange={setRoute}
          gateways={gateways}
          gatewayId={gatewayId}
          onGatewayIdChange={setGatewayId}
          skipCache={skipCache}
          onSkipCacheChange={setSkipCache}
          dynamicRoute={dynamicRoute}
          onDynamicRouteChange={setDynamicRoute}
          routeMetadata={routeMetadata}
          onRouteMetadataChange={setRouteMetadata}
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
