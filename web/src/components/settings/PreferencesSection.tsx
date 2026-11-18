// Settings → Your preferences: everything saved in THIS browser (localStorage,
// per viewer). None of it reaches the server or changes what anyone else sees —
// which is the whole reason it is a separate section from System settings.
// Replaces the old "Chat card layout" box that sat between the traffic-flow
// diagram and the provider cards, where it read as one more shared setting.
import { useEffect, useState } from "react";
import { UserRound } from "lucide-react";
import { useBoothFortiModel, useBoothGateway, useBoothModel } from "../../hooks/useBoothGateway";
import { getModels } from "../../lib/api";
import { resolveBoothChoice } from "../../lib/boothGateway";
import type { GatewayOption, ModelsResponse } from "../../lib/types";
import { useGuardrailCardLayout } from "../../hooks/useGuardrailCardLayout";
import { useShowRawResponses } from "../../hooks/useShowRawResponses";
import { useBoothMode } from "../../hooks/useBoothMode";
import { useShowTurnDetails } from "../../hooks/useShowTurnDetails";
import { useTheme, type Theme } from "../../hooks/useTheme";
import type { CardLayout } from "../../lib/cardLayout";
import { Group, PANEL, SectionHeader, Segmented, SettingRow } from "./primitives";

const NOT_SAVED = "This browser would not save the choice — it applies until you reload.";

const LAYOUTS: { id: CardLayout; label: string; hint: string }[] = [
  { id: "columns", label: "Columns", hint: "one card per guardrail — findings, notes, details" },
  { id: "compact", label: "Compact", hint: "one row per guardrail — ids and config behind Details" },
  { id: "table", label: "Table", hint: "one column per guardrail — verdict, detections, policy, id side by side" },
];

function ThemeRow() {
  const { theme, set } = useTheme();
  return (
    <SettingRow
      label="Theme"
      labelId="pref-theme"
      description="Light or dark. The sun/moon button in every page header switches the same setting."
      control={
        <Segmented<Theme>
          labelledBy="pref-theme"
          options={[
            { id: "light", label: "Light" },
            { id: "dark", label: "Dark" },
          ]}
          value={theme}
          onChange={set}
        />
      }
    />
  );
}

function CardLayoutRow() {
  const [layout, setLayout] = useGuardrailCardLayout();
  // null until a choice is made here; false when storage refused it (private window).
  const [saved, setSaved] = useState<boolean | null>(null);
  const current = LAYOUTS.find((o) => o.id === layout) ?? LAYOUTS[0];
  return (
    <SettingRow
      label="Guardrail card layout"
      labelId="pref-layout"
      description="How the chat shows a turn an external guardrail stopped, or a guardrail-only turn."
      note={saved === false ? NOT_SAVED : `${current.label}: ${current.hint}.`}
      control={
        <Segmented<CardLayout>
          labelledBy="pref-layout"
          options={LAYOUTS}
          value={layout}
          onChange={(v) => setSaved(setLayout(v))}
        />
      }
    />
  );
}

// One of booth's own send-time choices (lib/boothGateway.ts): a gateway or a model, from the same lists the chat page's
// dropdowns show (/api/models). A stored id that is no longer in the list is said, not silently kept.
function BoothChoiceRow({
  label,
  labelId,
  description,
  pref,
  setPref,
  options,
  chatDefault,
  what,
  loading,
  loadFailed,
  describe,
}: {
  label: string;
  labelId: string;
  description: string;
  pref: string;
  setPref: (v: string) => boolean;
  options: { id: string; label: string }[];
  chatDefault: string; // what the chat page holds after a reload
  what: string; // "gateway" | "model", for the notes
  loading: boolean;
  loadFailed: boolean;
  describe: (id: string) => string; // " (Guardrails on)" and the like; "" for nothing to add
}) {
  const [saved, setSaved] = useState<boolean | null>(null);
  const choice = resolveBoothChoice(pref, options.map((o) => o.id), chatDefault);
  const name = (id: string) => options.find((o) => o.id === id)?.label ?? id;
  const note =
    saved === false
      ? NOT_SAVED
      : loadFailed
        ? `Could not load the list — try again later. Booth keeps its current ${what}.`
        : choice.missing
          ? `"${pref}" is not in the list any more, so booth uses the chat page's ${what}. Pick another.`
          : loading
            ? "Loading…"
            : choice.source === "booth"
              ? `Booth uses ${name(choice.id)}${describe(choice.id)}. The chat page's own dropdown is unaffected.`
              : `Booth uses the chat page's ${what} — after a reload that is the default, ${chatDefault ? name(chatDefault) : "none"}${
                  chatDefault ? describe(chatDefault) : ""
                }. Pick one to pin the booth screen to it.`;
  return (
    <SettingRow
      label={label}
      labelId={labelId}
      description={description}
      note={note}
      control={
        <select
          aria-labelledby={labelId}
          value={choice.missing ? "" : pref}
          disabled={loading}
          onChange={(e) => setSaved(setPref(e.target.value))}
          className="max-w-72 rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] text-text outline-none focus:border-accent disabled:opacity-60"
        >
          <option value="">Same as the chat page</option>
          {options.map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </select>
      }
    />
  );
}

// Booth's gateway and models. Booth hides the chat page's gateway and model dropdowns, so this is where the booth
// screen's are chosen. One /api/models read feeds all three rows; the FortiAIGate row shows only while that route is on.
function BoothSendRows() {
  const [gatewayPref, setGatewayPref] = useBoothGateway();
  const [modelPref, setModelPref] = useBoothModel();
  const [fortiPref, setFortiPref] = useBoothFortiModel();
  const [data, setData] = useState<ModelsResponse | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  useEffect(() => {
    let live = true;
    getModels()
      .then((d) => live && setData(d))
      .catch(() => live && setLoadFailed(true));
    return () => {
      live = false;
    };
  }, []);
  const loading = !data && !loadFailed;
  const gateways: GatewayOption[] = data?.gateways ?? [];
  const forti = data?.fortiaigate?.enabled ? data.fortiaigate.models : [];
  const guard = (id: string) => {
    const g = gateways.find((x) => x.id === id);
    return g ? (g.guarded ? " (AI Gateway Guardrails on)" : " (Guardrails off)") : "";
  };
  return (
    <>
      <BoothChoiceRow
        label="Booth gateway"
        labelId="pref-booth-gateway"
        description="Which AI Gateway booth mode sends through when the AI Gateway route is selected."
        pref={gatewayPref}
        setPref={setGatewayPref}
        options={gateways.map((g) => ({ id: g.id, label: g.label }))}
        chatDefault={data?.defaultGateway ?? gateways[0]?.id ?? ""}
        what="gateway"
        loading={loading}
        loadFailed={loadFailed}
        describe={guard}
      />
      <BoothChoiceRow
        label="Booth model"
        labelId="pref-booth-model"
        description="Which Workers AI model booth mode asks, on the Workers AI and AI Gateway routes. A dynamic route set on the chat page still picks its own model."
        pref={modelPref}
        setPref={setModelPref}
        options={(data?.models ?? []).map((m) => ({ id: m.id, label: m.label }))}
        chatDefault={data?.default ?? ""}
        what="model"
        loading={loading}
        loadFailed={loadFailed}
        describe={() => ""}
      />
      {forti.length > 0 && (
        <BoothChoiceRow
          label="Booth FortiAIGate model"
          labelId="pref-booth-forti-model"
          description="Which FortiAIGate model booth mode asks on the FortiAIGate route (FortiAIGate's public model names)."
          pref={fortiPref}
          setPref={setFortiPref}
          options={forti.map((m) => ({ id: m, label: m }))}
          chatDefault={forti[0] ?? ""}
          what="model"
          loading={loading}
          loadFailed={loadFailed}
          describe={() => ""}
        />
      )}
    </>
  );
}

// One per-viewer on/off preference (hooks/useViewerFlag.ts).
function FlagRow({
  label,
  labelId,
  labels,
  flag,
  description,
  note,
}: {
  label: string;
  labelId: string;
  labels: [off: string, on: string];
  flag: () => [boolean, (on: boolean) => boolean];
  description: string;
  note: string;
}) {
  const [on, setOn] = flag();
  const [saved, setSaved] = useState<boolean | null>(null);
  return (
    <SettingRow
      label={label}
      labelId={labelId}
      description={description}
      note={saved === false ? NOT_SAVED : note}
      control={
        <Segmented<"off" | "on">
          labelledBy={labelId}
          options={[
            { id: "off", label: labels[0] },
            { id: "on", label: labels[1] },
          ]}
          value={on ? "on" : "off"}
          onChange={(v) => setSaved(setOn(v === "on"))}
        />
      }
    />
  );
}

export function PreferencesSection() {
  return (
    <section aria-labelledby="prefs" className="flex flex-col gap-4">
      <SectionHeader id="prefs" icon={<UserRound size={18} />} title="Your preferences" scope="This browser only" scopeTone="viewer">
        Saved in this browser. Nothing here reaches the server or changes what anyone else sees — a colleague on the same
        demo keeps their own choices.
      </SectionHeader>

      <Group id="pref-appearance" title="Appearance">
        <div className={PANEL}>
          <ThemeRow />
        </div>
      </Group>

      <Group id="pref-chat" title="Chat display" hint="Applies to the AI Guardrails Demo chat, including turns already on screen.">
        <div className={PANEL}>
          <FlagRow
            label="Booth mode"
            labelId="pref-booth"
            labels={["Off", "On"]}
            flag={useBoothMode}
            description="The chat as a booth visitor should see it: one big verdict per turn — which layer stopped the prompt, or that it reached the model — with larger text."
            note="Hides the setup panels, ray ids, tokens, cost, latency, the flow trace and raw responses; keeps the Attack Library, the route toggle and the vendor chips. Every banner comes from the same verdicts as the detailed view. Also switchable from the chat page header."
          />
          <BoothSendRows />
          <CardLayoutRow />
          <FlagRow
            label="Turn details"
            labelId="pref-turn-details"
            labels={["Hidden", "Shown"]}
            flag={useShowTurnDetails}
            description="The control strip and the edge-verdict line under each chat turn."
            note="Shown by default — the strip says which control stopped or passed each prompt, and the verdict line looks up what the edge WAF did. Hiding them also stops that lookup for new turns. The prompt log's verdict column is unaffected."
          />
          {/* The raw-response debug view: off by default; the warning is part of the control, not a footnote. */}
          <FlagRow
            label="Raw vendor responses"
            labelId="pref-raw"
            labels={["Off", "On"]}
            flag={useShowRawResponses}
            description='A "Raw responses" panel under each chat turn the guardrails scanned.'
            note="Each vendor's response body as it came back — it can include your prompt and anything the vendor detected. Only your own chat asks for it; it is not stored, logged or exported. Not available on streamed replies (no JSON body to carry it)."
          />
        </div>
      </Group>
    </section>
  );
}
