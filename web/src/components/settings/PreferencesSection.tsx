// Settings → Your preferences: everything saved in THIS browser (localStorage,
// per viewer). None of it reaches the server or changes what anyone else sees —
// which is the whole reason it is a separate section from System settings.
// Replaces the old "Chat card layout" box that sat between the traffic-flow
// diagram and the provider cards, where it read as one more shared setting.
import { useState } from "react";
import { UserRound } from "lucide-react";
import { useGuardrailCardLayout } from "../../hooks/useGuardrailCardLayout";
import { useShowRawResponses } from "../../hooks/useShowRawResponses";
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
