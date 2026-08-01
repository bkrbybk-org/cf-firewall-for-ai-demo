// The uploaded custom attack corpus, held for the lifetime of the page load.
//
// Module scope for the same reason as the chat session store: it survives
// switching to Analytics and back (losing a corpus mid-demo because you looked
// at the prompt log would be maddening), and a refresh clears it. Deliberately
// not localStorage — someone else's attack prompts should not outlive the
// browser session on a shared demo laptop.
import { createStore } from "./sessionStore";
import type { RedTeamAttack } from "./redteam";

export interface CustomCorpus {
  name: string; // the uploaded file's name, shown so the source is never ambiguous
  attacks: RedTeamAttack[];
  warnings: string[];
  loadedAt: number;
}

export const customCorpusStore = createStore<CustomCorpus | null>(null);
