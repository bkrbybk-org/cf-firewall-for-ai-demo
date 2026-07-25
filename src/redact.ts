// Best-effort PII redaction for the prompt log. Firewall for AI reports PII
// *categories*, not character offsets, so we cannot use its output to mask
// precisely — this is an independent regex pass targeting the identifier
// formats the demo's Attack Library actually generates (Thai national ID,
// credit card, IBAN, crypto wallet, email, IP, phone). It is deliberately
// conservative: better to over-mask than to persist a live identifier.
//
// NOTE: this only protects THIS app's D1 store. AI Gateway still logs the raw
// prompt+response payload (collect-log-payload defaults on) — the UI says so.

type Rule = { name: string; re: RegExp; mask: (m: string) => string };

// Keep the last 4 of a card so the log stays recognisable ("****1111").
function maskCard(m: string): string {
  const digits = m.replace(/\D/g, "");
  return `[card ****${digits.slice(-4)}]`;
}
const tag = (label: string) => () => `[${label}]`;

// Order matters: most specific first, so a Thai ID or card isn't half-eaten by
// the looser phone rule. Each match is replaced with a non-matching token.
const RULES: Rule[] = [
  // 13-digit Thai national ID, usually grouped 1-4-5-2-1 (e.g. 6-0048-53656-38-2).
  { name: "thai_id", re: /\b\d[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d\b/g, mask: tag("thai-id") },
  // IBAN: 2 letters, 2 digits, then 10–30 alphanumerics. Before `card` so the
  // account digits aren't matched as a bare card number first.
  { name: "iban", re: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9][ ]?){10,30}\b/g, mask: tag("iban") },
  // Payment card: 13–19 digits in groups of 4 (spaces/dashes optional).
  { name: "card", re: /\b(?:\d[ -]?){12,18}\d\b/g, mask: maskCard },
  // Crypto wallets: BTC bech32 / legacy, or 0x… Ethereum.
  { name: "crypto", re: /\b(?:bc1[a-z0-9]{20,60}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, mask: tag("wallet") },
  // Email.
  { name: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, mask: tag("email") },
  // IPv4.
  { name: "ip", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, mask: tag("ip") },
  // Phone: optional +, 8–15 digits with spaces/dashes. Runs last.
  { name: "phone", re: /\+?\d[\d -]{7,13}\d/g, mask: tag("phone") },
];

export function redact(input: string): { text: string; count: number } {
  let text = input;
  let count = 0;
  for (const rule of RULES) {
    text = text.replace(rule.re, (m) => {
      count++;
      return rule.mask(m);
    });
  }
  return { text, count };
}
