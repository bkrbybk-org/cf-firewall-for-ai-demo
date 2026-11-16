// What an error may say to the client (Open bug #25).
//
// Handlers used to return `err.message` verbatim from every catch. Most of those
// errors are not ours: D1 driver errors quote SQL and schema, a failed fetch or a
// programming bug can carry an internal path (on local dev one returned a stack
// trace with an absolute file path). The rule now:
//   - a message this code wrote ON PURPOSE for the operator — "Ruleset list failed
//     (HTTP 403)", "GUARDRAIL_SECRET_KEY must decode to 32 bytes" — is a
//     PublicError and is shown as-is: it is the actionable part of the page;
//   - anything else is logged whole (console.error → `wrangler tail` / the dev
//     terminal) and the client gets what failed and the error's class, never its text;
//   - Workers AI errors are the one exception, via aiErrorText: they are the
//     platform's own words about the model call (quota, capacity, unknown model),
//     which is what an operator needs, so they are kept — trimmed to one clean line.

export class PublicError extends Error {
  override name = "PublicError";
}

export function clientError(err: unknown, what: string, log: (...a: unknown[]) => void = console.error): string {
  if (err instanceof PublicError) return err.message;
  log(`[${what}]`, err);
  const kind = err instanceof Error && err.name && err.name !== "Error" ? ` (${err.name})` : "";
  return `${what} failed${kind} — the detail is in the Worker log`;
}

const AI_ERROR_MAX = 300;

export function aiErrorText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const firstLine = raw.split(/\r?\n/)[0] ?? "";
  const clean = firstLine
    // file:///… URLs and absolute POSIX / Windows paths, with any :line:col suffix
    .replace(/file:\/\/\S+/g, "[path]")
    .replace(/(?:[A-Za-z]:\\|\/)(?:[\w.@-]+[\\/])+[\w.@-]+(?::\d+){0,2}/g, "[path]")
    .trim();
  return clean.length > AI_ERROR_MAX ? clean.slice(0, AI_ERROR_MAX - 1) + "…" : clean || "unknown error";
}

// A vendor's own error text, if it may be shown (2026-11-16 review, S3). Four of the six vendor clients used to copy
// `message` / `detail` out verbatim and uncapped, while Cato and Datadog were already restricted — and the house rule is
// that a vendor's message field is never passed on, because some vendors echo the request in it (Lakera's 400 quotes
// the bad value; Cato's detection message quotes the SSN). The text travels in the JSON body, the
// `x-external-guardrails` header and the UI, so one rule now applies to every vendor:
//   - one line, control characters gone, at most VENDOR_ERROR_MAX characters;
//   - refused outright (undefined → the caller's own "returned HTTP n") when it holds three digits in a row or an
//     `@`: the shapes of card, ID, phone and account numbers and of email addresses — what an echo could leak. The
//     same digit rule the vendors' tags already follow. Losing an actionable error to it costs a status line; letting
//     an echoed SSN through costs much more.
const VENDOR_ERROR_MAX = 200;
const VENDOR_ERROR_REFUSE = /\d{3}|@/;

export function vendorErrorText(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const one = v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  if (!one || VENDOR_ERROR_REFUSE.test(one)) return undefined;
  return one.length > VENDOR_ERROR_MAX ? one.slice(0, VENDOR_ERROR_MAX - 1) + "…" : one;
}
