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
