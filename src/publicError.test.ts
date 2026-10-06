import { describe, expect, it } from "vitest";
import { PublicError, aiErrorText, clientError } from "./publicError";

describe("clientError", () => {
  it("shows a PublicError's message as-is, without logging it as a failure", () => {
    const logged: unknown[] = [];
    expect(clientError(new PublicError("Ruleset list failed (HTTP 403)"), "Zone rules", (...a) => logged.push(a))).toBe(
      "Ruleset list failed (HTTP 403)",
    );
    expect(logged).toEqual([]);
  });

  it("never returns another error's text — D1 SQL, paths — and logs it whole instead", () => {
    const logged: unknown[][] = [];
    const err = new Error("D1_ERROR: no such column: secret_col at /Users/someone/app/src/handlers.ts:42:7");
    const out = clientError(err, "Prompt log", (...a) => logged.push(a));
    expect(out).toBe("Prompt log failed — the detail is in the Worker log");
    expect(out).not.toMatch(/D1_ERROR|secret_col|\/Users/);
    expect(logged).toEqual([["[Prompt log]", err]]);
  });

  it("names the error class when it is not a plain Error, and copes with non-Errors", () => {
    expect(clientError(new TypeError("fetch failed"), "Analytics", () => {})).toBe(
      "Analytics failed (TypeError) — the detail is in the Worker log",
    );
    expect(clientError("boom", "Analytics", () => {})).toBe("Analytics failed — the detail is in the Worker log");
  });
});

describe("aiErrorText", () => {
  it("keeps the platform's own message", () => {
    expect(aiErrorText(new Error("3036: Account limited: you have used up your daily free allocation of 10,000 neurons"))).toBe(
      "3036: Account limited: you have used up your daily free allocation of 10,000 neurons",
    );
  });

  it("drops stack lines and absolute paths", () => {
    const err = new Error(
      "internal error at /Users/me/dev/app/node_modules/miniflare/dist/index.js:123:45\n    at Object.run (file:///Users/me/x.js:1:1)",
    );
    const out = aiErrorText(err);
    expect(out).toBe("internal error at [path]");
    expect(out).not.toMatch(/Users|node_modules|\n/);
    expect(aiErrorText(new Error("failed in C:\\Users\\me\\app\\worker.js:9"))).toBe("failed in [path]");
  });

  it("caps the length and never returns an empty string", () => {
    expect(aiErrorText(new Error("x".repeat(1000))).length).toBe(300);
    expect(aiErrorText(new Error(""))).toBe("unknown error");
  });
});
