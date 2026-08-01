// Tests for dynamic-route name normalisation.
//
// This exists because of a real bug: the dashboard renders a route as
// "dynamic / demo-routes", so the natural thing to paste is
// "dynamic/demo-routes" — which the bare-id charset rejected because of the
// slash. The request then silently fell through to the Workers AI binding and
// answered with the Model picker's model, so the demo looked like it worked
// while running a completely different path.
//
// The contract now: accept either form, and return null (never a silently
// wrong value) for anything unusable so the caller can reject the request.
import { describe, expect, it } from "vitest";
import { normalizeDynamicRoute } from "./config";

describe("normalizeDynamicRoute", () => {
  it("accepts a bare route name", () => {
    expect(normalizeDynamicRoute("demo-routes")).toBe("demo-routes");
  });

  it("accepts the dashboard's prefixed form", () => {
    expect(normalizeDynamicRoute("dynamic/demo-routes")).toBe("demo-routes");
  });

  it("tolerates surrounding and inner whitespace", () => {
    expect(normalizeDynamicRoute("  demo-routes  ")).toBe("demo-routes");
    expect(normalizeDynamicRoute("dynamic/ demo-routes")).toBe("demo-routes");
  });

  it("is case-insensitive about the prefix but preserves the route name's case", () => {
    expect(normalizeDynamicRoute("Dynamic/Demo-Routes")).toBe("Demo-Routes");
  });

  it("strips only one prefix, so a doubled prefix is still a rejection", () => {
    expect(normalizeDynamicRoute("dynamic/dynamic/demo-routes")).toBeNull();
  });

  it("rejects path traversal rather than passing it through", () => {
    for (const bad of ["../../evil", "dynamic/../../evil", "a/b", "route name", "route?x=1"]) {
      expect(normalizeDynamicRoute(bad), `for ${JSON.stringify(bad)}`).toBeNull();
    }
  });

  it("rejects empty input and a bare prefix", () => {
    for (const bad of ["", "   ", "dynamic/", "dynamic/   "]) {
      expect(normalizeDynamicRoute(bad), `for ${JSON.stringify(bad)}`).toBeNull();
    }
  });

  it("rejects a name longer than the 64-char id limit", () => {
    expect(normalizeDynamicRoute("a".repeat(64))).toBe("a".repeat(64));
    expect(normalizeDynamicRoute("a".repeat(65))).toBeNull();
  });
});
