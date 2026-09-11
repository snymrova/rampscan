import { describe, expect, it } from "vitest";
import {
  BoundaryRule,
  ContractConfig,
  ContractRule,
  DeclaredDocument,
  RouteAuthRule,
} from "../src/index.js";

// The #31 pins. contract.ts and documents.ts rest two hard edges on zod's
// strict object semantics: a misspelled field REFUSES rather than silently
// waiving a rule, and an unknown `kind` is a config error, never a skip.
// Before this file, no test asserted either refusal — a zod major degrading
// strict parsing to plain stripping would have turned a typo into a vacuous
// pass without failing anything. These assertions are what would catch that
// automatically instead of needing a hand-run probe at upgrade time.

const routeAuth = {
  kind: "route-auth",
  id: "admin-auth",
  routes: "/admin/*",
  description: "every admin route must reach an auth check",
};

const boundary = {
  kind: "boundary",
  id: "billing-boundary",
  module: "src/billing",
  allowedImporters: ["src/api"],
  description: "only the API layer may import billing",
};

describe("contract strictness (#31)", () => {
  it("baseline: both rule kinds parse as written", () => {
    expect(RouteAuthRule.parse(routeAuth)).toEqual(routeAuth);
    expect(BoundaryRule.parse(boundary)).toEqual(boundary);
  });

  it("a misspelled rule field refuses instead of stripping", () => {
    // the exact typo the contract.ts comment warns about: `allowedImporter`
    // would change what the rule means while looking like it declared something
    const { allowedImporters, ...rest } = boundary;
    expect(BoundaryRule.safeParse({ ...rest, allowedImporter: allowedImporters }).success).toBe(
      false,
    );
    expect(RouteAuthRule.safeParse({ ...routeAuth, route: "/admin/*" }).success).toBe(false);
  });

  it("an unknown rule kind is a config error, never a skip", () => {
    expect(ContractRule.safeParse({ ...boundary, kind: "boundry" }).success).toBe(false);
  });

  it("an unknown key on the contract block itself refuses", () => {
    expect(
      ContractConfig.safeParse({ rules: [routeAuth], rule: [boundary] }).success,
    ).toBe(false);
  });
});

describe("documents strictness (#31, same edge)", () => {
  const doc = {
    id: "acp",
    kind: "access-control-policy",
    path: "docs/access-control.md",
    description: "who may access what, and how access is granted",
  };

  it("baseline: a declared document parses as written", () => {
    expect(DeclaredDocument.parse(doc)).toEqual(doc);
  });

  it("a misspelled declaration field refuses instead of stripping", () => {
    const { path, ...rest } = doc;
    expect(DeclaredDocument.safeParse({ ...rest, paths: path }).success).toBe(false);
  });
});
