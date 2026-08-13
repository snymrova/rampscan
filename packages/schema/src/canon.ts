// Canonical JSON (JCS-style: recursively sorted object keys, no whitespace).
// The ledger addresses bundles by sha256 of this serialization and the signer
// signs exactly these bytes — both worlds must agree on one byte sequence per
// statement, so the serializer lives here in schema, dependency-free.

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "number" || typeof value === "boolean") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("canonical JSON cannot represent NaN/Infinity");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`);
    return `{${entries.join(",")}}`;
  }
  throw new Error(`canonical JSON cannot represent a ${typeof value}`);
}
