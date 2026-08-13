import { describe, expect, it } from "vitest";
import {
  buildDockerRunArgs,
  createDockerTool,
  loadToolManifest,
  resolveTool,
} from "../src/index.js";

// The Docker-first resolution policy: binary on PATH → pinned image via
// Docker → nothing (wrapper skips). Nothing ever installs on the host.

const MANIFEST = {
  gitleaks: { version: "8.24.3", image: "ghcr.io/gitleaks/gitleaks:v8.24.3" },
};

describe("resolveTool", () => {
  const probe = { args: ["--version"], parse: (out: string) => out.trim() };

  it("prefers an installed binary and reports its real version", async () => {
    const tool = await resolveTool("gitleaks", probe, {
      binaryVersion: "9.9.9",
      manifest: MANIFEST,
      docker: true,
    });
    expect(tool!.kind).toBe("binary");
    expect(tool!.version).toBe("9.9.9");
    expect(tool!.mount("/some/host/path")).toBe("/some/host/path"); // identity
  });

  it("falls back to the pinned Docker image when the binary is absent", async () => {
    const tool = await resolveTool("gitleaks", probe, {
      binaryVersion: null,
      manifest: MANIFEST,
      docker: true,
    });
    expect(tool!.kind).toBe("docker");
    expect(tool!.version).toBe("8.24.3"); // bare pin — same shape a binary reports
    expect(tool!.runtime).toBe("ghcr.io/gitleaks/gitleaks:v8.24.3");
  });

  it("resolves to nothing when there is no binary and no Docker", async () => {
    const tool = await resolveTool("gitleaks", probe, {
      binaryVersion: null,
      manifest: MANIFEST,
      docker: false,
    });
    expect(tool).toBeUndefined();
  });

  it("a tool missing from the manifest cannot resolve via Docker", async () => {
    const tool = await resolveTool("not-a-tool", probe, {
      binaryVersion: null,
      manifest: MANIFEST,
      docker: true,
    });
    expect(tool).toBeUndefined();
  });
});

describe("docker path mapping", () => {
  it("mount() maps each host dir once, dedupes, and upgrades ro→rw", () => {
    const tool = createDockerTool("gitleaks", MANIFEST.gitleaks);
    const a = tool.mount("/host/repo", "ro");
    const b = tool.mount("/host/out", "rw");
    expect(a).not.toBe(b);
    expect(tool.mount("/host/repo", "ro")).toBe(a); // dedupe
    expect(tool.mount("/host/repo", "rw")).toBe(a); // upgrade keeps the path
  });

  it("buildDockerRunArgs mounts, env, user, image, and tool args in order", () => {
    const args = buildDockerRunArgs(
      "anchore/syft:v1.51.0",
      [
        { host: "/host/repo", container: "/rampscan/m0", mode: "ro" },
        { host: "/host/out", container: "/rampscan/m1", mode: "rw" },
      ],
      ["scan", "dir:/rampscan/m0"],
      { GRYPE_DB_CACHE_DIR: "/rampscan/m2" },
      "1000:1000",
    );
    expect(args).toEqual([
      "run",
      "--rm",
      "-u",
      "1000:1000",
      "-e",
      "HOME=/tmp",
      "-e",
      "GRYPE_DB_CACHE_DIR=/rampscan/m2",
      "-v",
      "/host/repo:/rampscan/m0:ro",
      "-v",
      "/host/out:/rampscan/m1",
      "anchore/syft:v1.51.0",
      "scan",
      "dir:/rampscan/m0",
    ]);
  });
});

describe("tools.json", () => {
  it("pins a version and an image for every wrapped tool", async () => {
    const manifest = await loadToolManifest();
    for (const name of ["syft", "grype", "gitleaks", "osv-scanner"]) {
      expect(manifest[name]?.version, `${name} version pin`).toMatch(/^\d+\.\d+\.\d+$/);
      expect(manifest[name]?.image, `${name} image pin`).toContain(manifest[name]!.version);
    }
  });
});
