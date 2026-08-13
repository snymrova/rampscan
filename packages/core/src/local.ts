import type {
  LedgerStore,
  Projector,
  RepoSource,
  Runner,
  Scheduler,
  Signer,
} from "./ports.js";

// Local adapters, stubbed (plan B3: "stubbed, not implemented"). Each lands
// for real in its own milestone: ledger/signer in M2, runner/repo-source in
// M1, projector in M2, scheduler in M5. The stubs exist so wiring code can
// depend on constructors now without inventing interfaces later.

function notImplemented(port: string, milestone: string): never {
  throw new Error(`${port} local adapter lands in ${milestone} — not implemented yet`);
}

export function createLocalLedger(_dir: string): LedgerStore {
  return {
    append: async () => notImplemented("LedgerStore", "M2"),
    get: async () => notImplemented("LedgerStore", "M2"),
    list: async () => notImplemented("LedgerStore", "M2"),
  };
}

export function createLocalSigner(_keyPath: string): Signer {
  return {
    sign: async () => notImplemented("Signer", "M2"),
    verify: async () => notImplemented("Signer", "M2"),
  };
}

export function createLocalRunner(): Runner {
  return {
    run: async () => notImplemented("Runner", "M1"),
  };
}

export function createLocalScheduler(): Scheduler {
  return {
    ensureCadence: async () => notImplemented("Scheduler", "M5"),
  };
}

export function createLocalRepoSource(): RepoSource {
  return {
    fetch: async () => notImplemented("RepoSource", "M1"),
  };
}

export function createProjector(): Projector {
  return {
    fold: async () => notImplemented("Projector", "M2"),
  };
}
