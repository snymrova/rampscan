/** @type {import('next').NextConfig} */
const nextConfig = {
  // NEXT_PUBLIC_* values are inlined at compile time, and the on-disk webpack
  // cache does not reliably invalidate when they change — a dev serve (PB on
  // 8090) and the Playwright smoke (PB on 8098) sharing .next would serve each
  // other stale chunks pointing at the wrong PocketBase. The smoke sets
  // NEXT_DIST_DIR to keep its compile cache fully separate.
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  // workspace packages ship TS source; Next transpiles them for the approve
  // route (the only server-side consumer — everything else talks to
  // PocketBase from the browser)
  transpilePackages: [
    "@rampscan/cli",
    "@rampscan/core",
    "@rampscan/schema",
    "@rampscan/dataset",
    "@rampscan/ledger",
    "@rampscan/signer",
    "@rampscan/projector",
    "@rampscan/collectors",
  ],
  // those packages import NodeNext-style ("./fold.js" resolving to fold.ts);
  // webpack needs to be told to try the .ts source for a .js specifier
  webpack: (config) => {
    config.resolve.extensionAlias = {
      ".js": [".ts", ".tsx", ".js"],
      ".mjs": [".mts", ".mjs"],
    };
    return config;
  },
};

export default nextConfig;
