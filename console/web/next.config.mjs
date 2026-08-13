/** @type {import('next').NextConfig} */
const nextConfig = {
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
