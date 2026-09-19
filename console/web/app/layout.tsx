import type { Metadata } from "next";
import { Suspense, type ReactNode } from "react";
import { Nav } from "../components/Nav";
import { ScopeProvider } from "../lib/scope";
import "./globals.css";

export const metadata: Metadata = {
  title: "rampscan console",
  description:
    "Pipeline-source evidence registers: evidenced / violated / unevidenced, on the MVX clock.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          {/* the repo scope reads ?repo=, and useSearchParams needs a
              Suspense boundary for the static prerender */}
          <Suspense fallback={null}>
            <ScopeProvider>
              <Nav />
              {children}
            </ScopeProvider>
          </Suspense>
        </div>
      </body>
    </html>
  );
}
