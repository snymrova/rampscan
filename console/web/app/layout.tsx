import type { Metadata } from "next";
import { Suspense, type ReactNode } from "react";
import "@fontsource-variable/big-shoulders";
import "@fontsource-variable/geist";
import "@fontsource-variable/martian-mono/standard.css";
import { DepthRail } from "../components/DepthRail";
import { Nav } from "../components/Nav";
import { ScopeProvider } from "../lib/scope";
import "./globals.css";

export const metadata: Metadata = {
  title: "rampscan console",
  description:
    "Pipeline-source evidence registers: evidenced / violated / unevidenced, on the MVX clock.",
};

// The direction contract (impeccable new-work §5). DESIGN.md is the rulebook;
// this is what the build was held to.
// THESIS: the console is a technical descent. Six levels of zoom are depths, and a lit thermocline says how far down you are. It refuses the stock dashboard of equal-weight cards and tables.
// OWN-WORLD: abyss ink ground with faint marine snow, cold-blue hairlines, one thermocline cyan that only ever means "you are here", GitHub verdict hues that always carry their word. Tall condensed caps, dive-computer mono digits, quiet grotesk prose.
// STORY: an operator sees how they are doing in one numeral and one sentence, sees which theme is worst, and descends until the signed bytes are in hand.
// FIRST VIEWPORT: the depth rail on the left; a huge floor-met numeral with its computed sentence; ten theme strata; the next three actions and the MVX clock on the right.
// FORM: Depth Axis, comp A (depth rail), seed 4c7001d9.
// FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* the repo scope reads ?repo=, and useSearchParams needs a
            Suspense boundary for the static prerender */}
        <Suspense fallback={null}>
          <ScopeProvider>
            <div className="shell">
              <DepthRail />
              <div className="stage">
                <Nav />
                <main className="page">{children}</main>
              </div>
            </div>
          </ScopeProvider>
        </Suspense>
      </body>
    </html>
  );
}
