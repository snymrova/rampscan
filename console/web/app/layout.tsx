import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Nav } from "../components/Nav";
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
          <Nav />
          {children}
        </div>
      </body>
    </html>
  );
}
