import "@fontsource-variable/inter";
import "./globals.css";

import type { Metadata, Viewport } from "next";

import { Providers } from "@/lib/providers";

export const metadata: Metadata = {
  title: { default: "AgentGuard", template: "%s | AgentGuard" },
  description:
    "Self-hosted security, governance and control plane for AI agents: identity, policy, approvals, secrets, threat detection and a tamper-evident audit log.",
  icons: { icon: "/icon.svg" },
};

export const viewport: Viewport = {
  // Meta tags cannot read CSS variables: these mirror --background in globals.css.
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f3f5f7" },
    { media: "(prefers-color-scheme: dark)", color: "#090e12" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
