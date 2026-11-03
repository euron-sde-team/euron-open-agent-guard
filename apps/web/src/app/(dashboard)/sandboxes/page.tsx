import type { Metadata } from "next";

import { SandboxesScreen } from "@/features/sandbox/components/sandboxes-screen";

export const metadata: Metadata = { title: "Sandboxes" };

export default function Page() {
  return <SandboxesScreen />;
}
