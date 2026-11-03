import type { Metadata } from "next";

import { ToolsScreen } from "@/features/tools/components/tools-screen";

export const metadata: Metadata = { title: "Tool security" };

export default function Page() {
  return <ToolsScreen />;
}
