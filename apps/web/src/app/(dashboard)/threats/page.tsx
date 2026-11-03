import type { Metadata } from "next";

import { ThreatsScreen } from "@/features/threats/components/threats-screen";

export const metadata: Metadata = { title: "Threat detection" };

export default function Page() {
  return <ThreatsScreen />;
}
