import type { Metadata } from "next";

import { RiskScreen } from "@/features/threats/components/risk-screen";

export const metadata: Metadata = { title: "Risk center" };

export default function Page() {
  return <RiskScreen />;
}
