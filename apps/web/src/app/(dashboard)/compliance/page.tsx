import type { Metadata } from "next";

import { ComplianceScreen } from "@/features/compliance/components/compliance-screen";

export const metadata: Metadata = { title: "Compliance" };

export default function Page() {
  return <ComplianceScreen />;
}
