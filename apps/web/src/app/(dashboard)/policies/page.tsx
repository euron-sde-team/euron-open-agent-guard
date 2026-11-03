import type { Metadata } from "next";

import { PoliciesScreen } from "@/features/policies/components/policies-screen";

export const metadata: Metadata = { title: "Policy builder" };

export default function Page() {
  return <PoliciesScreen />;
}
