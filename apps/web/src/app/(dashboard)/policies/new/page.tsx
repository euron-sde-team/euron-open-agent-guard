import type { Metadata } from "next";

import { NewPolicyScreen } from "@/features/policies/components/policy-editor";

export const metadata: Metadata = { title: "New policy" };

export default function Page() {
  return <NewPolicyScreen />;
}
