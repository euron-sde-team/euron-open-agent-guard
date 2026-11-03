import type { Metadata } from "next";

import { EditPolicyScreen } from "@/features/policies/components/policy-editor";

export const metadata: Metadata = { title: "Policy" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <EditPolicyScreen id={id} />;
}
