import type { Metadata } from "next";

import { ThreatDetailScreen } from "@/features/threats/components/threat-detail";

export const metadata: Metadata = { title: "Threat" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ThreatDetailScreen id={id} />;
}
