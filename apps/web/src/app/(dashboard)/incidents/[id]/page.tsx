import type { Metadata } from "next";

import { IncidentDetailScreen } from "@/features/incidents/components/incident-detail";

export const metadata: Metadata = { title: "Incident" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <IncidentDetailScreen id={id} />;
}
