import type { Metadata } from "next";

import { AgentDetailScreen } from "@/features/agents/components/agent-detail";

export const metadata: Metadata = { title: "Agent" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <AgentDetailScreen id={id} />;
}
