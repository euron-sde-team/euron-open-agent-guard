import type { Metadata } from "next";

import { ApprovalDetailScreen } from "@/features/approvals/components/approval-detail";

export const metadata: Metadata = { title: "Approval" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ApprovalDetailScreen id={id} />;
}
