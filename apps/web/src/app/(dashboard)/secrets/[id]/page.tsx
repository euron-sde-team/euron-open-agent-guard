import type { Metadata } from "next";

import { SecretDetailScreen } from "@/features/secrets/components/secret-detail";

export const metadata: Metadata = { title: "Secret" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SecretDetailScreen id={id} />;
}
