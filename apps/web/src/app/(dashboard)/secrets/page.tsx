import type { Metadata } from "next";

import { SecretsScreen } from "@/features/secrets/components/secrets-screen";

export const metadata: Metadata = { title: "Secrets" };

export default function Page() {
  return <SecretsScreen />;
}
