import type { Metadata } from "next";

import { AccessScreen } from "@/features/access/components/access-screen";

export const metadata: Metadata = { title: "Access control" };

export default function Page() {
  return <AccessScreen />;
}
