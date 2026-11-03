import type { Metadata } from "next";

import { NetworkScreen } from "@/features/network/components/network-screen";

export const metadata: Metadata = { title: "Network guard" };

export default function Page() {
  return <NetworkScreen />;
}
