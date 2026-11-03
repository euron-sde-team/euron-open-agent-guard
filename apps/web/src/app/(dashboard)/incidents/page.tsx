import type { Metadata } from "next";

import { IncidentsScreen } from "@/features/incidents/components/incidents-screen";

export const metadata: Metadata = { title: "Incidents" };

export default function Page() {
  return <IncidentsScreen />;
}
