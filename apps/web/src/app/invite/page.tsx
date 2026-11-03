import type { Metadata } from "next";
import { Suspense } from "react";

import { LoginScreen } from "@/features/auth/components/login-screen";

export const metadata: Metadata = { title: "Accept invitation" };

export default function InvitePage() {
  return (
    <Suspense>
      <LoginScreen mode="invite" />
    </Suspense>
  );
}
