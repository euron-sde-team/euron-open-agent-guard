import type { Metadata } from "next";
import { Suspense } from "react";

import { LoginScreen } from "@/features/auth/components/login-screen";

export const metadata: Metadata = { title: "Create an account" };

export default function SignupPage() {
  return (
    <Suspense>
      <LoginScreen mode="signup" />
    </Suspense>
  );
}
