"use client";

import { ArrowRightIcon, BuildingIcon, EyeIcon, EyeOffIcon, FingerprintIcon, HandIcon, ScrollTextIcon, ShieldCheckIcon } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";

import { BrandLogo, BrandMark } from "@/components/brand";
import { ErrorState } from "@/components/error-state";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FieldError, FieldHint, Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { errorMessage } from "@/lib/api/errors";
import { HOME, safeNext } from "@/lib/auth-redirect";
import { passwordMessage } from "@/lib/password";
import { roleLabel } from "@/lib/roles";

import { useAcceptInvitation, useInvitationPreview, useLogin, useSignup, useSignupStatus } from "../api";

const PITCH = [
  {
    icon: FingerprintIcon,
    title: "An identity per agent",
    body: "Short-lived signed tokens, rotation with overlap, instant revocation and quarantine.",
  },
  {
    icon: ShieldCheckIcon,
    title: "Decided by policy, not the model",
    body: "Deterministic YAML policies, explicit deny wins, simulated against history before you ship.",
  },
  {
    icon: HandIcon,
    title: "Approvals you cannot swap",
    body: "A held action is bound to a hash of its exact parameters. Change one byte, ask again.",
  },
  {
    icon: ScrollTextIcon,
    title: "A log you can verify",
    body: "Hash-chained, signed checkpoints, and a database that refuses edits and deletes.",
  },
];

type Mode = "login" | "signup" | "invite";

function PasswordInput({
  id,
  value,
  onChange,
  autoComplete,
  invalid,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete: string;
  invalid?: boolean;
}) {
  const [show, setShow] = React.useState(false);
  return (
    <div className="relative">
      <Input
        id={id}
        type={show ? "text" : "password"}
        autoComplete={autoComplete}
        className="h-10 pr-10"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid || undefined}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? "Hide password" : "Show password"}
        className="absolute top-1/2 right-2 flex size-7 -translate-y-1/2 items-center justify-center rounded-md text-subtle hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
      >
        {show ? <EyeOffIcon className="size-4" /> : <EyeIcon className="size-4" />}
      </button>
    </div>
  );
}

export function LoginScreen({ mode = "login" }: { mode?: Mode }) {
  const router = useRouter();
  const params = useSearchParams();
  const login = useLogin();
  const signup = useSignup();
  const accept = useAcceptInvitation();
  const status = useSignupStatus();
  const token = mode === "invite" ? params.get("token") : null;
  const invitation = useInvitationPreview(token);
  const [org, setOrg] = React.useState("");
  const [name, setName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [ssoOpen, setSsoOpen] = React.useState(false);
  const [slug, setSlug] = React.useState("");
  const expired = params.get("reason") === "expired";
  const signupOpen = status.data?.signup_enabled !== false;
  const pending = login.isPending || signup.isPending || accept.isPending;
  const next = params.get("next");

  function welcome(firstName: string, dest: string, isNew: boolean) {
    toast.success(isNew ? `Welcome, ${firstName}. Let us register your first agent.` : `Welcome back, ${firstName}.`);
    router.replace(dest);
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const onError = (err: unknown) => setError(errorMessage(err));
    if (mode === "login") {
      if (!email.trim() || !password) return setError("Enter your email and password.");
      setError(null);
      login.mutate(
        { email: email.trim(), password },
        { onSuccess: (s) => welcome(s.user.name.split(" ")[0] ?? "", safeNext(next), false), onError },
      );
      return;
    }
    if (!name.trim() || (mode === "signup" && (!org.trim() || !email.trim()))) {
      return setError(mode === "signup" ? "Enter your organisation, your name, your email and a password." : "Enter your name and a password.");
    }
    const weak = passwordMessage(password);
    if (weak) return setError(weak);
    setError(null);
    if (mode === "signup") {
      signup.mutate(
        { org_name: org.trim(), name: name.trim(), email: email.trim(), password },
        { onSuccess: (s) => welcome(s.user.name.split(" ")[0] ?? "", HOME, true), onError },
      );
    } else if (token) {
      accept.mutate({ token, name: name.trim(), password }, { onSuccess: (s) => welcome(s.user.name.split(" ")[0] ?? "", HOME, true), onError });
    }
  }

  const title = mode === "signup" ? "Create your organisation" : mode === "invite" ? "Join your team" : "Sign in to AgentGuard";
  const subtitle =
    mode === "signup"
      ? "Creates your organisation and makes you its admin. Then register an agent and watch its first decision."
      : mode === "invite"
        ? invitation.data
          ? `${invitation.data.org_name} invited ${invitation.data.email} as ${roleLabel(invitation.data.role).toLowerCase()}. Choose your name and password.`
          : "Accept your invitation to help govern your organisation's agents."
        : "See what your agents did, what they were stopped from doing, and what waits for you.";

  const inviteBlocked = mode === "invite" && (!token || invitation.isError);

  return (
    <div className="grid min-h-dvh bg-background lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)]">
      <div className="relative flex flex-col px-5 py-6 sm:px-10">
        <div className="flex items-center justify-between">
          <BrandLogo />
          <ThemeToggle />
        </div>
        <div className="flex flex-1 items-center justify-center py-10">
          <div className="w-full max-w-[380px]">
            <h1 className="text-[26px] leading-tight font-semibold tracking-[-0.025em]">{title}</h1>
            {mode === "invite" && invitation.isLoading ? (
              <Skeleton className="mt-2 h-4 w-64" />
            ) : (
              <p className="mt-1.5 text-[13.5px] leading-relaxed text-muted-foreground">{subtitle}</p>
            )}
            {expired && mode === "login" && (
              <div role="status" className="mt-5 rounded-lg bg-warning-soft px-3.5 py-2.5 text-[13px] text-warning">
                Your session expired. Sign in again to pick up where you left off.
              </div>
            )}
            {mode === "signup" && status.isSuccess && !signupOpen && (
              <div role="status" className="mt-5 rounded-lg bg-warning-soft px-3.5 py-2.5 text-[13px] text-warning">
                Sign-up is closed on this server. Ask the person who runs it for an invitation.
              </div>
            )}
            {inviteBlocked ? (
              <div className="mt-6 rounded-xl bg-card shadow-[var(--elev-2)]">
                <ErrorState
                  compact
                  title={token ? "This invitation cannot be used" : "No invitation in this link"}
                  error={
                    token
                      ? invitation.error
                      : new Error("Open the link from your invitation email. It ends with ?token=...")
                  }
                  onRetry={token ? () => void invitation.refetch() : undefined}
                />
              </div>
            ) : (
              <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
                {mode === "signup" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="org">Organisation</Label>
                    <Input id="org" autoComplete="organization" autoFocus className="h-10" placeholder="Acme Inc." value={org} onChange={(e) => setOrg(e.target.value)} />
                  </div>
                )}
                {mode !== "login" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="name">Your name</Label>
                    <Input id="name" autoComplete="name" autoFocus={mode === "invite"} className="h-10" value={name} onChange={(e) => setName(e.target.value)} />
                  </div>
                )}
                {mode !== "invite" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="email">Work email</Label>
                    <Input
                      id="email"
                      type="email"
                      autoComplete="username"
                      autoFocus={mode === "login"}
                      placeholder="you@company.com"
                      className="h-10"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      aria-invalid={!!error || undefined}
                    />
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label htmlFor="password">Password</Label>
                  <PasswordInput
                    id="password"
                    value={password}
                    onChange={setPassword}
                    autoComplete={mode === "login" ? "current-password" : "new-password"}
                    invalid={!!error}
                  />
                  {mode !== "login" && <FieldHint>At least 10 characters, with upper and lower case letters and a digit.</FieldHint>}
                </div>
                {error && <FieldError>{error}</FieldError>}
                <Button type="submit" size="lg" className="w-full" disabled={pending || (mode === "signup" && !signupOpen)}>
                  {pending
                    ? mode === "login"
                      ? "Signing in..."
                      : "Setting up..."
                    : mode === "signup"
                      ? "Create organisation"
                      : mode === "invite"
                        ? "Join the team"
                        : "Sign in"}
                  {!pending && <ArrowRightIcon />}
                </Button>
              </form>
            )}
            {mode === "login" && (
              <div className="mt-5">
                {ssoOpen ? (
                  <form
                    className="space-y-2 rounded-xl bg-muted p-3"
                    onSubmit={(e) => {
                      e.preventDefault();
                      const s = slug.trim().toLowerCase();
                      if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(s)) return setError("Enter your organisation's short name (letters, digits and dashes), as your admin gave it.");
                      window.location.assign(`/api/v1/auth/oidc/${encodeURIComponent(s)}/start`);
                    }}
                  >
                    <Label htmlFor="org-slug">Organisation short name</Label>
                    <div className="flex gap-2">
                      <Input id="org-slug" autoFocus placeholder="acme" className="h-9" value={slug} onChange={(e) => setSlug(e.target.value)} />
                      <Button type="submit" variant="outline">
                        Continue
                      </Button>
                    </div>
                    <FieldHint>You will sign in with your organisation&apos;s identity provider, then come back here.</FieldHint>
                  </form>
                ) : (
                  <Button type="button" variant="outline" className="w-full" onClick={() => setSsoOpen(true)}>
                    <BuildingIcon />
                    Sign in with your organisation
                  </Button>
                )}
              </div>
            )}
            <p className="mt-6 text-xs leading-relaxed text-muted-foreground">
              {mode === "login" ? (
                signupOpen ? (
                  <>
                    New to AgentGuard?{" "}
                    <Link href="/signup" className="font-medium text-primary underline-offset-2 hover:underline">
                      Create an organisation
                    </Link>
                    . Forgot your password? Ask an admin of your organisation to reset it.
                  </>
                ) : (
                  <>Accounts are created by invitation. Forgot your password? Ask an admin of your organisation.</>
                )
              ) : (
                <>
                  Already have an account?{" "}
                  <Link href="/login" className="font-medium text-primary underline-offset-2 hover:underline">
                    Sign in
                  </Link>
                  .
                </>
              )}
            </p>
          </div>
        </div>
        <p className="text-[11.5px] text-faint">Self-hosted. Decisions, secrets and audit records stay on your infrastructure.</p>
      </div>

      <aside className="relative hidden overflow-hidden bg-[var(--panel)] p-10 text-white lg:flex lg:flex-col lg:justify-between">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-90"
          style={{
            background:
              "radial-gradient(60% 50% at 80% 10%, var(--panel-glow), transparent 70%), radial-gradient(50% 45% at 10% 90%, var(--panel-glow-2), transparent 70%)",
          }}
        />
        <div className="relative flex items-center gap-2 text-[13px] font-medium text-white/70">
          <BrandMark className="size-6" />
          Open-source security for AI agents
        </div>

        <div className="relative max-w-lg">
          <h2 className="text-[34px] leading-[1.12] font-semibold tracking-[-0.03em]">
            Secure every agent.
            <br />
            Control every action.
            <br />
            <span className="text-[var(--panel-accent)]">Trust every execution.</span>
          </h2>
          <p className="mt-3 text-[14.5px] leading-relaxed text-white/65">
            AgentGuard stands between your agents and the tools they call. Every action is decided by policy before it runs, sensitive
            ones wait for a person, and everything lands in a log you can verify.
          </p>

          <div className="mt-8 space-y-2.5 rounded-2xl bg-white/[0.06] p-4 font-mono text-[12px] shadow-[0_20px_60px_rgba(0,0,0,0.35)] ring-1 ring-white/10 backdrop-blur">
            <div className="flex items-center justify-between gap-3 text-white/80">
              <span>billing-agent &rarr; payments.refund</span>
              <span className="rounded-full bg-amber-400/15 px-2 py-0.5 font-sans text-[11px] font-semibold text-amber-300">Needs approval</span>
            </div>
            <div className="text-white/50">{'{ "amount": 1250, "currency": "EUR", "order": "A-10422" }'}</div>
            <div className="flex items-center justify-between gap-3 text-white/80">
              <span>support-bot &rarr; crm.export</span>
              <span className="rounded-full bg-sky-400/15 px-2 py-0.5 font-sans text-[11px] font-semibold text-sky-300">Restrict: 100 rows</span>
            </div>
            <div className="flex items-center justify-between gap-3 text-white/80">
              <span>research-agent &rarr; db.delete</span>
              <span className="rounded-full bg-rose-400/15 px-2 py-0.5 font-sans text-[11px] font-semibold text-rose-300">Deny</span>
            </div>
            <div className="pt-1 font-sans text-[11px] text-white/45">policy production-database-protection v3, decided in 4 ms</div>
          </div>

          <ul className="mt-8 grid gap-5 sm:grid-cols-2">
            {PITCH.map((p) => (
              <li key={p.title} className="flex gap-3">
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-white/10 text-[var(--panel-accent)]">
                  <p.icon className="size-4" />
                </span>
                <div>
                  <div className="text-[13px] font-semibold">{p.title}</div>
                  <div className="mt-0.5 text-[12.5px] leading-relaxed text-white/55">{p.body}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="relative text-[11.5px] text-white/40">MIT licensed. Part of the Euron open-source initiative.</div>
      </aside>
    </div>
  );
}
