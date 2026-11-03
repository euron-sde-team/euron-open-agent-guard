"use client";

import {
  ActivityIcon,
  BotIcon,
  CheckCheckIcon,
  CheckCircle2Icon,
  CircleIcon,
  FileCode2Icon,
  GlobeLockIcon,
  ShieldAlertIcon,
  SirenIcon,
  TimerIcon,
  WrenchIcon,
} from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { SeverityChip, StatusChip } from "@/components/badges";
import { DecisionChart, toDayRows } from "@/components/charts/decision-chart";
import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { Hint } from "@/components/hint";
import { PageHeader } from "@/components/page-header";
import { Segmented } from "@/components/segmented";
import { Stat } from "@/components/stat";
import { Surface, SurfaceHeader } from "@/components/surface";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolicies } from "@/features/policies/api";
import { useTools } from "@/features/tools/api";
import { useNow } from "@/hooks/use-now";
import type { Overview } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { formatMs, formatNumber, formatRelative } from "@/lib/format";
import { DECISION_CHART, DECISIONS, decisionSpec, SEVERITIES, threatKindLabel } from "@/lib/labels";
import { arr, counts, num, obj, str } from "@/lib/read";

import { useOverview } from "../api";

function sum(values: Record<string, number>): number {
  return Object.values(values).reduce((a, b) => a + b, 0);
}

/** The three steps a fresh organisation takes before AgentGuard is useful. */
function Onboarding({ agents }: { agents: number }) {
  const tools = useTools();
  const policies = usePolicies();
  const steps = [
    {
      done: agents > 0,
      icon: BotIcon,
      title: "Register your first agent",
      body: "Give it an identity and a credential. The SDK exchanges the credential for a short-lived token.",
      href: "/agents?register=1",
      cta: "Register an agent",
    },
    {
      done: (tools.data?.length ?? 0) > 0,
      icon: WrenchIcon,
      title: "Register a tool",
      body: "Describe what the agent may call: its parameters, risk, and whether AgentGuard executes it.",
      href: "/tools?register=1",
      cta: "Register a tool",
    },
    {
      done: (policies.data ?? []).some((p) => !p.builtin),
      icon: FileCode2Icon,
      title: "Write a policy",
      body: "Decide which actions are allowed, restricted, held for a person or denied. Simulate it first.",
      href: "/policies/new",
      cta: "Write a policy",
    },
  ];
  if (steps.every((s) => s.done)) return null;
  const doneCount = steps.filter((s) => s.done).length;
  return (
    <Surface className="mb-6 overflow-hidden">
      <SurfaceHeader
        title="Get AgentGuard between your agents and their tools"
        description={`${doneCount} of 3 done. With these in place, every action an agent takes is decided, recorded and, when it matters, held for a person.`}
      />
      <ol className="grid gap-3 px-5 pb-5 md:grid-cols-3">
        {steps.map((s, i) => (
          <li key={s.title} className={cn("flex flex-col rounded-xl bg-muted/70 p-4", s.done && "opacity-70")}>
            <div className="flex items-center gap-2 text-[12px] font-medium text-subtle">
              {s.done ? <CheckCircle2Icon className="size-4 text-primary" /> : <CircleIcon className="size-4" />}
              Step {i + 1}
            </div>
            <div className="mt-2 flex items-center gap-2 text-[14px] font-semibold">
              <s.icon className="size-4 text-primary" aria-hidden />
              {s.title}
            </div>
            <p className="mt-1 flex-1 text-[12.5px] leading-relaxed text-muted-foreground">{s.body}</p>
            {!s.done && (
              <Link href={s.href} className={buttonVariants({ size: "sm", className: "mt-3 self-start" })}>
                {s.cta}
              </Link>
            )}
          </li>
        ))}
      </ol>
    </Surface>
  );
}

function DecisionTile({ data }: { data: Overview }) {
  const d = counts(data.decisions_24h);
  const total = sum(d);
  return (
    <Surface className="flex flex-col gap-2 p-4 sm:col-span-2">
      <div className="flex items-center gap-2 text-[12.5px] font-medium text-muted-foreground">
        <ActivityIcon className="size-4 text-subtle" aria-hidden />
        Decisions, last 24 hours
      </div>
      <div className="tabular text-[22px] leading-tight font-semibold tracking-[-0.02em]">{formatNumber(total)}</div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted" aria-hidden>
        {total > 0 &&
          DECISIONS.map((k) =>
            d[k] ? <span key={k} className="h-full" style={{ width: `${(d[k] / total) * 100}%`, background: `var(--${DECISION_CHART[k]})` }} /> : null,
          )}
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-1 text-[12px] text-muted-foreground">
        {DECISIONS.map((k) => (
          <li key={k} className="flex items-center gap-1.5">
            <span className="size-2 rounded-[3px]" style={{ background: `var(--${DECISION_CHART[k]})` }} aria-hidden />
            {decisionSpec(k).label}
            <span className="tabular font-semibold text-foreground">{formatNumber(d[k] ?? 0)}</span>
          </li>
        ))}
      </ul>
    </Surface>
  );
}

function BarList({ items, empty, tone }: { items: { label: React.ReactNode; value: number; href?: string; display?: string }[]; empty: React.ReactNode; tone: string }) {
  if (!items.length) return <div className="px-5 pb-5">{empty}</div>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="space-y-1 px-3 pb-4">
      {items.map((i, n) => {
        const body = (
          <>
            <span className="absolute inset-y-1 left-0 rounded-md opacity-15" style={{ width: `${Math.max(4, (i.value / max) * 100)}%`, background: `var(--${tone})` }} aria-hidden />
            <span className="relative min-w-0 truncate font-medium">{i.label}</span>
            <span className="relative tabular text-muted-foreground">{i.display ?? formatNumber(i.value)}</span>
          </>
        );
        const cls = "relative flex items-center justify-between gap-3 rounded-md px-2 py-2 text-[13px]";
        return (
          <li key={n}>
            {i.href ? (
              <Link href={i.href} className={cn(cls, "hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring")}>
                {body}
              </Link>
            ) : (
              <div className={cls}>{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function RecentThreats({ items }: { items: Record<string, unknown>[] }) {
  const now = useNow(60_000);
  if (!items.length)
    return (
      <EmptyState
        compact
        icon={ShieldAlertIcon}
        title="No threats detected"
        description="Detections for injections, exfiltration, loops and privilege probing appear here as they fire."
        action={
          <Link href="/threats" className={buttonVariants({ size: "sm", variant: "outline" })}>
            Try the injection analyzer
          </Link>
        }
      />
    );
  return (
    <ul className="divide-y divide-hairline px-2 pb-2">
      {items.map((t) => {
        const id = str(t.id) ?? "";
        return (
          <li key={id}>
            <Link href={`/threats/${id}`} className="flex items-start gap-3 rounded-lg px-3 py-2.5 hover:bg-muted/60 focus-visible:outline-2 focus-visible:outline-ring">
              <SeverityChip level={str(t.severity) ?? "low"} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-medium">{str(t.summary) || threatKindLabel(str(t.kind) ?? "")}</div>
                <div className="mt-0.5 text-[12px] text-muted-foreground">
                  {threatKindLabel(str(t.kind) ?? "")}
                  {str(t.agent) ? ` · ${str(t.agent)}` : ""} · {formatRelative(str(t.at), now)}
                </div>
              </div>
              <StatusChip kind="threat" status={str(t.status) ?? "open"} />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-4" aria-busy aria-label="Loading">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className={cn("h-28 rounded-[14px]", i === 0 && "sm:col-span-2")} />
        ))}
      </div>
      <Skeleton className="h-80 rounded-[14px]" />
    </div>
  );
}

export function OverviewScreen() {
  const [days, setDays] = React.useState<"7" | "14" | "30">("14");
  const q = useOverview(Number(days));

  return (
    <>
      <PageHeader title="Overview" description="What your agents did, what they were stopped from doing, and what is waiting for you." />
      {q.isPending ? (
        <OverviewSkeleton />
      ) : q.isError ? (
        <Surface>
          <ErrorState error={q.error} title="Could not load the overview" onRetry={() => void q.refetch()} />
        </Surface>
      ) : (
        <OverviewBody data={q.data} days={days} setDays={setDays} />
      )}
    </>
  );
}

function OverviewBody({ data, days, setDays }: { data: Overview; days: "7" | "14" | "30"; setDays: (d: "7" | "14" | "30") => void }) {
  const agents = counts(data.agents);
  const threats = counts(data.threats_open);
  const totalThreats = sum(threats);
  const latency = counts(data.latency_ms);
  const rows = toDayRows(arr(data.decisions_by_day).map(obj));
  const anyDecision = rows.some((r) => r.allow + r.restrict + r.require_approval + r.deny + r.quarantine > 0);
  const denied = arr(data.top_denied_tools).map(obj);
  const risky = arr(data.top_risky_agents).map(obj);

  return (
    <>
      <Onboarding agents={sum(agents)} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <DecisionTile data={data} />
        <Link href="/approvals" className="rounded-[14px] focus-visible:outline-2 focus-visible:outline-ring">
          <Stat
            className="h-full"
            label="Approvals pending"
            icon={CheckCheckIcon}
            value={formatNumber(data.approvals_pending)}
            tone={data.approvals_pending ? "warn" : "default"}
            detail={data.approvals_pending ? "Held actions wait for a person" : "Nothing is waiting"}
          />
        </Link>
        <Link href="/threats" className="rounded-[14px] focus-visible:outline-2 focus-visible:outline-ring">
          <Stat
            className="h-full"
            label="Open threats"
            icon={ShieldAlertIcon}
            value={formatNumber(totalThreats)}
            detail={
              totalThreats ? (
                <span className="flex flex-wrap gap-1">
                  {SEVERITIES.filter((s) => threats[s])
                    .reverse()
                    .map((s) => (
                      <SeverityChip key={s} level={s} prefix={String(threats[s])} />
                    ))}
                </span>
              ) : (
                "No open detections"
              )
            }
          />
        </Link>
        <Link href="/incidents" className="rounded-[14px] focus-visible:outline-2 focus-visible:outline-ring">
          <Stat
            className="h-full"
            label="Open incidents"
            icon={SirenIcon}
            value={formatNumber(data.incidents_open)}
            detail={`${formatNumber(data.incidents_contained)} contained`}
          />
        </Link>
        <Link href="/network" className="rounded-[14px] focus-visible:outline-2 focus-visible:outline-ring">
          <Stat className="h-full" label="Blocked connections" icon={GlobeLockIcon} value={formatNumber(data.blocked_connections_24h)} detail="Egress refused, last 24 hours" />
        </Link>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Surface className="xl:col-span-2">
          <SurfaceHeader
            title="Decisions per day"
            description="Every authorize, execute and MCP call, by the outcome it would have had."
            action={
              <Segmented
                ariaLabel="Period"
                value={days}
                onChange={setDays}
                options={[
                  { value: "7", label: "7d" },
                  { value: "14", label: "14d" },
                  { value: "30", label: "30d" },
                ]}
              />
            }
          />
          <div className="px-5 pb-5">
            {anyDecision ? (
              <DecisionChart rows={rows} />
            ) : (
              <EmptyState
                compact
                icon={ActivityIcon}
                title="No decisions yet"
                description="Once an agent calls authorize, execute or the MCP gateway, each decision shows up here by outcome."
                action={
                  <Link href="/integrations" className={buttonVariants({ size: "sm", variant: "outline" })}>
                    See the SDK quick start
                  </Link>
                }
              />
            )}
          </div>
        </Surface>
        <Surface>
          <SurfaceHeader title="Decision latency" titleExtra={<Hint term="p95" />} description="Time to decide, last 24 hours (API, execute and MCP)." />
          <div className="grid grid-cols-2 gap-3 px-5 pb-4">
            <div className="rounded-xl bg-muted/70 p-3">
              <div className="text-[12px] text-muted-foreground">p50</div>
              <div className="tabular text-[20px] font-semibold">{formatMs(latency.p50 ?? null)}</div>
            </div>
            <div className="rounded-xl bg-muted/70 p-3">
              <div className="text-[12px] text-muted-foreground">p95</div>
              <div className="tabular text-[20px] font-semibold">{formatMs(latency.p95 ?? null)}</div>
            </div>
          </div>
          <SurfaceHeader className="pt-2" title="Top denied tools" description="Denied or quarantined, last 7 days." />
          <BarList
            tone="chart-deny"
            items={denied.map((t) => ({ label: <span className="font-mono text-[12.5px]">{str(t.tool)}</span>, value: num(t.denied) ?? 0, href: "/tools" }))}
            empty={<p className="text-[12.5px] text-muted-foreground">No tool was denied in the last 7 days.</p>}
          />
        </Surface>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Surface>
          <SurfaceHeader title="Riskiest agents" description="Average risk score of their actions, last 7 days." titleExtra={<Hint term="riskScore" />} />
          <BarList
            tone="chart-approval"
            items={risky.map((a) => ({
              label: (
                <span className="inline-flex items-center gap-2">
                  <BotIcon className="size-3.5 text-subtle" aria-hidden />
                  {str(a.agent)}
                  <span className="font-normal text-subtle">{formatNumber(num(a.actions))} actions</span>
                </span>
              ),
              value: num(a.risk) ?? 0,
              display: `risk ${num(a.risk) ?? 0}`,
              href: `/agents/${str(a.agent_id)}`,
            }))}
            empty={<p className="text-[12.5px] text-muted-foreground">No agent acted in the last 7 days.</p>}
          />
        </Surface>
        <Surface>
          <SurfaceHeader
            title="Recent threats"
            action={
              <Link href="/threats" className={buttonVariants({ size: "xs", variant: "ghost" })}>
                All threats
              </Link>
            }
          />
          <RecentThreats items={arr(data.recent_threats).map(obj)} />
        </Surface>
      </div>
      <p className="mt-6 flex items-center gap-1.5 text-[12px] text-subtle">
        <TimerIcon className="size-3.5" aria-hidden />
        {formatNumber(agents.active ?? 0)} active agents
        {agents.quarantined ? `, ${agents.quarantined} quarantined` : ""}
        {agents.suspended ? `, ${agents.suspended} suspended` : ""}.
      </p>
    </>
  );
}
