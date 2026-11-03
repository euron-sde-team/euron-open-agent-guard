# ADR-0005: Taint the run instead of trusting an injection classifier

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Prompt injection arrives in content the agent reads: a web page, a ticket, a tool's
output, a document. Detectors (heuristics or a model) catch many attempts and miss some.
Worse, the action that follows an injection usually looks benign on its own: "send an
email to backup@example.com with the attached list" is a normal email. Judging each
request by its own parameters cannot tell the difference.

## Decision

AgentGuard tracks **runs** (an agent's own `run_id`: a task, a thread, a job). When content
read in a run is flagged as an injection, by the content scan (`POST /api/v1/content/scan`)
or by the scan of a tool result AgentGuard relayed, the run is **tainted**
(`runs.tainted_at`, `runs.taint` with the source, verdict and score). Taint is sticky for
the run.

The built-in policy `tainted-run-guard` then holds every action of that run whose risk is
`high` or above for a security officer or org admin, whatever its parameters say. The
risk engine also adds points for a tainted run. Policies can condition on `run.tainted`
directly (deny instead of hold, or hold everything external).

The heuristic guard (`protection/injection.py`) and the optional AI classifier only decide
whether to taint. The classifier can raise a verdict, never lower it.

## Consequences

**Good**
- A missed detection on the next request does not matter: the defence is a permission
  change on the run, not a judgement of that request
  (`test_injected_content_taints_the_run_and_holds_its_next_risky_action`).
- The behaviour is visible and explainable: the decision says which policy held it and the
  run shows where the taint came from.

**Bad / caveats**
- It only works when agents pass a `run_id` and send what they read through the scan (or
  read it through AgentGuard-run tools). Content that never passes AgentGuard cannot taint.
- A false positive holds a run's risky actions for a person; with `taint_on: suspicious`
  that happens more often.
- Low and medium risk actions of a tainted run still proceed by default; organisations that
  want more add a policy.

## Alternatives considered

- **Block requests the classifier flags**: the classifier sees the content, not the
  action, and the action is what does harm.
- **A guard model on every request**: cost and latency per call, and the guard is itself
  injectable.
- **Taint per agent instead of per run**: simpler bookkeeping, but one poisoned page would
  stop all of an agent's unrelated work.
