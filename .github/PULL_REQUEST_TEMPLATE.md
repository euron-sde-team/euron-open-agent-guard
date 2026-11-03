## What and why

<!-- One paragraph: what was wrong or missing, and how this change fixes it. Link the issue. -->

## How it was verified

- [ ] `make lint typecheck test`
- [ ] `make test-integration` (if the API, the worker, the egress proxy, a cache or database code changed)
- [ ] `make test-matrix` (if keys, secret stores or Redis code changed)
- [ ] `make test-sandbox` (if the sandbox, its image or its seccomp profile changed)
- [ ] `make e2e` (if a user flow or infrastructure changed)
- [ ] `make tf-validate tf-lint tf-security tf-aws-on-floci` (if Terraform changed)

## Checklist

- [ ] Docs updated (README, `docs/`, configuration reference) for any behavior or config change
- [ ] New Alembic revision instead of editing an applied one
- [ ] Every query stays scoped to the caller's organisation (no cross-tenant read or write)
- [ ] The guard still fails closed: a denied or held action never reaches the tool, and an error on the decision path denies sensitive actions
- [ ] No secret value can reach a response, a log, an audit record or an error
- [ ] Untrusted code still runs only in the sandbox, and every new outbound path goes through the egress checks
- [ ] `make openapi` run if the API changed
- [ ] No secrets, account ids, real hostnames or em/en dashes (`make sanitize` is clean)
- [ ] Security-relevant change? Described the threat and mitigation above
