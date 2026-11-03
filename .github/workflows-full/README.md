# Full pipeline (opt-in)

This repository runs only the fast checks in `.github/workflows/checks.yml` (ruff, mypy,
API unit tests, web lint, typecheck, unit tests and build). The full pipeline lives here
so it does not spend CI minutes on every fork by default. To enable it in your fork, copy
the files you want into `.github/workflows/`:

```bash
cp .github/workflows-full/*.yml .github/workflows/
```

| Workflow | What it runs | Time |
| --- | --- | --- |
| `ci.yml` | sanitization (secrets, account ids, em and en dashes), OpenAPI drift, unit and integration tests against Postgres 16, Redis 7, OPA, Vault and the mock services with the 85% coverage floor, and the hostile sandbox suite in the real sandbox image | about 20 min |
| `security.yml` | gitleaks over the full history, CodeQL (Python, TypeScript), bandit, pip-audit of the locked server dependencies, pnpm audit of the web app, and trivy scans of the server, sandbox and web images (fixed HIGH and CRITICAL fail) | about 15 min |
| `terraform.yml` | `terraform fmt` and `validate` of every environment, tflint, checkov (any unskipped finding fails), and `make tf-aws-on-floci`: aws-dev planned, applied, re-planned and destroyed against a throwaway Floci | about 15 min |
| `docker.yml` | multi-architecture builds (amd64, arm64) of the server, sandbox and web images | about 20 min |
| `e2e.yml` | the whole stack with `make up` on Floci, `make demo`, the stack acceptance tests, the 8-way backend matrix (keys local or KMS, secret store database or Vault, Redis on or off), Playwright, the browser QA sweep and an OWASP ZAP scan of the API | about 60 min |

Everything here also runs locally with the same `make` targets; see
[docs/guides/testing.md](../../docs/guides/testing.md).
