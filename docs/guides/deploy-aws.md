# Deploy to AWS

AgentGuard ships complete Terraform for AWS in `infra/terraform`. This repository never
applies it to a real account itself: every module is validated, linted (tflint), scanned
(checkov) and exercised end to end against the Floci emulator (`make tf-aws-on-floci`:
plan, apply, re-plan with no additions or replacements, destroy). Everything a real
deployment needs is here; you run it with your own account and credentials.

## What gets created

```
                    Internet
                       │ 443 (80 redirects)
                ┌──────▼──────┐   WAF: AWS managed rules + per-IP flood guard
                │     ALB     │
                └──┬───────┬──┘
     /api/* /ws/*  │       │  everything else
     /oauth/* /mcp │       │
     /.well-known/*│       │
              ┌────▼──┐ ┌──▼───┐
              │  api  │ │ web  │            ECS Fargate (cluster <name_prefix>)
              └─┬──┬──┘ └──────┘
   ┌────────────┘  │  egress.<prefix>.internal:3128   ┌──────────────┐
   │   ┌───────────┼───────────────────────────────►  │ egress proxy │──► internet
   │   │  ┌────────┴┐                                 └──────▲───────┘   (network policy)
   │   │  │ worker  │──────────────────────────────────────┘ │
   │   │  └────┬────┘                                        │ only destination
   │   │       │ sandbox.<prefix>.internal:8080       ┌──────┴───────┐
   │   └───────┴────────────────────────────────────► │   sandbox    │ ECS on EC2
   │                                                  └──────────────┘ (cluster <prefix>-sandbox)
   ├──► RDS PostgreSQL 16     ├──► ElastiCache (Valkey, TLS, AUTH)
   ├──► S3 objects bucket     ├──► S3 audit bucket (Object Lock)
   ├──► KMS customer key      ├──► Secrets Manager
   └──► SES (outgoing mail)        CloudWatch logs, metrics, alarms, dashboard
```

| Module | Creates |
| --- | --- |
| `network` | VPC, public and private subnets across 2 (dev) or 3 (prod) AZs, NAT, S3 gateway endpoint, optional KMS and Secrets Manager interface endpoints, VPC flow logs, a locked-down default security group |
| `kms` | One customer managed key (yearly rotation) and its alias: wraps every stored secret's data key (encryption context `agentguard:record`) and encrypts the buckets, RDS, ElastiCache, Secrets Manager, the alarm topic and the logs |
| `database` | RDS PostgreSQL 16, encrypted, TLS forced, private, Performance Insights, enhanced monitoring, IAM auth enabled. No extensions needed |
| `cache` | ElastiCache (Valkey) with TLS in transit, an AUTH token and `maxmemory-policy noeviction` (limit counters and replay nonces are never evicted; a full cache makes AgentGuard fail closed) |
| `storage` | `<prefix>-objects` (versioned: evidence, exports, backups) and `<prefix>-audit` (versioned, S3 Object Lock with a default retention: signed audit checkpoints) |
| `secrets` | `<prefix>/app` (SESSION_SECRET, TOKEN_PEPPER, SANDBOX_TOKEN), `<prefix>/connections` (DATABASE_URL, REDIS_URL), `<prefix>/integrations` (VAULT_TOKEN, empty until you set them), `<prefix>/bootstrap` (first owner's password, only during `make aws-admin`) |
| `email` | SES domain identity with Easy DKIM, a configuration set that requires TLS and suppresses bounces and complaints, and a send policy limited to one From address |
| `ecr` | Repositories `server`, `web`, `sandbox`: immutable tags, scan on push, KMS encrypted, lifecycle rules |
| `service` | ECS Fargate cluster with the api, worker, egress proxy and web services, the migrate task definition, the ALB with HTTPS (TLS 1.3 policy), WAF with logging, Cloud Map names, autoscaling, and a security group, execution role and task role per app |
| `sandbox` | A separate ECS cluster on EC2 (Graviton) hosts for the sandbox, with the sandbox seccomp profile as the Docker daemon default (see below) |
| `observability` | Encrypted log groups per app, security metrics from the JSON logs, alarms to an SNS topic (optionally e-mailed) and one dashboard |

### Why the sandbox is not on Fargate

The sandbox runs one nsjail per execution, built from user namespaces so that the
container itself needs no privilege. That needs Docker's default seccomp profile plus the
namespace syscalls, and Fargate cannot take a custom seccomp profile. The `sandbox` module
therefore runs its own Auto Scaling group of ECS optimized Amazon Linux 2023 hosts whose
user data installs `infra/docker/sandbox-seccomp.json` as the Docker daemon default.
Nothing else is scheduled on those hosts. Around the code it runs:

| Layer | Control |
| --- | --- |
| Task | all capabilities dropped, `no-new-privileges`, privileged off, read-only root, tmpfs `/tmp`, nproc and nofile ulimits, no core dumps, user 10001 |
| Each run | nsjail: new user, PID, network, mount, IPC and UTS namespaces, rlimits, read-only runtimes, a private scratch tmpfs, no network interface |
| Network | ingress only from the api and worker security groups on port 8080; egress only to the egress proxy on 3128 (plus DNS to the VPC resolver) |
| Host | IMDSv2 only with hop limit 1, `ECS_AWSVPC_BLOCK_IMDS=true`, `ECS_DISABLE_PRIVILEGED=true`, HTTPS egress only, encrypted root volume, no SSH (Session Manager) |
| IAM | the task role has no policy at all; the execution role injects only `SANDBOX_TOKEN` |

### The egress proxy

The egress proxy runs as a Fargate service, never behind the load balancer. It registers
in Cloud Map as `egress.<name_prefix>.internal` and accepts connections on port 3128 only
from the api, the worker, the sandbox, and the agent networks you list in
`egress_client_cidrs` or `egress_client_security_group_ids`. It may connect out on 443,
80 and any `egress_extra_ports`; the agent's network policy then decides per destination,
and the proxy checks the connected peer so private ranges and metadata addresses are
refused even after DNS rebinding. Point your agents at the `egress_proxy_url` output as
`HTTP_PROXY` and `HTTPS_PROXY`.

## Prerequisites

- An AWS account and credentials with rights to create the resources above
- Terraform 1.10 or newer (or the `hashicorp/terraform:1.16.6` image), Docker with
  buildx, the AWS CLI v2 and Python 3
- An ACM certificate in the target region covering your host name
- A domain for mail (an SES identity) and, ideally, a Route53 hosted zone for it

## Deploy

1. Copy and edit the variables:

   ```bash
   cp infra/terraform/envs/aws-dev/terraform.tfvars.example infra/terraform/envs/aws-dev/terraform.tfvars
   ```

   `name_prefix` must be globally unique (the bucket names derive from it) and at most 24
   characters. Set `hostname`, `certificate_arn`, `route53_zone_id` (or leave it out and
   create the DNS records from the outputs), `mail_domain` and `mail_from_address`.

2. Keep state remotely for anything shared: copy `backend.tf.example` to `backend.tf`
   and fill in a private, versioned, encrypted state bucket. State contains generated
   secrets.

3. Deploy in one step:

   ```bash
   make aws-deploy ENV=aws-dev TAG=0.1.0
   ```

   `scripts/aws-deploy.sh` applies the registries first, builds and pushes the `server`,
   `web` and `sandbox` images for ARM64, applies the infrastructure with the services
   still on the previous tag and only the migrate task on the new one, runs the
   migrations as a one-off task, then moves every service to the new tag and waits for
   the main cluster and the sandbox cluster to become stable. A failed migration stops
   the deploy with the previous release still serving, so migrations must stay backward
   compatible with the release before them.

4. Create the first owner:

   ```bash
   AGENTGUARD_ADMIN_PASSWORD='...' make aws-admin ENV=aws-dev EMAIL=you@example.com ORG='Acme'
   ```

   The password goes to the bootstrap secret, never into an ECS override, and is
   overwritten with a random value as soon as the task stops.

5. Mail: publish the `dkim_records` output if you gave no Route53 zone, and request SES
   production access. Until then approval requests reach only verified addresses.

6. Optional integrations: for the Vault secret store put `VAULT_TOKEN` into the
   `integrations_secret_arn` secret (as JSON keys), set `vault_url`, `tokenshield_url` or
   `opa_url` in `terraform.tfvars`, apply again and force a new deployment.

## aws-dev and aws-prod

| | aws-dev | aws-prod |
| --- | --- | --- |
| AZs, NAT | 2, one NAT | 3, NAT per AZ, interface endpoints |
| Database | single AZ, 3-day backups, no deletion protection | Multi-AZ, 14-day backups, deletion protection, final snapshot |
| Cache | one node | primary and replica with failover, snapshots |
| Services | api 1 to 2, worker 1 to 2, egress 1 to 2, web 1 to 2 | api 2 to 6, worker 2 to 6, egress 2 to 6, web 2 to 4 |
| Sandbox | 1 to 2 hosts, 1 to 4 tasks | 2 to 6 hosts, 2 to 12 tasks |
| Audit checkpoints | Object Lock GOVERNANCE, 30 days | Object Lock COMPLIANCE, 365 days |
| Logs | 14 days | 365 days |

COMPLIANCE mode means nobody, including the account root, can delete or shorten the lock
on a checkpoint inside the window. Destroying aws-prod while checkpoints are locked fails
on the audit bucket by design.

## Production settings the API enforces

With `ENVIRONMENT=production` the API, the worker and the egress proxy refuse to start
unless SESSION_SECRET, TOKEN_PEPPER and SANDBOX_TOKEN are random, at least 32 characters
and all different, cookies are secure, mail is SES or SMTP, `ALLOW_PRIVATE_URLS` is false,
public URLs are HTTPS, `VAULT_URL` (when set) is HTTPS, and `AWS_ENDPOINT_URL` is unset.
The Terraform sets all of these; `signup_enabled` defaults to false on AWS.

## Cost notes

The fixed cost is dominated by the NAT gateways, RDS, ElastiCache, the ALB and the
always-on sandbox host. aws-dev keeps each of these at its smallest sensible size.
