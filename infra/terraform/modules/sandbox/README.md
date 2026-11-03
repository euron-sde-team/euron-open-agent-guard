# Module: sandbox

The only place AgentGuard runs untrusted code (Python, Node.js, shell): an ECS service on
EC2 hosts of its own, in a cluster of its own.

Fargate cannot take a custom seccomp profile, and nsjail needs Docker's default profile
plus the namespace syscalls to build each run's sandbox without privilege. On these hosts
the profile (`infra/docker/sandbox-seccomp.json`) is the Docker daemon's default, written
by the user data, so the task itself stays unprivileged:

| Layer | Control |
| --- | --- |
| Task | every capability dropped, `no-new-privileges`, privileged off, read-only root, tmpfs `/tmp`, nproc and nofile ulimits, no core dumps, user 10001 |
| Each run | nsjail: fresh user, PID, network, mount, IPC and UTS namespaces, rlimits, read-only runtimes, private scratch tmpfs, no network interface |
| Network | ingress only from the api and worker security groups on the service port; egress only to the egress proxy (and DNS to the VPC resolver) |
| Host | IMDSv2 only, hop limit 1, `ECS_AWSVPC_BLOCK_IMDS=true`, `ECS_DISABLE_PRIVILEGED=true`, HTTPS egress only, encrypted root volume |
| IAM | task role with no policy; execution role injects only `SANDBOX_TOKEN` |

The service registers as `sandbox.<name_prefix>.internal` in the service module's Cloud
Map namespace; the `url` output is the api and worker's `SANDBOX_URL`.

```hcl
module "sandbox" {
  source                    = "../../modules/sandbox"
  name_prefix               = var.name_prefix
  vpc_id                    = module.network.vpc_id
  vpc_cidr_block            = module.network.vpc_cidr_block
  private_subnet_ids        = module.network.private_subnet_ids
  namespace_id              = module.service.namespace_id
  namespace_name            = module.service.namespace_name
  image                     = "${module.ecr.repository_urls["sandbox"]}:${var.image_tag}"
  caller_security_group_ids = { api = module.service.security_group_ids["api"], worker = module.service.security_group_ids["worker"] }
  egress_security_group_id  = module.service.security_group_ids["egress"]
  secrets                   = module.secrets.sandbox_secrets
  kms_key_arn               = module.kms.key_arn
  log_group_name            = module.observability.log_group_names["sandbox"]
  seccomp_profile_json      = file("${path.module}/../../../docker/sandbox-seccomp.json")
}
```
