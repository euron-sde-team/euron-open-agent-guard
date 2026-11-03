# Local stack against real AWS

`make up` runs everything locally on the Floci emulator, which is what development, the
tests and the demo use. `make up-aws` keeps the same containers but points the AWS parts
at a real account: the KMS key, the objects and audit buckets, Secrets Manager and,
optionally, SES. Use it to check KMS policies, Object Lock and IAM against the real
service before a deployment, or to develop against a shared dev account.

## What stays local and what does not

| Part | `make up` (Floci) | `make up-aws` |
| --- | --- | --- |
| Postgres, Redis | containers | containers |
| OPA, Vault (dev mode), Mailpit, mock services | containers | containers |
| Sandbox and egress proxy | containers | containers |
| Key wrapping (`KEY_MODE=kms`) | KMS on Floci | your KMS key |
| Evidence, exports (`OBJECTS_BUCKET`) | S3 on Floci | your bucket |
| Audit checkpoints (`AUDIT_BUCKET`) | S3 on Floci with Object Lock | your Object Lock bucket |
| AWS Secrets Manager secret store | Floci | your account |
| Mail | SES on Floci (or Mailpit) | Mailpit by default, SES if you set it |

Only migrate, the api, the worker and the egress proxy call AWS. They run with
`AGENTGUARD_CLOUD=aws`, so no endpoint override is used.

## Steps

1. Create the AWS resources. The simplest way is the `aws-dev` environment
   ([deploy-aws.md](deploy-aws.md)), or just its key and buckets:

   ```bash
   cd infra/terraform/envs/aws-dev
   terraform init
   terraform apply -target=module.kms -target=module.storage
   terraform output
   ```

2. Fill in the overlay's settings from the outputs:

   ```bash
   cp deploy/compose/.env.aws.example deploy/compose/.env.aws
   # OBJECTS_BUCKET=<objects_bucket>   AUDIT_BUCKET=<audit_bucket>
   # KMS_KEY_ID=<kms_key_alias>        AWS_REGION=<region>
   ```

3. Make sure your AWS CLI profile can use them. The containers mount `~/.aws` read-only
   and use `AWS_PROFILE` (default `default`); no key is ever written to a file in this
   repository. The profile needs `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKey`
   on the key, `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on both buckets, and,
   for the Secrets Manager store, `secretsmanager:GetSecretValue` on the secrets your
   organisation references.

4. Start the stack:

   ```bash
   make up-aws
   make demo
   ```

## Things to know

- Object Lock is real: checkpoints written to an aws-dev bucket stay for the
  GOVERNANCE retention (30 days) unless a principal with `s3:BypassGovernanceRetention`
  removes them; in a COMPLIANCE bucket nobody can.
- KMS calls carry the encryption context `agentguard:record`. A key policy or IAM policy
  that requires it (as the `service` module's task roles do) works the same way from your
  laptop.
- Keep `MAIL_BACKEND=smtp` (the example's default) to read mail in Mailpit at
  http://localhost:5125. With `ses`, your account must have a verified identity for
  `MAIL_FROM_ADDRESS` and, in the SES sandbox, verified recipients.
- `make down` stops the containers and deletes only the local volumes; the AWS
  resources stay until you destroy them with Terraform.
