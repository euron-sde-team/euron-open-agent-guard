/**
 * Named aliases over the generated OpenAPI types (`pnpm gen:api`). Nothing here is
 * hand-written: every shape comes from `schema.d.ts`, which is generated from
 * docs/api/openapi.yaml.
 */
import type { components } from "./schema";

type S = components["schemas"];

export type User = S["UserOut"];
export type Session = S["SessionOut"];
export type Invitation = S["InvitationOut"];
export type InvitationCreated = S["InvitationCreated"];
export type Oidc = S["OidcOut"];
export type OidcIn = S["OidcIn"];

export type OrgSettings = S["OrgSettingsOut"];
export type OrgSettingsUpdate = S["OrgSettingsUpdate"];
export type Enforcement = S["Enforcement"];
export type Detection = S["Detection"];
export type ThreatResponses = S["ThreatResponses"];
export type Retention = S["Retention"];
export type Notifications = S["Notifications"];
export type KillSwitch = S["KillSwitch"];
export type Project = S["ProjectOut"];
export type ProjectIn = S["ProjectIn"];
export type SystemInfo = S["SystemInfo"];
export type Overview = S["Overview"];

export type Agent = S["AgentOut"];
export type AgentDetail = S["AgentDetail"];
export type AgentIn = S["AgentIn"];
export type AgentUpdate = S["AgentUpdate"];
export type Credential = S["CredentialOut"];
export type Issued = S["IssuedOut"];
export type Registered = S["RegisteredOut"];

export type AccessRole = S["RoleOut"];
export type AccessRoleIn = S["RoleIn"];
export type Permission = S["PermissionIn"];
export type Binding = S["BindingOut"];
export type Resource = S["ResourceOut"];
export type ResourceIn = S["ResourceIn"];

export type PolicySummary = S["PolicyOut"];
export type PolicyDetail = S["PolicyDetail"];
export type PolicyVersion = S["agentguard__policies__router__VersionOut"];
export type ValidateOut = S["ValidateOut"];
export type EvaluateRequest = S["EvaluateRequest"];
export type EvaluateResponse = S["EvaluateResponse"];
export type SimulateOut = S["SimulateOut"];

export type Tool = S["ToolOut"];
export type ToolIn = S["ToolIn"];
export type ToolVersion = S["agentguard__tools__router__VersionOut"];
export type McpServer = S["ServerOut"];
export type McpServerIn = S["ServerIn"];
export type Discover = S["DiscoverOut"];

export type Decision = S["DecisionOut"];
export type DecisionDetail = S["DecisionDetail"];
export type DecisionPage = S["Page_DecisionOut_"];
export type Run = S["RunOut"];

export type Approval = S["ApprovalOut"];
export type ApprovalDetail = S["ApprovalDetail"];
export type ApprovalCounts = S["CountsOut"];
export type Vote = S["VoteOut"];

export type Threat = S["ThreatOut"];
export type Analyze = S["AnalyzeOut"];
export type SecurityEvent = S["SecurityEvent"];
export type Assessment = S["AssessmentOut"];
export type RiskRule = S["RiskRuleOut"];
export type RiskRuleIn = S["RiskRuleIn"];

export type Secret = S["SecretOut"];
export type SecretDetail = S["SecretDetail"];
export type SecretIn = S["SecretIn"];
export type Lease = S["LeaseOut"];

export type SandboxSession = S["SandboxOut"];
export type SandboxHealth = S["SandboxHealth"];

export type NetworkPolicy = S["NetworkPolicyOut"];
export type NetworkPolicyIn = S["NetworkPolicyIn"];
export type NetworkTest = S["TestOut"];
export type Egress = S["EgressOut"];
export type Limit = S["LimitOut"];
export type LimitIn = S["LimitIn"];

export type Incident = S["IncidentOut"];
export type IncidentDetail = S["IncidentDetail"];
export type Evidence = S["EvidenceOut"];
export type TimelineEvent = S["EventOut"];

export type AuditEntry = S["AuditOut"];
export type AuditPage = S["Page_AuditOut_"];
export type Verify = S["VerifyOut"];
export type Checkpoint = S["CheckpointOut"];

export type ApiKey = S["ApiKeyOut"];
export type ApiKeyCreated = S["ApiKeyCreated"];
export type Webhook = S["WebhookOut"];
export type WebhookCreated = S["WebhookCreated"];
export type Delivery = S["DeliveryOut"];
export type Integration = S["IntegrationOut"];
export type IntegrationIn = S["IntegrationIn"];
