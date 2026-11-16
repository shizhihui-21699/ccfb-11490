export type Scope = { kind: 'cluster' } | { kind: 'namespace'; namespace: string };

export interface PolicyRule {
  apiGroups?: string[];
  resources?: string[];
  verbs?: string[];
  nonResourceURLs?: string[];
  resourceNames?: string[];
}

export interface LabelSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: Array<{ key: string; operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist'; values?: string[] }>;
}

export type Origin = 'imported' | 'builtin';

export interface ClusterRoleDef {
  name: string;
  rules: PolicyRule[];
  aggregationRule?: { clusterRoleSelectors: LabelSelector[] };
  labels: Record<string, string>;
  origin: Origin;
}

export interface RoleDef {
  namespace: string;
  name: string;
  rules: PolicyRule[];
  labels: Record<string, string>;
  origin: Origin;
}

export interface RoleRef {
  apiGroup: string;
  kind: 'ClusterRole' | 'Role';
  name: string;
}

export interface Subject {
  apiGroup?: string;
  kind: 'User' | 'Group' | 'ServiceAccount';
  name: string;
  namespace?: string;
}

export interface BindingDef {
  kind: 'RoleBinding' | 'ClusterRoleBinding';
  name: string;
  namespace?: string;
  roleRef: RoleRef;
  subjects: Subject[];
  origin: Origin;
}

export interface ServiceAccountDef {
  namespace: string;
  name: string;
  secrets: string[];
  automountServiceAccountToken?: boolean | null;
  origin: Origin;
}

export interface PodDef {
  namespace: string;
  name: string;
  serviceAccountName: string;
  nodeName?: string;
  labels: Record<string, string>;
}

export interface SecretDef {
  namespace: string;
  name: string;
  type: string;
  serviceAccountName?: string;
  keys: string[];
}

export interface ResolvedClusterRole {
  def: ClusterRoleDef;
  rules: PolicyRule[];
  /** Names of ClusterRoles whose rules are aggregated into this one. */
  aggregatedFrom: string[];
  /** Aggregated selectors of this role, if any. */
  aggregated: boolean;
}

export interface Diagnostic {
  level: 'error' | 'warning' | 'info';
  message: string;
  object?: string;
}

export interface ClusterModel {
  clusterRoles: Map<string, ResolvedClusterRole>;
  /** namespace -> role name -> role */
  roles: Map<string, Map<string, RoleDef>>;
  roleBindings: BindingDef[];
  clusterRoleBindings: BindingDef[];
  serviceAccounts: ServiceAccountDef[];
  pods: PodDef[];
  secrets: SecretDef[];
  namespaces: string[];
  users: Set<string>;
  groups: Set<string>;
  diagnostics: Diagnostic[];
  bootstrapIncluded: boolean;
}

// ---------------------------------------------------------------------------
// Principals (the identities an attacker can act as)
// ---------------------------------------------------------------------------

export type Principal =
  | { kind: 'User'; name: string }
  | { kind: 'Group'; name: string }
  | { kind: 'ServiceAccount'; namespace: string; name: string };

export function principalId(p: Principal): string {
  switch (p.kind) {
    case 'User':
      return `user:${p.name}`;
    case 'Group':
      return `group:${p.name}`;
    case 'ServiceAccount':
      return `sa:${p.namespace}/${p.name}`;
  }
}

export function principalLabel(p: Principal): string {
  switch (p.kind) {
    case 'User':
      return `用户 ${p.name}`;
    case 'Group':
      return `组 ${p.name}`;
    case 'ServiceAccount':
      return `SA ${p.namespace}/${p.name}`;
  }
}

/** A source of a permission: which binding, which subject entry, which role. */
export interface GrantSource {
  bindingKind: 'RoleBinding' | 'ClusterRoleBinding';
  bindingName: string;
  bindingNamespace?: string;
  roleKind: 'Role' | 'ClusterRole';
  roleName: string;
  roleNamespace?: string;
  subjectKind: string;
  subjectName: string;
  subjectNamespace?: string;
  origin: Origin;
}

export interface Grant {
  rule: PolicyRule;
  scope: Scope;
  source: GrantSource;
  /** Set when this grant comes from a technique rather than a binding (e.g. poisoned role). */
  viaTechnique?: string;
}

export interface RequestAttrs {
  verb: string;
  apiGroup: string;
  resource?: string;
  subresource?: string;
  name?: string;
  namespace?: string;
  nonResourceURL?: string;
}

export type Confidence = 'certain' | 'conditional';

export type TechniqueCategory = 'rbac-write' | 'impersonation' | 'workload' | 'credential' | 'admission' | 'infra';

export interface Reference {
  label: string;
  url: string;
}

export interface TechniqueSpec {
  id: string;
  nameZh: string;
  nameEn: string;
  category: TechniqueCategory;
  severity: 'critical' | 'high' | 'medium' | 'info';
  requirement: string;
  rationale: string;
  limitations: string[];
  references: Reference[];
  /** Hidden / often-missed escalation path worth auditing. */
  hidden: boolean;
}

export interface EdgeEvidence {
  /** The permission required, in human terms. */
  permission: string;
  /** The concrete API request / kubectl command an attacker would issue. */
  action: string;
  /** The rule that authorizes the step. */
  rule?: PolicyRule;
  /** Where the rule came from. */
  source?: GrantSource;
  /** Extra objects involved (pod, secret, target SA, role bound...). */
  objects?: string[];
  notes?: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
  technique: string;
  confidence: Confidence;
  evidence: EdgeEvidence;
}

export interface GraphNode {
  id: string;
  base: Principal;
  held: HeldRole[];
  impersonatedGroups: string[];
  synthetic?: SyntheticCapability;
  /** Set when this node represents a principal after acquiring a role via a technique. */
  derived?: { techniqueId: string; description: string; addedGrants: number };
  /** Every grant comes from bootstrap policy, not from an imported object. */
  builtinOnly: boolean;
  /** The identity itself appears in the imported data (an SA object, a pod, or a binding subject). */
  imported: boolean;
  grants: Grant[];
  label: string;
  detail: string;
}

export interface HeldRole {
  kind: 'Role' | 'ClusterRole';
  name: string;
  namespace?: string;
  scope: Scope;
}

export interface SyntheticCapability {
  kind: 'cluster-admin' | 'namespace-wildcard' | 'read-all-secrets';
  namespace?: string;
  techniqueId: string;
  note: string;
  evidence: EdgeEvidence;
}

export interface PathHop {
  edge: GraphEdge;
  fromNode: GraphNode;
  toNode: GraphNode;
}

export interface PathResult {
  start: GraphNode;
  end: GraphNode;
  hops: PathHop[];
  /** True when the terminal node is cluster-admin equivalent. */
  reachesClusterAdmin: boolean;
}
