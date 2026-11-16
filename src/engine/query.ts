import type { Grant, GrantSource, PolicyRule, Principal, RequestAttrs, Scope } from '../model/types';
import { ruleAllowsRequest, apiGroupMatches, resourceMatches, verbMatches } from '../model/rbac';

export interface AllowResult {
  rule: PolicyRule;
  source: GrantSource;
  scope: Scope;
}

/**
 * Does any grant authorize this request? Mirrors the RBAC authorizer: for a
 * namespaced request, both cluster-wide and same-namespace grants apply; for a
 * cluster-scoped request only cluster-wide grants apply.
 */
export function findAllowance(grants: Grant[], req: RequestAttrs): AllowResult | null {
  for (const grant of grants) {
    if (grant.scope.kind === 'namespace') {
      if (req.namespace === undefined) continue;
      if (grant.scope.namespace !== req.namespace) continue;
    }
    if (ruleAllowsRequest(grant.rule, req)) {
      return { rule: grant.rule, source: grant.source, scope: grant.scope };
    }
  }
  return null;
}

export function anyAllowance(grants: Grant[], req: RequestAttrs): boolean {
  return findAllowance(grants, req) !== null;
}

/** All grants that permit the request, for showing every reason. */
export function allAllowances(grants: Grant[], req: RequestAttrs): AllowResult[] {
  const out: AllowResult[] = [];
  for (const grant of grants) {
    if (grant.scope.kind === 'namespace') {
      if (req.namespace === undefined || grant.scope.namespace !== req.namespace) continue;
    }
    if (ruleAllowsRequest(grant.rule, req)) {
      out.push({ rule: grant.rule, source: grant.source, scope: grant.scope });
    }
  }
  return out;
}

export function canCluster(grants: Grant[], verb: string, apiGroup: string, resource: string, name?: string): AllowResult | null {
  return findAllowance(grants, { verb, apiGroup, resource, name });
}

export function canInNamespace(
  grants: Grant[],
  verb: string,
  apiGroup: string,
  resource: string,
  namespace: string,
  name?: string,
  subresource?: string,
): AllowResult | null {
  return findAllowance(grants, { verb, apiGroup, resource, namespace, name, subresource });
}

export function canAnyOf(
  grants: Grant[],
  verbs: string[],
  apiGroup: string,
  resource: string,
  namespace: string | undefined,
  subresource?: string,
): AllowResult | null {
  for (const verb of verbs) {
    const hit = findAllowance(grants, {
      verb,
      apiGroup,
      resource,
      ...(namespace !== undefined ? { namespace } : {}),
      ...(subresource !== undefined ? { subresource } : {}),
    });
    if (hit) return hit;
  }
  return null;
}

/** True when the rule could match any object of the resource (no name restriction). */
export function ruleUnrestricted(rule: PolicyRule): boolean {
  return (rule.resourceNames ?? []).length === 0;
}

/**
 * Does this rule grant a wildcard over all resources? Mirrors the "cluster
 * admin" community definition: `apiGroups: ["*"], resources: ["*"], verbs: ["*"]`
 * (or equivalent verb wildcard) at cluster scope.
 */
export function isClusterAdminRule(rule: PolicyRule): boolean {
  if ((rule.nonResourceURLs ?? []).length > 0 && (rule.resources ?? []).length === 0) return false;
  return apiGroupMatches(rule, '*') && resourceMatches(rule, '*', '') && verbMatches(rule, '*');
}

export function isClusterAdminGrant(grant: Grant): boolean {
  return grant.scope.kind === 'cluster' && isClusterAdminRule(grant.rule);
}

export function clusterAdminGrant(grants: Grant[]): Grant | null {
  return grants.find(isClusterAdminGrant) ?? null;
}

/**
 * Is this principal a hard-coded superuser? `system:masters` is wired straight
 * into the API server's privileged-group authorizer, so it is cluster-admin
 * whether or not a ClusterRoleBinding exists in the dump.
 */
export function isHardcodedSuperuser(principal: Principal): boolean {
  return principal.kind === 'Group' && principal.name === 'system:masters';
}

/**
 * Read access to Secrets is the canonical token-theft primitive. Returns the
 * namespaces where the grants allow reading at least one Secret, and whether
 * the access is unrestricted (no resourceNames).
 */
export interface SecretReadCapability {
  scope: 'cluster' | 'namespaces';
  namespaces: string[];
  unrestricted: boolean;
  grants: Grant[];
}

export function secretReadCapability(grants: Grant[], allNamespaces: string[]): SecretReadCapability | null {
  const hits: Grant[] = [];
  let unrestricted = false;
  const namespaces = new Set<string>();
  let clusterWide = false;

  for (const grant of grants) {
    const readOk = ['get', 'list', 'watch'].some((v) =>
      ruleAllowsRequest(grant.rule, {
        verb: v,
        apiGroup: '',
        resource: 'secrets',
        ...(grant.scope.kind === 'namespace' ? { namespace: grant.scope.namespace } : {}),
      }),
    );
    if (!readOk) continue;
    hits.push(grant);
    if ((grant.rule.resourceNames ?? []).length === 0) unrestricted = true;
    if (grant.scope.kind === 'cluster') {
      clusterWide = true;
      allNamespaces.forEach((n) => namespaces.add(n));
    } else {
      namespaces.add(grant.scope.namespace);
    }
  }

  if (hits.length === 0) return null;
  return {
    scope: clusterWide ? 'cluster' : 'namespaces',
    namespaces: [...namespaces].sort(),
    unrestricted,
    grants: hits,
  };
}

/** Can the grants create/patch/update Secrets (needed to mint a legacy token secret)? */
export function secretWriteCapability(grants: Grant[], namespace: string): AllowResult | null {
  for (const verb of ['create', 'patch', 'update']) {
    const hit = canInNamespace(grants, verb, '', 'secrets', namespace);
    if (hit) return hit;
  }
  return null;
}

/** Can the grants mint tokens for arbitrary ServiceAccounts in `namespace`? */
export function tokenRequestCapability(grants: Grant[], namespace: string): AllowResult | null {
  return canInNamespace(grants, 'create', '', 'serviceaccounts', namespace, undefined, 'token');
}

/** Can the grants create Pods (or a workload controller) in `namespace`? */
export function podCreationCapability(grants: Grant[], namespace: string): AllowResult | null {
  const direct = canInNamespace(grants, 'create', '', 'pods', namespace);
  if (direct) return direct;
  const controllers: Array<[string, string]> = [
    ['apps', 'deployments'],
    ['apps', 'daemonsets'],
    ['apps', 'statefulsets'],
    ['apps', 'replicasets'],
    ['batch', 'jobs'],
    ['batch', 'cronjobs'],
  ];
  for (const [group, resource] of controllers) {
    const hit = canInNamespace(grants, 'create', group, resource, namespace);
    if (hit) return hit;
  }
  return null;
}

/** Can the grants exec/attach into a Pod in `namespace` (or patch ephemeral containers)? */
export function podExecCapability(grants: Grant[], namespace: string): { result: AllowResult; via: string } | null {
  for (const [verb, sub, label] of [
    ['create', 'exec', 'pods/exec'],
    ['create', 'attach', 'pods/attach'],
    ['update', 'ephemeralcontainers', 'pods/ephemeralcontainers'],
    ['patch', 'ephemeralcontainers', 'pods/ephemeralcontainers'],
  ] as const) {
    const hit = canInNamespace(grants, verb, '', 'pods', namespace, undefined, sub);
    if (hit) return { result: hit, via: label };
  }
  const patch = canInNamespace(grants, 'patch', '', 'pods', namespace);
  if (patch) return { result: patch, via: 'patch pods' };
  const update = canInNamespace(grants, 'update', '', 'pods', namespace);
  if (update) return { result: update, via: 'update pods' };
  return null;
}

/**
 * Access to the kubelet API through the node proxy subresource. `nodes/proxy`
 * is cluster-scoped, so only cluster-wide grants can satisfy it.
 */
export function nodeProxyCapability(grants: Grant[]): AllowResult | null {
  for (const verb of ['get', 'create']) {
    const hit = findAllowance(grants, { verb, apiGroup: '', resource: 'nodes', subresource: 'proxy' });
    if (hit) return hit;
  }
  return null;
}

/** A cluster-scoped request (no namespace), including subresources. */
export function canClusterResource(
  grants: Grant[],
  verb: string,
  apiGroup: string,
  resource: string,
  subresource?: string,
  name?: string,
): AllowResult | null {
  return findAllowance(grants, { verb, apiGroup, resource, subresource, name });
}
