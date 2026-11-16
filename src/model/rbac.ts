import type { PolicyRule, RequestAttrs } from './types';

/**
 * These matchers mirror `pkg/apis/rbac/v1/evaluation_helpers.go` in
 * kubernetes/kubernetes. Keeping them byte-for-byte equivalent matters: an
 * analyzer that is stricter than the API server produces false negatives, and
 * one that is looser produces paths that cannot be walked.
 */

export function verbMatches(rule: PolicyRule, verb: string): boolean {
  for (const v of rule.verbs ?? []) {
    if (v === '*') return true;
    if (v === verb) return true;
  }
  return false;
}

export function apiGroupMatches(rule: PolicyRule, apiGroup: string): boolean {
  for (const g of rule.apiGroups ?? []) {
    if (g === '*') return true;
    if (g === apiGroup) return true;
  }
  return false;
}

export function resourceMatches(rule: PolicyRule, combinedResource: string, subresource: string): boolean {
  for (const r of rule.resources ?? []) {
    if (r === '*') return true;
    if (r === combinedResource) return true;
    if (!subresource) continue;
    // Kubernetes also allows a `*\/subresource` form.
    if (r.length === subresource.length + 2 && r.startsWith('*/') && r.endsWith(subresource)) return true;
  }
  return false;
}

export function resourceNameMatches(rule: PolicyRule, requestedName: string | undefined): boolean {
  if (!rule.resourceNames || rule.resourceNames.length === 0) return true;
  if (requestedName === undefined) {
    // A rule restricted to specific names cannot authorize a request with no name.
    return false;
  }
  return rule.resourceNames.includes(requestedName);
}

export function nonResourceURLMatches(rule: PolicyRule, url: string): boolean {
  for (const u of rule.nonResourceURLs ?? []) {
    if (u === '*') return true;
    if (u === url) return true;
    if (u.endsWith('*') && url.startsWith(u.replace(/\*+$/, ''))) return true;
  }
  return false;
}

export function ruleAllowsRequest(rule: PolicyRule, req: RequestAttrs): boolean {
  if (!verbMatches(rule, req.verb)) return false;
  if (req.nonResourceURL !== undefined) {
    return nonResourceURLMatches(rule, req.nonResourceURL);
  }
  const resource = req.resource ?? '';
  const sub = req.subresource ?? '';
  const combined = sub ? `${resource}/${sub}` : resource;
  return (
    apiGroupMatches(rule, req.apiGroup) &&
    resourceMatches(rule, combined, sub) &&
    resourceNameMatches(rule, req.name)
  );
}

/** A request target restricted to one namespace, used for wildcard expansion. */
export interface WildcardRequest {
  verb: string;
  apiGroup: string;
  resource: string;
  subresource?: string;
}

/**
 * Does `rule` contain a resource entry that is a wildcard (`*`)?
 * Used to build "covered requests" for wildcard rules.
 */
export function ruleHasResourceWildcard(rule: PolicyRule): boolean {
  return (rule.resources ?? []).some((r) => r === '*');
}

export function ruleHasVerbWildcard(rule: PolicyRule): boolean {
  return (rule.verbs ?? []).some((v) => v === '*');
}

export function ruleGrantsNonResource(rule: PolicyRule): boolean {
  return (rule.nonResourceURLs ?? []).length > 0;
}

/**
 * The set of write verbs that mean "can change this object". `deletecollection`
 * is included because it can remove every object of a kind in a namespace.
 */
export const WRITE_VERBS = ['create', 'update', 'patch', 'delete', 'deletecollection'];

/** Any of these verbs means the holder can read an object. */
export const READ_VERBS = ['get', 'list', 'watch'];

export function ruleHasWrite(rule: PolicyRule, verbs: string[] = WRITE_VERBS): boolean {
  return verbs.some((v) => verbMatches(rule, v));
}

export function ruleHasRead(rule: PolicyRule, verbs: string[] = READ_VERBS): boolean {
  return verbs.some((v) => verbMatches(rule, v));
}

/** Human readable form, close to `rbacv1helpers.CompactString`. */
export function compactRule(rule: PolicyRule): string {
  if (rule.nonResourceURLs?.length) {
    return `verbs=[${(rule.verbs ?? []).join(',')}] urls=[${rule.nonResourceURLs.join(',')}]`;
  }
  const parts: string[] = [];
  if (rule.resourceNames?.length) {
    parts.push(`[${rule.resourceNames.join(',')}]`);
  }
  parts.push(`[${(rule.apiGroups ?? []).map((g) => (g === '' ? '""' : g)).join(',')}]`);
  parts.push(`[${(rule.resources ?? []).join(',')}]`);
  parts.push(`[${(rule.verbs ?? []).join(',')}]`);
  return parts.join(' ');
}

/**
 * Does `a` fully cover `b`? Used for the RBAC "you may only grant what you
 * already hold" escalation check (`validation.Covers`). This is an
 * approximation: it compares verb/resource sets rather than enumerating the
 * API surface, which is what the API server does using the same rule lists.
 */
export function ruleCovers(a: PolicyRule, b: PolicyRule): boolean {
  const verbsCovered = (b.verbs ?? []).every((v) => verbMatches(a, v));
  if (!verbsCovered) return false;

  const aGroups = a.apiGroups ?? [];
  const bGroups = b.apiGroups ?? [];
  const groupsCovered = bGroups.every((g) => aGroups.includes('*') || aGroups.includes(g));
  if (!groupsCovered) return false;

  const namesCovered = (b.resourceNames ?? []).every((n) => resourceNameMatches(a, n));
  if (!namesCovered) return false;

  if ((a.resourceNames ?? []).length > 0 && (b.resourceNames ?? []).length === 0) {
    // `a` only covers specific names, `b` needs everything.
    return false;
  }

  const aResources = a.resources ?? [];
  const resourcesCovered = (b.resources ?? []).every((r) =>
    aResources.some((ar) => ar === '*' || ar === r),
  );
  if (!resourcesCovered) return false;

  const aUrls = a.nonResourceURLs ?? [];
  const urlsCovered = (b.nonResourceURLs ?? []).every((u) => aUrls.some((au) => au === '*' || au === u));
  return urlsCovered;
}

/** Do the holder's rules cover every rule in the target role? */
export function rulesCover(held: PolicyRule[], target: PolicyRule[]): boolean {
  return target.every((t) => held.some((h) => ruleCovers(h, t)));
}

export function scopeContains(outer: { kind: 'cluster' } | { kind: 'namespace'; namespace: string }, innerNamespace: string): boolean {
  if (outer.kind === 'cluster') return true;
  return outer.namespace === innerNamespace;
}
