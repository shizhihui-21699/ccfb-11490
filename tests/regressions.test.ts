import { describe, expect, it } from 'vitest';
import { buildModel } from '../src/model/model';
import { buildGraph, projectToPrincipals, shortestPath, CLUSTER_ADMIN } from '../src/engine/graph';

const NS = `
apiVersion: v1
kind: Namespace
metadata: {name: ns1}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: ns1}
---
`;

function analyze(text: string, bootstrap = false) {
  const model = buildModel(text, { includeBootstrap: bootstrap });
  return { model, ...buildGraph(model) };
}

describe('role node identity includes scope', () => {
  it('the same ClusterRole bound cluster-wide and in a namespace are distinct nodes', () => {
    const { graph } = analyze(
      NS +
        `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: shared}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: cb}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["shared"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: rb, namespace: ns1}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["shared"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: cb-b}
roleRef: {kind: ClusterRole, name: cb}
subjects: [{kind: ServiceAccount, name: app, namespace: ns1}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rb-b, namespace: ns1}
roleRef: {kind: Role, name: rb}
subjects: [{kind: ServiceAccount, name: app, namespace: ns1}]
`,
    );
    const targets = graph.edges
      .filter((e) => e.technique === 'bind-clusterrole' && e.from === 'sa:ns1/app')
      .map((e) => e.to);
    expect(new Set(targets).size).toBe(2);
    const scopes = targets.map((id) => graph.nodes.get(id)!.grants[0].scope.kind).sort();
    expect(scopes).toEqual(['cluster', 'namespace']);
  });
});

describe('projection preserves reachability', () => {
  it('every principal that reaches cluster-admin in the full graph reaches it in the projection', () => {
    const { graph } = analyze(
      NS +
        `
apiVersion: v1
kind: ServiceAccount
metadata: {name: victim, namespace: ns1}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: runner, namespace: ns1}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["create"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: runner-b, namespace: ns1}
roleRef: {kind: Role, name: runner}
subjects: [{kind: ServiceAccount, name: app, namespace: ns1}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: top}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: top-b}
roleRef: {kind: ClusterRole, name: top}
subjects: [{kind: ServiceAccount, name: victim, namespace: ns1}]
`,
    );
    const projected = projectToPrincipals(graph);
    const fullReach = graph.principalIds.filter((id) => shortestPath(graph, id, CLUSTER_ADMIN));
    const projReach = new Set(
      projected.principalIds.filter((id) => shortestPath(projected, id, CLUSTER_ADMIN)),
    );
    for (const id of fullReach) {
      if (id === 'sa:ns1/victim') continue; // terminal-ish principals are fine
      expect(projReach.has(id), `${id} lost its path in the projection`).toBe(true);
    }
    expect(projReach.has('sa:ns1/app')).toBe(true);
  });
});

describe('self-read is not an escalation', () => {
  it('a principal cannot reach cluster-admin merely by reading its own Secret', () => {
    const { graph } = analyze(
      NS +
        `
apiVersion: v1
kind: Secret
metadata:
  name: app-token
  namespace: ns1
  annotations: {kubernetes.io/service-account.name: app}
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: ns1}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: reader-b, namespace: ns1}
roleRef: {kind: Role, name: reader}
subjects: [{kind: ServiceAccount, name: app, namespace: ns1}]
`,
    );
    expect(shortestPath(graph, 'sa:ns1/app', CLUSTER_ADMIN)).toBeNull();
    // It must still show up as a Secret reader, though.
    expect(graph.nodes.has('x:secret-read:ns1')).toBe(true);
  });
});

describe('principal discovery', () => {
  it('a user named only by an imported ClusterRoleBinding is a selectable principal', () => {
    const { graph } = analyze(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: imp}
rules: [{apiGroups: [""], resources: ["groups"], verbs: ["impersonate"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: imp-b}
roleRef: {kind: ClusterRole, name: imp}
subjects: [{kind: User, name: alice@example.com}]
`);
    expect(graph.principalIds).toContain('user:alice@example.com');
    expect(graph.nodes.get('user:alice@example.com')!.imported).toBe(true);
  });

  it('bootstrap system users are not offered as cluster principals', () => {
    const { graph } = analyze('', true);
    for (const id of graph.principalIds) {
      expect(id.startsWith('user:system:')).toBe(false);
      expect(id.startsWith('group:')).toBe(false);
    }
  });

  it('a real ServiceAccount holding only bootstrap grants stays selectable', () => {
    const { graph } = analyze(`
apiVersion: v1
kind: Namespace
metadata: {name: quiet}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: quiet, namespace: quiet}
`, true);
    expect(graph.principalIds).toContain('sa:quiet/quiet');
    expect(graph.nodes.get('sa:quiet/quiet')!.builtinOnly).toBe(true);
  });
});

describe('implicit group edges', () => {
  it('draws an explanatory edge when an imported binding names a group the principal is in', () => {
    const { graph } = analyze(
      `
apiVersion: v1
kind: Namespace
metadata: {name: ci}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: group-reader}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: gr-b}
roleRef: {kind: ClusterRole, name: group-reader}
subjects: [{kind: Group, name: system:serviceaccounts}]
`,
    );
    const edge = graph.edges.find(
      (e) => e.from === 'sa:ci/app' && e.technique === 'implicit-group' && e.to === 'group:system:serviceaccounts',
    );
    expect(edge).toBeDefined();
    // The permission is folded into the principal's own grants, not inherited by
    // walking the edge, so the hop must not be needed to see it.
    expect(graph.nodes.get('sa:ci/app')!.held.map((h) => h.name)).toContain('group-reader');
    // And the edge is not traversable, so no zero-cost path is invented.
    expect(shortestPath(graph, 'sa:ci/app', 'group:system:serviceaccounts')).toBeNull();
  });
});
