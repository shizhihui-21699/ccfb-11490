import { describe, expect, it } from 'vitest';
import { buildModel } from '../src/model/model';
import { buildGraph, shortestPath, CLUSTER_ADMIN } from '../src/engine/graph';
import { principalId } from '../src/model/types';

/**
 * Regression: the "you may only grant what you already hold" check must compare
 * rules at the *scope of the object being changed*. A wildcard held only inside
 * one namespace must not be treated as covering a ClusterRole, or a genuine
 * `create clusterrolebindings` + `bind clusterroles/*` path is skipped.
 */

function analyze(text: string) {
  const model = buildModel(text, { includeBootstrap: false });
  return { model, ...buildGraph(model) };
}

const NS_AND_SA = `
apiVersion: v1
kind: Namespace
metadata: {name: ci}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: ci}
---
`;

const BINDER = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: binder}
rules:
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterrolebindings"], verbs: ["create"]}
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["bind"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: binder-b}
roleRef: {kind: ClusterRole, name: binder}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: rootrole}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
`;

describe('coverage is scope-aware', () => {
  it('a namespace-wide wildcard does not hide a cluster-wide bind path', () => {
    const { graph } = analyze(
      NS_AND_SA +
        `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: big, namespace: ci}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: big-b, namespace: ci}
roleRef: {kind: Role, name: big}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
` +
        BINDER,
    );
    const app = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' });
    expect(shortestPath(graph, app, CLUSTER_ADMIN)).not.toBeNull();
    const bind = graph.edges.find((e) => e.from === app && e.technique === 'bind-clusterrole');
    expect(bind).toBeDefined();
    expect(bind!.evidence.objects).toContain('clusterrole/rootrole');
  });

  it('holding the same permissions cluster-wide legitimately suppresses the bind edge', () => {
    const { graph } = analyze(
      NS_AND_SA +
        `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: already-root}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: already-root-b}
roleRef: {kind: ClusterRole, name: already-root}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
` +
        BINDER,
    );
    const app = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' });
    // Already cluster-admin, so binding rootrole *cluster-wide* is not an
    // escalation step. (A RoleBinding in `ci` can still bind it namespace-wide;
    // that is a real but strictly weaker action, so it is not suppressed.)
    const clusterWideBind = graph.edges.filter(
      (e) => e.from === app && e.technique === 'bind-clusterrole' && e.to.startsWith('role:cluster:'),
    );
    expect(clusterWideBind).toHaveLength(0);
    expect(shortestPath(graph, app, CLUSTER_ADMIN)!.hops).toHaveLength(1);
  });

  it('cover the target role only when the namespace-scoped binding is in that namespace', () => {
    // RoleBinding to `binder` lives in `other`, so it grants nothing in `ci`;
    // `big` in ci still covers nothing cluster-wide, and the bind edge stays.
    const { graph } = analyze(
      NS_AND_SA +
        `
apiVersion: v1
kind: Namespace
metadata: {name: other}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: big, namespace: ci}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: big-b, namespace: ci}
roleRef: {kind: Role, name: big}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
` +
        BINDER,
    );
    const app = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' });
    expect(shortestPath(graph, app, CLUSTER_ADMIN)).not.toBeNull();
  });
});

describe('cluster-admin grant is absorbing', () => {
  it('does not expand a cluster-admin principal into every other technique', () => {
    const { graph } = analyze(
      NS_AND_SA +
        `
apiVersion: v1
kind: ServiceAccount
metadata: {name: other, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: root}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: root-b}
roleRef: {kind: ClusterRole, name: root}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
    );
    const from = graph.edges.filter((e) => e.from === 'sa:ci/app');
    // The only escalation edge is "you are already admin". The remaining edges
    // are Secret-reachability links that keep the reverse query working.
    expect(from.filter((e) => e.technique === 'already-cluster-admin').map((e) => e.to)).toEqual([CLUSTER_ADMIN]);
    expect(from.filter((e) => e.technique !== 'already-cluster-admin').every((e) => e.to.startsWith('x:secret-read:'))).toBe(true);
    expect(from.some((e) => e.to === 'sa:ci/other')).toBe(false);
  });
});

describe('escalate + create + bind requires unrestricted escalate', () => {
  const GRANTS = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: rbac-admin, namespace: ci}
rules:
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles"], verbs: ["create"]}
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["rolebindings"], verbs: ["create"]}
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles"], verbs: ["bind"]}
`;
  const BINDING = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ra-b, namespace: ci}
roleRef: {kind: Role, name: rbac-admin}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`;

  it('unrestricted escalate lets the principal mint a wildcard role', () => {
    const { graph } = analyze(
      NS_AND_SA +
        GRANTS +
        `
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles"], verbs: ["escalate"]}
` +
        BINDING,
    );
    expect(graph.edges.some((e) => e.from === 'sa:ci/app' && e.technique === 'escalate-create-bind')).toBe(true);
  });

  it('escalate restricted to a resourceName cannot cover a role yet to be created', () => {
    const { graph } = analyze(
      NS_AND_SA +
        GRANTS +
        `
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles"], resourceNames: ["existing"], verbs: ["escalate"]}
` +
        BINDING,
    );
    expect(graph.edges.some((e) => e.from === 'sa:ci/app' && e.technique === 'escalate-create-bind')).toBe(false);
  });
});
