import { describe, expect, it } from 'vitest';
import { buildModel } from '../src/model/model';
import { buildGraph, shortestPath, CLUSTER_ADMIN } from '../src/engine/graph';
import { principalId } from '../src/model/types';

/**
 * `patch` reaches the same storage Update path as `update`, and the RBAC
 * escalate check / roleRef-immutability check apply to both. An analyzer that
 * only looks for `update` misses real paths, which is the common case in
 * GitOps-managed clusters where controllers hold `patch` rather than `update`.
 */

function analyze(text: string) {
  const model = buildModel(text, { includeBootstrap: false });
  return { model, ...buildGraph(model) };
}

const BASE = `
apiVersion: v1
kind: Namespace
metadata: {name: ci}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: ci}
---
`;

const APP = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' });

describe('patch is equivalent to update', () => {
  it('patch + escalate on a held ClusterRole escalates it', () => {
    const { graph } = analyze(
      BASE +
        `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: mine}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: mine-b}
roleRef: {kind: ClusterRole, name: mine}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: editor}
rules:
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], resourceNames: ["mine"], verbs: ["patch", "escalate"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: editor-b}
roleRef: {kind: ClusterRole, name: editor}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
    );
    expect(shortestPath(graph, APP, CLUSTER_ADMIN)!.hops.map((h) => h.edge.technique)).toEqual(['escalate-clusterrole']);
  });

  it('patch on rolebindings lets an existing binding be rewritten', () => {
    const { graph } = analyze(
      BASE +
        `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: granter, namespace: ci}
rules:
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["rolebindings"], verbs: ["patch"]}
  - {apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["bind"], resourceNames: ["admin"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: granter-b, namespace: ci}
roleRef: {kind: Role, name: granter}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
`,
    );
    expect(graph.edges.some((e) => e.from === APP && e.technique === 'bind-clusterrole')).toBe(true);
  });
});
