import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildModel, grantsForPrincipal } from '../src/model/model';
import { buildGraph, enumeratePaths, projectToPrincipals, shortestPath, whoCanReadSecrets, CLUSTER_ADMIN } from '../src/engine/graph';
import { principalId } from '../src/model/types';

const fixture = readFileSync(fileURLToPath(new URL('../fixtures/cluster.yaml', import.meta.url)), 'utf8');

function analyze(text = fixture) {
  const model = buildModel(text, { includeBootstrap: true });
  const { graph } = buildGraph(model);
  return { model, graph };
}

function techniquesOf(path: { hops: Array<{ edge: { technique: string } }> }): string[] {
  return path.hops.map((h) => h.edge.technique);
}

describe('parsing and model', () => {
  it('parses every object kind in the fixture', () => {
    const { model } = analyze();
    expect(model.clusterRoles.size).toBeGreaterThan(10);
    expect(model.namespaces).toEqual(expect.arrayContaining(['ci', 'metrics', 'payments', 'kube-system']));
    expect(model.serviceAccounts).toHaveLength(9);
    expect(model.pods).toHaveLength(3);
    expect(model.secrets).toHaveLength(3);
  });

  it('parses kubectl List wrappers and multi-doc streams', () => {
    const text = `
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Namespace
    metadata: {name: from-list}
  - apiVersion: v1
    kind: Pod
    metadata: {name: p, namespace: from-list}
    spec: {serviceAccountName: custom}
---
apiVersion: v1
kind: Pod
metadata: {name: q, namespace: from-list}
`;
    const model = buildModel(text, { includeBootstrap: false });
    expect(model.namespaces).toContain('from-list');
    expect(model.pods.map((p) => p.name).sort()).toEqual(['p', 'q']);
    // An unset serviceAccountName means the namespace's `default` SA.
    expect(model.pods.find((p) => p.name === 'q')!.serviceAccountName).toBe('default');
  });

  it('expands aggregated ClusterRoles the way the controller does', () => {
    const { model } = analyze();
    const payments = model.clusterRoles.get('payments-operator')!;
    expect(payments.aggregated).toBe(true);
    expect(payments.aggregatedFrom).toEqual(['payments-operator-secrets']);
    expect(payments.rules.some((r) => r.resources?.includes('secrets'))).toBe(true);
    // The aggregated role's manifest has `rules: []` and must stay empty of leaks.
    expect(payments.def.rules).toHaveLength(0);
  });

  it('aggregates the built-in admin role through the label chain', () => {
    const { model } = analyze();
    const admin = model.clusterRoles.get('admin')!;
    // admin <- system:aggregate-to-admin, and edit carries aggregate-to-admin
    // and itself aggregates system:aggregate-to-edit.
    expect(admin.aggregatedFrom).toContain('system:aggregate-to-admin');
    expect(admin.aggregatedFrom).toContain('edit');
    expect(admin.rules.some((r) => r.resources?.includes('rolebindings'))).toBe(true);
  });

  it('does not aggregate a role that merely matches a label used elsewhere', () => {
    const text = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: agg}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {team: blue}}]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: blue, labels: {team: blue}}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: red, labels: {team: red}}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get"]}]
`;
    const model = buildModel(text, { includeBootstrap: false });
    expect(model.clusterRoles.get('agg')!.aggregatedFrom).toEqual(['blue']);
    expect(model.clusterRoles.get('agg')!.rules.some((r) => r.resources?.includes('secrets'))).toBe(false);
  });

  it('warns about dangling role references', () => {
    const model = buildModel(
      `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: broken, namespace: ci}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: nope}
subjects: [{kind: User, name: bob}]
`,
      { includeBootstrap: false },
    );
    expect(model.diagnostics.some((d) => d.message.includes('nope'))).toBe(true);
  });
});

describe('grants', () => {
  it('applies RoleBinding rules only inside their namespace', () => {
    const { model } = analyze();
    const sa = { kind: 'ServiceAccount' as const, namespace: 'ci', name: 'builder' };
    const grants = grantsForPrincipal(model, sa);
    const podGrants = grants.filter((g) => g.rule.resources?.includes('pods'));
    expect(podGrants.length).toBeGreaterThan(0);
    expect(podGrants.every((g) => g.scope.kind === 'namespace' && g.scope.namespace === 'ci')).toBe(true);
  });

  it('applies ClusterRoleBinding rules cluster-wide', () => {
    const { model } = analyze();
    const sa = { kind: 'ServiceAccount' as const, namespace: 'ci', name: 'builder' };
    const grants = grantsForPrincipal(model, sa);
    const noop = grants.filter((g) => g.rule.resources?.includes('certificatesigningrequests'));
    expect(noop).toHaveLength(0);
    const certBot = grantsForPrincipal(model, { kind: 'ServiceAccount', namespace: 'ci', name: 'cert-bot' });
    expect(certBot.some((g) => g.scope.kind === 'cluster' && g.rule.resources?.includes('certificatesigningrequests'))).toBe(true);
  });

  it('defaults a ServiceAccount subject namespace to the binding namespace', () => {
    const text = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: r, namespace: ns1}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: b, namespace: ns1}
roleRef: {kind: Role, name: r}
subjects: [{kind: ServiceAccount, name: app}]
`;
    const model = buildModel(text, { includeBootstrap: false });
    expect(model.roleBindings[0].subjects[0].namespace).toBe('ns1');
  });
});

describe('planted escalation paths', () => {
  it('PATH A: CI builder creates a pod as deployer, who can bind cluster-admin', () => {
    const { graph } = analyze();
    const start = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'builder' });
    // builder can run pods as *any* ci SA, so several one-hop pivots exist.
    // Take the deployer branch explicitly: that is the planted bind path.
    const paths = enumeratePaths(graph, start, CLUSTER_ADMIN, { maxHops: 4, limit: 24 });
    const viaDeployer = paths.find((p) => p.hops.some((h) => h.toNode.id === 'sa:ci/deployer'));
    expect(viaDeployer).toBeDefined();
    expect(techniquesOf(viaDeployer!)).toEqual(['pod-create-sa', 'bind-clusterrole', 'already-cluster-admin']);

    const podHop = viaDeployer!.hops[0];
    expect(podHop.edge.evidence.objects).toContain('serviceaccount/ci/deployer');
    expect(podHop.edge.evidence.source?.roleName).toBe('ci-pod-runner');
    const bindHop = viaDeployer!.hops[1];
    expect(bindHop.edge.evidence.objects).toContain('clusterrole/cluster-admin');
    expect(bindHop.edge.evidence.rule?.verbs).toContain('bind');
  });

  it('PATH A-alt: the shortest builder path is the 2-hop CSR pivot through cert-bot', () => {
    const { graph } = analyze();
    const path = shortestPath(graph, principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'builder' }), CLUSTER_ADMIN);
    // Run a pod as cert-bot, then use its CSR approvals — fewer hops than the
    // bind chain, and easy to miss because the two permissions live in
    // different roles.
    expect(techniquesOf(path!)).toEqual(['pod-create-sa', 'csr-approve']);
    expect(path!.hops[0].edge.evidence.objects).toContain('serviceaccount/ci/cert-bot');
  });

  it('PATH B: metrics SA impersonates prometheus, who escalates its own ClusterRole', () => {
    const { graph } = analyze();
    const start = principalId({ kind: 'ServiceAccount', namespace: 'metrics', name: 'default' });
    const path = shortestPath(graph, start, CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    expect(techniquesOf(path!)).toEqual(['impersonate-serviceaccount', 'escalate-clusterrole']);
    expect(path!.hops[0].edge.evidence.action).toContain('system:serviceaccount:metrics:prometheus');
    expect(path!.hops[1].edge.evidence.objects).toContain('clusterrole/metrics-scraper-cluster');
  });

  it('PATH C: aggregated role hides a Secret read that reaches a break-glass SA', () => {
    const { graph } = analyze();
    const start = principalId({ kind: 'ServiceAccount', namespace: 'payments', name: 'default' });
    const path = shortestPath(graph, start, CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    expect(techniquesOf(path!)).toEqual(['secret-read-sa-token', 'already-cluster-admin']);
    expect(path!.hops[0].edge.evidence.objects).toContain('secret/payments/breakglass-token');
    expect(path!.hops[0].edge.evidence.source?.roleName).toBe('payments-operator');
  });

  it('PATH D: alice impersonates the system:masters group', () => {
    const { graph } = analyze();
    const start = principalId({ kind: 'User', name: 'alice@example.com' });
    const path = shortestPath(graph, start, CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    expect(techniquesOf(path!)).toEqual(['impersonate-group']);
    expect(path!.hops[0].edge.evidence.objects).toContain('group/system:masters');
  });

  it('PATH E: cert-bot forges a CSR', () => {
    const { graph } = analyze();
    const start = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'cert-bot' });
    const path = shortestPath(graph, start, CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    expect(techniquesOf(path!)).toEqual(['csr-approve']);
    expect(path!.hops[0].edge.confidence).toBe('conditional');
  });

  it('reverse query: who can read payments Secrets', () => {
    const { graph } = analyze();
    const readers = whoCanReadSecrets(graph, 'payments');
    const ids = readers.map((r) => r.startId);
    expect(ids).toContain(principalId({ kind: 'ServiceAccount', namespace: 'payments', name: 'default' }));
  });

  it('does not let a namespaced binding address Secrets in another namespace', () => {
    const { graph, model } = analyze();
    // The payments RoleBinding must not leak into kube-system. The only direct
    // readers left are cluster-wide grants from the bootstrap policy.
    const direct = whoCanReadSecrets(graph, 'kube-system', { directOnly: true });
    expect(direct.map((r) => r.startId)).not.toContain(
      principalId({ kind: 'ServiceAccount', namespace: 'payments', name: 'default' }),
    );
    for (const reader of direct) {
      for (const grant of graph.nodes.get(reader.startId)!.grants) {
        if (grant.source.origin === 'builtin') continue;
        expect(grant.scope.kind).toBe('cluster');
      }
    }
    void model;
  });

  it('reports transitive Secret readers separately from direct ones', () => {
    const { graph } = analyze();
    const direct = whoCanReadSecrets(graph, 'payments', { directOnly: true }).map((r) => r.startId);
    // `system:masters` is a bootstrap principal, so include those to prove a
    // user with no Secret RBAC still reaches the read via group impersonation.
    const all = whoCanReadSecrets(graph, 'payments', { includeBootstrapPrincipals: true }).map((r) => r.startId);
    expect(direct).toContain(principalId({ kind: 'ServiceAccount', namespace: 'payments', name: 'default' }));
    expect(direct).not.toContain(principalId({ kind: 'User', name: 'alice@example.com' }));
    expect(all).toContain(principalId({ kind: 'User', name: 'alice@example.com' }));
  });
});

describe('path evidence', () => {
  it('gives every hop a permission, an action and a rule', () => {
    const { graph } = analyze();
    for (const startId of graph.principalIds) {
      const path = shortestPath(graph, startId, CLUSTER_ADMIN);
      if (!path) continue;
      for (const hop of path.hops) {
        expect(hop.edge.evidence.permission.length).toBeGreaterThan(0);
        expect(hop.edge.evidence.action.length).toBeGreaterThan(0);
        // Implicit group membership is granted by the authenticator, not by a
        // PolicyRule, so it is the one hop type with no rule to cite.
        if (hop.edge.technique === 'implicit-group') continue;
        expect(hop.edge.evidence.rule).toBeDefined();
        expect(hop.edge.evidence.source).toBeDefined();
      }
    }
  });

  it('never emits self-loops', () => {
    const { graph } = analyze();
    for (const edge of graph.edges) expect(edge.from).not.toBe(edge.to);
  });
});

describe('principal projection', () => {
  it('drops intermediate role nodes but keeps the reachability', () => {
    const { graph } = analyze();
    const projected = projectToPrincipals(graph);
    expect([...projected.nodes.keys()].some((id) => id.startsWith('role:'))).toBe(false);
    const start = principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'builder' });
    const path = shortestPath(projected, start, CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    // builder -> deployer -> cluster-admin, with the bind step preserved.
    expect(path!.hops.map((h) => h.edge.technique)).toEqual(['pod-create-sa', 'bind-clusterrole']);
  });

  it('collapses the technique chain into a single edge for the tooltip', () => {
    const { graph } = analyze();
    const projected = projectToPrincipals(graph);
    const composed = projected.edges.find(
      (e) => e.from === 'sa:ci/builder' && e.to === 'sa:ci/deployer',
    );
    expect(composed).toBeDefined();
    expect((composed as { chain?: string[] }).chain).toEqual(['pod-create-sa']);
  });
});
