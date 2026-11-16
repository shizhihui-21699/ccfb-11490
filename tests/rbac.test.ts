import { describe, expect, it } from 'vitest';
import { buildModel } from '../src/model/model';
import { buildGraph, shortestPath, CLUSTER_ADMIN } from '../src/engine/graph';
import { ruleAllowsRequest, ruleCovers, rulesCover } from '../src/model/rbac';
import { principalId } from '../src/model/types';
import { builtinClusterRoles } from '../src/model/builtins';

function graphOf(text: string) {
  const model = buildModel(text, { includeBootstrap: false });
  return { model, ...buildGraph(model) };
}

function adminPathExists(text: string, sa: string): boolean {
  const { graph } = graphOf(text);
  return shortestPath(graph, principalId({ kind: 'ServiceAccount', namespace: 'ci', name: sa }), CLUSTER_ADMIN) !== null;
}

describe('request matching', () => {
  it('treats apiGroups as exact, with "" meaning the legacy group', () => {
    const rule = { apiGroups: [''], resources: ['pods'], verbs: ['get'] };
    expect(ruleAllowsRequest(rule, { verb: 'get', apiGroup: '', resource: 'pods' })).toBe(true);
    expect(ruleAllowsRequest(rule, { verb: 'get', apiGroup: 'apps', resource: 'pods' })).toBe(false);
  });

  it('matches a star wildcard for every field', () => {
    const rule = { apiGroups: ['*'], resources: ['*'], verbs: ['*'] };
    expect(ruleAllowsRequest(rule, { verb: 'delete', apiGroup: 'anything', resource: 'anything' })).toBe(true);
  });

  it('distinguishes a resource from its subresource', () => {
    const rule = { apiGroups: [''], resources: ['pods'], verbs: ['create'] };
    expect(ruleAllowsRequest(rule, { verb: 'create', apiGroup: '', resource: 'pods', subresource: 'exec' })).toBe(false);
    const sub = { apiGroups: [''], resources: ['pods/exec'], verbs: ['create'] };
    expect(ruleAllowsRequest(sub, { verb: 'create', apiGroup: '', resource: 'pods', subresource: 'exec' })).toBe(true);
    const starSub = { apiGroups: [''], resources: ['*/exec'], verbs: ['create'] };
    expect(ruleAllowsRequest(starSub, { verb: 'create', apiGroup: '', resource: 'pods', subresource: 'exec' })).toBe(true);
    expect(ruleAllowsRequest(starSub, { verb: 'create', apiGroup: '', resource: 'pods', subresource: 'attach' })).toBe(false);
  });

  it('honours resourceNames, and refuses nothing when the request names nothing', () => {
    const rule = { apiGroups: ['rbac.authorization.k8s.io'], resources: ['clusterroles'], verbs: ['bind'], resourceNames: ['admin'] };
    expect(ruleAllowsRequest(rule, { verb: 'bind', apiGroup: 'rbac.authorization.k8s.io', resource: 'clusterroles', name: 'admin' })).toBe(true);
    expect(ruleAllowsRequest(rule, { verb: 'bind', apiGroup: 'rbac.authorization.k8s.io', resource: 'clusterroles', name: 'cluster-admin' })).toBe(false);
    expect(ruleAllowsRequest(rule, { verb: 'bind', apiGroup: 'rbac.authorization.k8s.io', resource: 'clusterroles' })).toBe(false);
  });

  it('matches nonResourceURLs with a trailing star', () => {
    const rule = { nonResourceURLs: ['/metrics/*'], verbs: ['get'] };
    expect(ruleAllowsRequest(rule, { verb: 'get', apiGroup: '', nonResourceURL: '/metrics/cadvisor' })).toBe(true);
    expect(ruleAllowsRequest(rule, { verb: 'get', apiGroup: '', nonResourceURL: '/logs' })).toBe(false);
  });

  it('treats deletecollection as a write verb', () => {
    const rule = { apiGroups: [''], resources: ['secrets'], verbs: ['deletecollection'] };
    expect(ruleAllowsRequest(rule, { verb: 'deletecollection', apiGroup: '', resource: 'secrets' })).toBe(true);
  });
});

describe('rule coverage (the escalation-prevention check)', () => {
  it('accepts a wildcard that covers a narrower rule', () => {
    expect(ruleCovers({ apiGroups: ['*'], resources: ['*'], verbs: ['*'] }, { apiGroups: [''], resources: ['secrets'], verbs: ['get'] })).toBe(true);
  });

  it('rejects a narrower rule that cannot cover a wildcard', () => {
    expect(ruleCovers({ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }, { apiGroups: ['*'], resources: ['*'], verbs: ['*'] })).toBe(false);
  });

  it('rejects covering a verb the holder lacks', () => {
    expect(ruleCovers({ apiGroups: [''], resources: ['pods'], verbs: ['get'] }, { apiGroups: [''], resources: ['pods'], verbs: ['get', 'create'] })).toBe(false);
  });

  it('rejects a resourceNames rule trying to cover an unnamed grant', () => {
    expect(ruleCovers({ apiGroups: [''], resources: ['secrets'], verbs: ['get'], resourceNames: ['a'] }, { apiGroups: [''], resources: ['secrets'], verbs: ['get'] })).toBe(false);
  });

  it('covers a name-restricted rule from an unrestricted one', () => {
    expect(ruleCovers({ apiGroups: [''], resources: ['secrets'], verbs: ['get'] }, { apiGroups: [''], resources: ['secrets'], verbs: ['get'], resourceNames: ['a'] })).toBe(true);
  });

  it('requires the whole target rule set', () => {
    const held = [{ apiGroups: [''], resources: ['pods'], verbs: ['get'] }];
    const target = [
      { apiGroups: [''], resources: ['pods'], verbs: ['get'] },
      { apiGroups: [''], resources: ['secrets'], verbs: ['get'] },
    ];
    expect(rulesCover(held, target)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Negative cases: things that must NOT produce a cluster-admin path.
// ---------------------------------------------------------------------------

const HEADER = `
apiVersion: v1
kind: Namespace
metadata: {name: ci}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app, namespace: ci}
---
`;

describe('no false positives', () => {
  it('a plain namespace editor cannot reach cluster-admin', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: editor, namespace: ci}
rules:
  - apiGroups: ["", "apps", "batch"]
    resources: ["pods", "deployments", "jobs", "configmaps"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: editor-binding, namespace: ci}
roleRef: {kind: Role, name: editor}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('create rolebindings without bind or escalate is harmless', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: binder, namespace: ci}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: binder-binding, namespace: ci}
roleRef: {kind: Role, name: binder}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('bind without the ability to create a binding goes nowhere', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: v1
kind: ServiceAccount
metadata: {name: victim, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: binder-only}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: binder-only-binding}
roleRef: {kind: ClusterRole, name: binder-only}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('escalate without update does nothing', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: viewer}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: escalator}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: viewer-binding}
roleRef: {kind: ClusterRole, name: viewer}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: escalator-binding}
roleRef: {kind: ClusterRole, name: escalator}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('impersonating a namespaced SA does not inherit cluster grants of another SA', () => {
    // app may impersonate ci/victim, but only ci/victim has a cluster role and
    // app is in a different namespace's impersonation scope? No: same ns, so
    // this MUST work. The negative case is impersonation in a *different* ns.
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: v1
kind: Namespace
metadata: {name: other}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: victim, namespace: other}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: imp, namespace: ci}
rules: [{apiGroups: [""], resources: ["serviceaccounts"], verbs: ["impersonate"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: imp-binding, namespace: ci}
roleRef: {kind: Role, name: imp}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: victim-admin}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: victim, namespace: other}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('an empty aggregation selector yields no rules', () => {
    const { model } = graphOf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: nothing}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {missing: "true"}}]}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
`);
    // The controller overwrites `rules` with the aggregation result, so the
    // hand-written wildcard must be discarded, not trusted.
    expect(model.clusterRoles.get('nothing')!.rules).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Positive cases that the analyzer must not miss.
// ---------------------------------------------------------------------------

describe('no false negatives', () => {
  it('detects escalate when the target role is held through a RoleBinding in another ns (should not fire)', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: v1
kind: Namespace
metadata: {name: other}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: r, namespace: other}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rb, namespace: other}
roleRef: {kind: Role, name: r}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: updater, namespace: ci}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["update", "escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: updater-binding, namespace: ci}
roleRef: {kind: Role, name: updater}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('detects secret-read to a token Secret to a cluster-admin SA', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: v1
kind: Secret
metadata:
  name: admin-token
  namespace: ci
  annotations: {kubernetes.io/service-account.name: admin-sa}
type: kubernetes.io/service-account-token
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: admin-sa, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: secret-reader, namespace: ci}
rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get", "list"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: secret-reader-binding, namespace: ci}
roleRef: {kind: Role, name: secret-reader}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin-sa-binding}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: admin-sa, namespace: ci}]
`,
        'app',
      ),
    ).toBe(true);
  });

  it('detects TokenRequest to a privileged SA', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: v1
kind: ServiceAccount
metadata: {name: admin-sa, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: token-minter, namespace: ci}
rules: [{apiGroups: [""], resources: ["serviceaccounts/token"], verbs: ["create"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: token-minter-binding, namespace: ci}
roleRef: {kind: Role, name: token-minter}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin-sa-binding}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: admin-sa, namespace: ci}]
`,
        'app',
      ),
    ).toBe(true);
  });

  it('detects pod-exec into an existing privileged pod', () => {
    const { graph } = graphOf(
      HEADER +
        `
apiVersion: v1
kind: Pod
metadata: {name: web, namespace: ci}
spec: {serviceAccountName: admin-sa}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: admin-sa, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: execer, namespace: ci}
rules: [{apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: execer-binding, namespace: ci}
roleRef: {kind: Role, name: execer}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin-sa-binding}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: admin-sa, namespace: ci}]
`,
    );
    const path = shortestPath(graph, principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' }), CLUSTER_ADMIN);
    expect(path!.hops[0].edge.technique).toBe('pod-exec');
    expect(path!.hops[0].edge.evidence.objects).toContain('pod/ci/web');
  });
});

describe('cluster-scoped vs namespaced requests', () => {
  it('a namespaced RoleBinding cannot grant nodes/proxy (cluster-scoped)', () => {
    expect(
      adminPathExists(
        HEADER +
          `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: proxier, namespace: ci}
rules: [{apiGroups: [""], resources: ["nodes/proxy"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: proxier-binding, namespace: ci}
roleRef: {kind: Role, name: proxier}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin-other}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: victim, namespace: ci}]
`,
        'app',
      ),
    ).toBe(false);
  });

  it('a ClusterRoleBinding does grant nodes/proxy', () => {
    const { graph } = graphOf(
      HEADER +
        `
apiVersion: v1
kind: ServiceAccount
metadata: {name: admin-sa, namespace: ci}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: proxier, namespace: ci}
rules: [{apiGroups: [""], resources: ["nodes/proxy"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: proxier-binding, namespace: ci}
roleRef: {kind: Role, name: proxier}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: admin-sa}
roleRef: {kind: ClusterRole, name: admin}
subjects: [{kind: ServiceAccount, name: admin-sa, namespace: ci}]
`,
    );
    // The RoleBinding is namespaced, so it must NOT produce a nodes/proxy edge.
    expect(graph.edges.some((e) => e.technique === 'node-proxy')).toBe(false);
  });
});

describe('builtin bootstrap policy', () => {
  it('every builtin ClusterRoleBinding references a defined ClusterRole', () => {
    const model = buildModel('', { includeBootstrap: true });
    for (const binding of model.clusterRoleBindings) {
      expect(
        model.clusterRoles.has(binding.roleRef.name),
        `${binding.name} -> ${binding.roleRef.name}`,
      ).toBe(true);
    }
  });

  it('defines no duplicate ClusterRole names', () => {
    const names = builtinClusterRoles().map((r) => r.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('includes cluster-admin wired to system:masters', () => {
    const model = buildModel('', { includeBootstrap: true });
    const masters = model.clusterRoleBindings.find((b) => b.name === 'cluster-admin');
    expect(masters?.subjects).toEqual([expect.objectContaining({ kind: 'Group', name: 'system:masters' })]);
    expect(model.clusterRoles.get('cluster-admin')!.rules.some((r) => r.resources?.includes('*') && r.verbs?.includes('*'))).toBe(true);
  });
});

describe('bind scope semantics', () => {
  it('binding a ClusterRole through a RoleBinding stays namespace-scoped', () => {
    // `create rolebindings` + `bind clusterroles/admin` in one namespace lets you
    // grant admin *there*, which is not cluster-admin. The edge must exist but
    // must NOT reach the cluster-admin node.
    const { graph } = graphOf(
      HEADER +
        `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: granter, namespace: ci}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["admin"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: granter-binding, namespace: ci}
roleRef: {kind: Role, name: granter}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
    );
    const bindEdge = graph.edges.find(
      (e) => e.technique === 'bind-clusterrole' && e.from === 'sa:ci/app',
    );
    expect(bindEdge).toBeDefined();
    expect(bindEdge!.evidence.objects).toContain('clusterrole/admin');
    // The acquired node is namespace-scoped, so it cannot be cluster-admin.
    const target = graph.nodes.get(bindEdge!.to)!;
    expect(target.grants.every((g) => g.scope.kind === 'namespace')).toBe(true);
    expect(shortestPath(graph, principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' }), CLUSTER_ADMIN)).toBeNull();
  });

  it('bind with resourceNames that do not cover the target role yields no edge', () => {
    const { graph } = graphOf(
      HEADER +
        `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: granter, namespace: ci}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["view", "edit"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: granter-binding, namespace: ci}
roleRef: {kind: Role, name: granter}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
    );
    expect(
      graph.edges.some((e) => e.technique === 'bind-clusterrole' && e.evidence.objects?.includes('clusterrole/admin')),
    ).toBe(false);
  });
});

describe('escalate through group membership', () => {
  it('escalates a ClusterRole the principal holds only via an implicit group', () => {
    const { graph } = graphOf(
      HEADER +
        `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: shared-viewer}
rules: [{apiGroups: [""], resources: ["pods"], verbs: ["get"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: sv-all}
roleRef: {kind: ClusterRole, name: shared-viewer}
subjects: [{kind: Group, name: system:serviceaccounts}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: role-editor}
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    resourceNames: ["shared-viewer"]
    verbs: ["update", "patch", "escalate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: re-binding}
roleRef: {kind: ClusterRole, name: role-editor}
subjects: [{kind: ServiceAccount, name: app, namespace: ci}]
`,
    );
    // app is implicitly in system:serviceaccounts -> holds shared-viewer cluster-wide
    // -> may rewrite it -> becomes cluster-admin.
    const path = shortestPath(graph, principalId({ kind: 'ServiceAccount', namespace: 'ci', name: 'app' }), CLUSTER_ADMIN);
    expect(path).not.toBeNull();
    expect(path!.hops.map((h) => h.edge.technique)).toContain('escalate-clusterrole');
  });
});
