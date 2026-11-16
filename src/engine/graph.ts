import type {
  ClusterModel,
  Confidence,
  EdgeEvidence,
  GraphEdge,
  GraphNode,
  Grant,
  HeldRole,
  PathHop,
  PathResult,
  PolicyRule,
  Principal,
  Scope,
} from '../model/types';
import { principalId, principalLabel } from '../model/types';
import { grantsForPrincipal } from '../model/model';
import {
  canInNamespace,
  clusterAdminGrant,
  findAllowance,
  isHardcodedSuperuser,
  nodeProxyCapability,
  podCreationCapability,
  podExecCapability,
  secretReadCapability,
  secretWriteCapability,
  tokenRequestCapability,
} from './query';
import { rulesCover } from '../model/rbac';

export interface Graph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  outgoing: Map<string, GraphEdge[]>;
  incoming: Map<string, GraphEdge[]>;
  /** Principal nodes the user can pick as a starting point. */
  principalIds: string[];
  /** Includes principals known only through bootstrap policy bindings. */
  allPrincipalIds: string[];
}

const CLUSTER_ADMIN = 'x:cluster-admin';
const ADMIN_RULE: PolicyRule = { apiGroups: ['*'], resources: ['*'], verbs: ['*'] };

function clusterAdminNode(): GraphNode {
  return {
    id: CLUSTER_ADMIN,
    base: { kind: 'User', name: '（任意高权限身份）' },
    held: [],
    impersonatedGroups: [],
    synthetic: {
      kind: 'cluster-admin',
      techniqueId: 'synthetic',
      note: '等价于 cluster-admin：可对任意资源执行任意操作',
      evidence: {
        permission: '*',
        action: '任意 API 请求',
        rule: ADMIN_RULE,
        objects: ['*'],
        notes: ['该节点是分析器的终点标记，不代表真实存在的对象'],
      },
    },
    grants: [{ rule: ADMIN_RULE, scope: { kind: 'cluster' }, source: syntheticSource('cluster-admin') }],
    builtinOnly: false,
    imported: false,
    label: 'cluster-admin（集群管理员）',
    detail: '分析终点：拥有集群全部权限',
  };
}

function syntheticSource(roleName: string): import('../model/types').GrantSource {
  return {
    bindingKind: 'ClusterRoleBinding',
    bindingName: '（分析器推导）',
    roleKind: 'ClusterRole',
    roleName,
    subjectKind: 'User',
    subjectName: '（推导）',
    origin: 'builtin',
  };
}

function nodeHeldFromGrants(grants: Grant[]): HeldRole[] {
  const out: HeldRole[] = [];
  const seen = new Set<string>();
  for (const g of grants) {
    const key = `${g.source.roleKind}:${g.source.roleNamespace ?? ''}:${g.source.roleName}:${g.scope.kind}:${g.scope.kind === 'namespace' ? g.scope.namespace : ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      kind: g.source.roleKind,
      name: g.source.roleName,
      namespace: g.source.roleNamespace,
      scope: g.scope,
    });
  }
  return out.sort((a, b) => `${a.scope.kind}${a.name}`.localeCompare(`${b.scope.kind}${b.name}`));
}

/** All ServiceAccounts we can prove exist (imported, referenced by pods, or `default`). */
function knownServiceAccounts(model: ClusterModel): Map<string, Set<string>> {
  const byNs = new Map<string, Set<string>>();
  const add = (ns: string, name: string) => {
    let set = byNs.get(ns);
    if (!set) {
      set = new Set();
      byNs.set(ns, set);
    }
    set.add(name);
  };
  for (const sa of model.serviceAccounts) add(sa.namespace, sa.name);
  for (const pod of model.pods) add(pod.namespace, pod.serviceAccountName);
  for (const ns of model.namespaces) add(ns, 'default');
  return byNs;
}

interface TokenSecretInfo {
  namespace: string;
  name: string;
  serviceAccount?: string;
}

function tokenSecrets(model: ClusterModel): TokenSecretInfo[] {
  return model.secrets
    .filter(
      (s) =>
        s.type === 'kubernetes.io/service-account-token' ||
        !!s.serviceAccountName ||
        (s.keys.includes('token') && s.keys.includes('ca.crt')),
    )
    .map((s) => ({ namespace: s.namespace, name: s.name, serviceAccount: s.serviceAccountName }));
}

export interface BuildGraphResult {
  graph: Graph;
  notes: string[];
}

export function buildGraph(model: ClusterModel): BuildGraphResult {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const edgeKeys = new Set<string>();
  const notes: string[] = [];

  // ---------------------------------------------------------------- principals
  const saMap = knownServiceAccounts(model);
  const addPrincipal = (principal: Principal, detail: string, imported: boolean) => {
    const id = principalId(principal);
    if (nodes.has(id)) return;
    const grants = grantsForPrincipal(model, principal);
    nodes.set(id, {
      id,
      base: principal,
      held: nodeHeldFromGrants(grants),
      impersonatedGroups: [],
      builtinOnly: grants.length > 0 && grants.every((g) => g.source.origin === 'builtin'),
      imported,
      grants,
      label: principalLabel(principal),
      detail,
    });
  };

  for (const ns of saMap.keys()) {
    for (const name of saMap.get(ns)!) {
      addPrincipal({ kind: 'ServiceAccount', namespace: ns, name }, `命名空间 ${ns} 中的 ServiceAccount`, true);
    }
  }
  for (const user of model.users) {
    // Users and groups have no API object; they exist here because a binding
    // names them. Only imported bindings make them part of the cluster's own
    // configuration (as opposed to the API server's built-in policy).
    const importedUser = [...model.roleBindings, ...model.clusterRoleBindings].some(
      (b) => b.origin === 'imported' && b.subjects.some((x) => x.kind === 'User' && x.name === user),
    );
    addPrincipal({ kind: 'User', name: user }, '在 RoleBinding/ClusterRoleBinding 中出现的用户', importedUser);
  }
  for (const group of model.groups) {
    const importedGroup = [...model.roleBindings, ...model.clusterRoleBindings].some(
      (b) => b.origin === 'imported' && b.subjects.some((x) => x.kind === 'Group' && x.name === group),
    );
    addPrincipal({ kind: 'Group', name: group }, '在 RoleBinding/ClusterRoleBinding 中出现的组', importedGroup);
  }
  // Node identities: only meaningful when we know pods are scheduled to them.
  const nodeNames = new Set(model.pods.map((p) => p.nodeName).filter((n): n is string => !!n));
  for (const nodeName of nodeNames) {
    addPrincipal({ kind: 'User', name: `system:node:${nodeName}` }, `节点 ${nodeName} 的 kubelet 身份`, true);
  }

  nodes.set(CLUSTER_ADMIN, clusterAdminNode());

  // ------------------------------------------------------------- helper state
  const addEdge = (
    from: string,
    to: string,
    technique: string,
    confidence: Confidence,
    evidence: EdgeEvidence,
  ) => {
    if (!nodes.has(to)) {
      // Target role/synthetic node created lazily by caller.
      return;
    }
    // A principal acting as itself is not an escalation step and would turn the
    // graph into noise (impersonating yourself, running a pod as your own SA).
    if (from === to) return;
    const key = `${from}->${to}:${technique}:${evidence.objects?.join(',') ?? ''}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ from, to, technique, confidence, evidence });
  };

  const ensureRoleNode = (
    kind: 'ClusterRole' | 'Role',
    name: string,
    scope: Scope,
    technique: string,
    evidence: EdgeEvidence,
  ): string => {
    // The scope is part of the identity: a ClusterRole bound cluster-wide and
    // the same ClusterRole bound into one namespace grant different things, and
    // collapsing them into one node would (wrongly) make the namespaced grant
    // look cluster-wide.
    const id =
      scope.kind === 'cluster'
        ? `role:cluster:${name}`
        : `role:ns:${scope.namespace}:${kind}:${name}`;
    if (!nodes.has(id)) {
      let rules: PolicyRule[] = [];
      if (kind === 'ClusterRole') {
        rules = model.clusterRoles.get(name)?.rules ?? [];
      } else if (scope.kind === 'namespace') {
        rules = model.roles.get(scope.namespace)?.get(name)?.rules ?? [];
      }
      const grants: Grant[] = rules.map((rule) => ({
        rule,
        scope,
        source: {
          bindingKind: 'ClusterRoleBinding',
          bindingName: '（分析器推导）',
          roleKind: kind,
          roleName: name,
          roleNamespace: scope.kind === 'namespace' ? scope.namespace : undefined,
          subjectKind: 'User',
          subjectName: '（推导）',
          origin: 'imported',
        },
        viaTechnique: technique,
      }));
      nodes.set(id, {
        id,
        base: { kind: 'User', name: `（已获得 ${kind} ${name}）` },
        held: [{ kind, name, namespace: scope.kind === 'namespace' ? scope.namespace : undefined, scope }],
        impersonatedGroups: [],
        grants,
        builtinOnly: false,
        imported: false,
        label:
          kind === 'ClusterRole'
            ? `已获得 ClusterRole ${name}`
            : `已获得 Role ${scope.kind === 'namespace' ? scope.namespace + '/' : ''}${name}`,
        detail: `通过 ${technique} 获得的角色权限（作用域：${scope.kind === 'cluster' ? '集群' : scope.namespace}）`,
        derived: {
          techniqueId: technique,
          description: evidence.action,
          addedGrants: rules.length,
        },
      });
    }
    return id;
  };

  const ensureNsWildcardNode = (namespace: string, technique: string, evidence: EdgeEvidence): string => {
    const id = `x:ns-wildcard:${namespace}`;
    if (!nodes.has(id)) {
      const rule: PolicyRule = { apiGroups: ['*'], resources: ['*'], verbs: ['*'] };
      nodes.set(id, {
        id,
        base: { kind: 'User', name: `（命名空间 ${namespace} 的 * 权限）` },
        held: [],
        impersonatedGroups: [],
        synthetic: {
          kind: 'namespace-wildcard',
          namespace,
          techniqueId: technique,
          note: `在命名空间 ${namespace} 内拥有全部权限，但无法直接操作集群级资源`,
          evidence,
        },
        grants: [{ rule, scope: { kind: 'namespace', namespace }, source: syntheticSource('（推导）') }],
        builtinOnly: false,
        imported: false,
        label: `命名空间 ${namespace} 完全控制`,
        detail: '命名空间内通配权限；从集群管理员视角看仍是未完成的一步',
      });
    }
    return id;
  };

  const ensureSecretReadNode = (namespace: string): string => {
    const id = `x:secret-read:${namespace}`;
    if (!nodes.has(id)) {
      const rule: PolicyRule = { apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list', 'watch'] };
      nodes.set(id, {
        id,
        base: { kind: 'User', name: `（可读取 ${namespace} 的 Secret）` },
        held: [],
        impersonatedGroups: [],
        synthetic: {
          kind: 'read-all-secrets',
          namespace,
          techniqueId: 'secret-read-sa-token',
          note: `可读取命名空间 ${namespace} 中所有 Secret`,
          evidence: {
            permission: 'get/list/watch secrets',
            action: `kubectl get secrets -n ${namespace}`,
            objects: [`namespace/${namespace}`],
          },
        },
        grants: [{ rule, scope: { kind: 'namespace', namespace }, source: syntheticSource('（推导）') }],
        builtinOnly: false,
        imported: false,
        label: `可读 ${namespace} 的 Secret`,
        detail: 'Secret 读取能力节点（用于反查）',
      });
    }
    return id;
  };

  const saNodeId = (ns: string, name: string) => principalId({ kind: 'ServiceAccount', namespace: ns, name });

  const ensureSaNode = (namespace: string, name: string) => {
    if (!nodes.has(saNodeId(namespace, name))) {
      addPrincipal({ kind: 'ServiceAccount', namespace, name }, `命名空间 ${namespace} 中的 ServiceAccount`, true);
    }
    return saNodeId(namespace, name);
  };

  const allRoles = [...model.clusterRoles.values()];

  // ------------------------------------------------------------- edge generation
  // Iterate over a snapshot of principal nodes; edges can create role/synthetic
  // nodes which are processed in a later pass. Processing is repeated until no
  // new nodes appear, because a role node's grants can unlock further steps.
  const processed = new Set<string>();
  for (let guard = 0; guard < 12; guard++) {
    const pending = [...nodes.keys()].filter((id) => !processed.has(id));
    if (pending.length === 0) break;
    for (const id of pending) {
      processed.add(id);
      const node = nodes.get(id)!;
      generateEdges(node);
    }
  }

  function generateEdges(node: GraphNode): void {
    const grants = node.grants;
    if (grants.length === 0 && !node.synthetic) return;

    // The terminal node is absorbing. Everything a cluster-admin can do is
    // already implied, so expanding it would add an outgoing edge for every
    // principal in the cluster and bury the real signal. The capabilities we
    // still need downstream (Secret reachability) are attached explicitly.
    if (node.id === CLUSTER_ADMIN) {
      for (const ns of model.namespaces) {
        addEdge(node.id, ensureSecretReadNode(ns), 'already-cluster-admin', 'certain', {
          permission: '*',
          action: `kubectl get secrets -n ${ns}`,
          rule: ADMIN_RULE,
          objects: [`namespace/${ns}`],
          notes: ['cluster-admin 隐含对全部命名空间 Secret 的读取能力'],
        });
      }
      return;
    }

    // 1. Hard-coded superuser group.
    const hardcoded = isHardcodedSuperuser(node.base);
    if (hardcoded) {
      addEdge(node.id, CLUSTER_ADMIN, 'hardcoded-masters', 'certain', {
        permission: '（无需 RBAC 权限）',
        action: '以 system:masters 组成员身份直接访问 API Server',
        objects: ['group/system:masters'],
        notes: [
          'API Server 内置 privilegedGroupAuthorizer 直接放行 system:masters，不查 RBAC',
          '对应 bootstrap ClusterRoleBinding cluster-admin → group system:masters',
        ],
      });
    }

    // 2. Cluster-admin already held. Also absorbing: holding `*` on `*` makes
    //    every other technique a strictly longer way to the same place.
    const directAdmin = clusterAdminGrant(grants);
    if (directAdmin) {
      if (!hardcoded) {
        addEdge(node.id, CLUSTER_ADMIN, 'already-cluster-admin', 'certain', {
          permission: '*',
          action: '直接调用任意 API',
          rule: directAdmin.rule,
          source: directAdmin.source,
          objects: ['*'],
        });
      }
      return;
    }

    // 3. Impersonation ------------------------------------------------------
    // The real impersonation request carries the target SA's namespace, so a
    // RoleBinding in that namespace is sufficient.
    for (const [ns, sas] of saMap) {
      const hit = findAllowance(grants, { verb: 'impersonate', apiGroup: '', resource: 'serviceaccounts', namespace: ns });
      if (!hit) continue;
      for (const saName of sas) {
        const restricted = (hit.rule.resourceNames ?? []).length > 0;
        if (restricted && !(hit.rule.resourceNames ?? []).includes(saName)) continue;
        addEdge(node.id, ensureSaNode(ns, saName), 'impersonate-serviceaccount', restricted ? 'conditional' : 'certain', {
          permission: `impersonate serviceaccounts${restricted ? ` (resourceNames: ${(hit.rule.resourceNames ?? []).join(',')})` : ''} in ${ns}`,
          action: `kubectl auth whoami --as=system:serviceaccount:${ns}:${saName}`,
          rule: hit.rule,
          source: hit.source,
          objects: [`serviceaccount/${ns}/${saName}`],
          notes: ['impersonate 请求按被冒充对象所在命名空间判定作用域'],
        });
      }
    }

    const groupHit = findAllowance(grants, { verb: 'impersonate', apiGroup: '', resource: 'groups' });
    if (groupHit) {
      const restricted = (groupHit.rule.resourceNames ?? []).length > 0;
      const names = groupHit.rule.resourceNames ?? [];
      const targets = restricted ? names : [...model.groups, 'system:masters'];
      for (const group of new Set(targets)) {
        if (group === 'system:masters') {
          addEdge(node.id, CLUSTER_ADMIN, 'impersonate-group', restricted ? 'conditional' : 'certain', {
            permission: `impersonate groups${restricted ? ` (resourceNames: ${names.join(',')})` : ''}`,
            action: 'kubectl --as-group=system:masters auth whoami',
            rule: groupHit.rule,
            source: groupHit.source,
            objects: ['group/system:masters'],
            notes: ['system:masters 被 API Server 内置作者器直接放行，冒充它即等于 cluster-admin'],
          });
          continue;
        }
        const gid = principalId({ kind: 'Group', name: group });
        if (nodes.has(gid)) {
          addEdge(node.id, gid, 'impersonate-group', restricted ? 'conditional' : 'certain', {
            permission: `impersonate groups${restricted ? ` (resourceNames: ${names.join(',')})` : ''}`,
            action: `kubectl --as-group=${group} auth whoami`,
            rule: groupHit.rule,
            source: groupHit.source,
            objects: [`group/${group}`],
          });
        }
      }
    }

    const userHit = findAllowance(grants, { verb: 'impersonate', apiGroup: '', resource: 'users' });
    if (userHit) {
      const restricted = (userHit.rule.resourceNames ?? []).length > 0;
      const names = userHit.rule.resourceNames ?? [];
      const candidates = restricted ? names : [...model.users];
      for (const user of candidates) {
        const uid = principalId({ kind: 'User', name: user });
        if (!nodes.has(uid)) continue;
        addEdge(node.id, uid, 'impersonate-user', 'certain', {
          permission: `impersonate users${restricted ? ` (resourceNames: ${names.join(',')})` : ''}`,
          action: `kubectl --as=${user} auth whoami`,
          rule: userHit.rule,
          source: userHit.source,
          objects: [`user/${user}`],
        });
      }
      // A node identity is a User too; impersonating it reaches the kubelet's
      // Secret access. Nodes are covered because they exist as User principals.
    }

    // 4. Implicit group membership -----------------------------------------
    // These edges exist for *explanation*: they show why a group's bindings
    // apply to this principal. The grants themselves are already folded into
    // `node.grants` (see implicitGroups), so the edge carries no NEW capability
    // and must not be traversed as an escalation step — otherwise every path
    // through a group would be counted twice.
    const isPrincipal = !node.synthetic && !node.derived;
    if (isPrincipal && (node.base.kind === 'ServiceAccount' || node.base.kind === 'User')) {
      const memberOf = node.base.kind === 'ServiceAccount'
        ? ['system:serviceaccounts', `system:serviceaccounts:${node.base.namespace}`, 'system:authenticated']
        : ['system:authenticated'];
      for (const g of memberOf) {
        const gid = principalId({ kind: 'Group', name: g });
        const groupNode = nodes.get(gid);
        if (!groupNode) continue;
        // Only draw it when the group actually carries something; a purely
        // cosmetic edge is noise.
        if (groupNode.grants.length === 0 && !isHardcodedSuperuser(groupNode.base)) continue;
        addEdge(node.id, gid, 'implicit-group', 'certain', {
          permission: '（认证层自动赋予，无需 RBAC）',
          action: `以 ${g} 组成员身份发起请求`,
          objects: [`group/${g}`],
          notes: [
            '该组成员关系由认证层固定赋予，不可被 RBAC 撤销',
            '其权限已经计入本主体，此边仅用于解释来源，遍历时会跳过',
          ],
        });
      }
    } else if (isPrincipal && node.base.kind === 'Group' && isHardcodedSuperuser(node.base)) {
      // handled by the hardcoded-superuser branch above
    }

    // 5. bind / escalate / create-role --------------------------------------
    generateRbacWriteEdges(node);

    // 6. Workload-based identity acquisition --------------------------------
    generateWorkloadEdges(node);

    // 7. Credential acquisition --------------------------------------------
    generateCredentialEdges(node);

    // 8. CSR --------------------------------------------------------------
    generateCsrEdges(node);

    // 9. Webhook injection -------------------------------------------------
    const webhookHit =
      canInNamespace(grants, 'create', 'admissionregistration.k8s.io', 'mutatingwebhookconfigurations', '') ??
      canInNamespace(grants, 'patch', 'admissionregistration.k8s.io', 'mutatingwebhookconfigurations', '') ??
      canInNamespace(grants, 'update', 'admissionregistration.k8s.io', 'mutatingwebhookconfigurations', '');
    if (webhookHit) {
      for (const [ns, sas] of saMap) {
        for (const saName of sas) {
          addEdge(node.id, ensureSaNode(ns, saName), 'webhook-inject', 'conditional', {
            permission: 'create/patch mutatingwebhookconfigurations',
            action: '注册一个 sidecar 注入 webhook，在目标 Pod 启动时注入容器',
            rule: webhookHit.rule,
            source: webhookHit.source,
            objects: [`serviceaccount/${ns}/${saName}`],
            notes: [
              '需要 webhook 后端可从 API Server 访问',
              '注入发生在 Pod 准入阶段，因此只能影响新创建的 Pod',
            ],
          });
        }
      }
    }

    // 10. Node proxy → kubelet exec ----------------------------------------
    const proxyHit = nodeProxyCapability(grants);
    if (proxyHit) {
      for (const [ns, sas] of saMap) {
        for (const saName of sas) {
          addEdge(node.id, ensureSaNode(ns, saName), 'node-proxy', 'conditional', {
            permission: 'get nodes/proxy',
            action: 'kubectl get --raw "/api/v1/nodes/<node>/proxy/run/..." 或在容器内 exec',
            rule: proxyHit.rule,
            source: proxyHit.source,
            objects: [`serviceaccount/${ns}/${saName}`],
            notes: ['需要 kubelet 允许经 API Server 转发 exec 请求', 'node-proxy 是集群级子资源，RoleBinding 无法授予'],
          });
        }
      }
    }
  }

  function generateRbacWriteEdges(node: GraphNode): void {
    const grants = node.grants;

    /**
     * The API server's no-escalation check compares against rules held *at the
     * same scope as the object being modified*. A wildcard held only inside one
     * namespace does not cover a ClusterRole, so coverage must be computed per
     * target scope or a real `bind clusterroles` path gets skipped.
     */
    const coversAt = (rules: PolicyRule[], clusterWide: boolean): boolean =>
      rulesCover(
        grants
          .filter((g) => (clusterWide ? g.scope.kind === 'cluster' : g.scope.kind === 'namespace'))
          .map((g) => g.rule),
        rules,
      );

    // --- bind: create clusterrolebindings + bind clusterroles/<role> -----
    // `create` a new binding, or `patch`/`update` an existing one's subjects —
    // the API server only forbids changing `roleRef`, not the subject list.
    const createCrb =
      canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'clusterrolebindings', '') ??
      canInNamespace(grants, 'patch', 'rbac.authorization.k8s.io', 'clusterrolebindings', '') ??
      canInNamespace(grants, 'update', 'rbac.authorization.k8s.io', 'clusterrolebindings', '');
    if (createCrb) {
      for (const role of allRoles) {
        const bindHit = findAllowance(grants, {
          verb: 'bind',
          apiGroup: 'rbac.authorization.k8s.io',
          resource: 'clusterroles',
          name: role.def.name,
        });
        if (!bindHit) continue;
        if (coversAt(role.rules, true)) continue; // holder already has all of it cluster-wide
        const target = ensureRoleNode('ClusterRole', role.def.name, { kind: 'cluster' }, 'bind-clusterrole', {
          permission: `create clusterrolebindings + bind clusterroles/${role.def.name}`,
          action: `kubectl create clusterrolebinding pwn --clusterrole=${role.def.name} --user=<me>`,
          rule: bindHit.rule,
          source: bindHit.source,
          objects: [`clusterrole/${role.def.name}`],
        });
        addEdge(node.id, target, 'bind-clusterrole', 'certain', {
          permission: `create clusterrolebindings + bind clusterroles/${role.def.name}`,
          action: `kubectl create clusterrolebinding pwn --clusterrole=${role.def.name} --user=<me>`,
          rule: bindHit.rule,
          source: bindHit.source,
          objects: [`clusterrole/${role.def.name}`],
          notes: [
            `目标角色含 ${role.rules.length} 条规则（${role.aggregatedFrom.length ? '含聚合: ' + role.aggregatedFrom.join(',') : '无聚合'}）`,
            'API Server 只校验 bind 或“已持有全部权限”，不校验目的主体',
          ],
        });
      }
    }

    // --- bind: create rolebindings + bind roles|clusterroles in namespace ---
    for (const ns of model.namespaces) {
      const createRb =
        canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'rolebindings', ns) ??
        canInNamespace(grants, 'patch', 'rbac.authorization.k8s.io', 'rolebindings', ns) ??
        canInNamespace(grants, 'update', 'rbac.authorization.k8s.io', 'rolebindings', ns);
      if (!createRb) continue;

      // ClusterRole bound into a namespace.
      for (const role of allRoles) {
        const bindHit = findAllowance(grants, {
          verb: 'bind',
          apiGroup: 'rbac.authorization.k8s.io',
          resource: 'clusterroles',
          namespace: ns,
          name: role.def.name,
        });
        if (!bindHit) continue;
        // RoleBinding to a ClusterRole grants only within ns, so same-namespace
        // coverage is the relevant comparison.
        if (coversAt(role.rules, false)) continue;
        const target = ensureRoleNode('ClusterRole', role.def.name, { kind: 'namespace', namespace: ns }, 'bind-clusterrole', {
          permission: `create rolebindings in ${ns} + bind clusterroles/${role.def.name}`,
          action: `kubectl create rolebinding pwn -n ${ns} --clusterrole=${role.def.name} --user=<me>`,
          rule: bindHit.rule,
          source: bindHit.source,
          objects: [`clusterrole/${role.def.name}`, `namespace/${ns}`],
        });
        addEdge(node.id, target, 'bind-clusterrole', 'certain', {
          permission: `create rolebindings in ${ns} + bind clusterroles/${role.def.name}`,
          action: `kubectl create rolebinding pwn -n ${ns} --clusterrole=${role.def.name} --user=<me>`,
          rule: bindHit.rule,
          source: bindHit.source,
          objects: [`clusterrole/${role.def.name}`, `namespace/${ns}`],
          notes: ['RoleBinding 引用 ClusterRole 时，规则只在该命名空间生效'],
        });
      }

      // Namespaced Roles.
      const nsRoles = model.roles.get(ns);
      if (nsRoles) {
        for (const role of nsRoles.values()) {
          const bindHit = findAllowance(grants, {
            verb: 'bind',
            apiGroup: 'rbac.authorization.k8s.io',
            resource: 'roles',
            namespace: ns,
            name: role.name,
          });
          if (!bindHit) continue;
          if (coversAt(role.rules, false)) continue;
          const target = ensureRoleNode('Role', role.name, { kind: 'namespace', namespace: ns }, 'bind-role', {
            permission: `create rolebindings in ${ns} + bind roles/${role.name}`,
            action: `kubectl create rolebinding pwn -n ${ns} --role=${role.name} --user=<me>`,
            rule: bindHit.rule,
            source: bindHit.source,
            objects: [`role/${ns}/${role.name}`],
          });
          addEdge(node.id, target, 'bind-role', 'certain', {
            permission: `create rolebindings in ${ns} + bind roles/${role.name}`,
            action: `kubectl create rolebinding pwn -n ${ns} --role=${role.name} --user=<me>`,
            rule: bindHit.rule,
            source: bindHit.source,
            objects: [`role/${ns}/${role.name}`],
          });
        }
      }
    }

    // --- escalate an already-bound ClusterRole ---------------------------
    const boundClusterRoleNames = new Set<string>();
    for (const g of grants) {
      if (g.scope.kind === 'cluster' && g.source.roleKind === 'ClusterRole') boundClusterRoleNames.add(g.source.roleName);
    }
    for (const roleName of boundClusterRoleNames) {
      // `patch` reaches the same storage Update path as `update`, and both are
      // gated by the escalate check, so either verb is enough.
      const updateHit =
        findAllowance(grants, { verb: 'update', apiGroup: 'rbac.authorization.k8s.io', resource: 'clusterroles', name: roleName }) ??
        findAllowance(grants, { verb: 'patch', apiGroup: 'rbac.authorization.k8s.io', resource: 'clusterroles', name: roleName });
      if (!updateHit) continue;
      const escalateHit = findAllowance(grants, {
        verb: 'escalate',
        apiGroup: 'rbac.authorization.k8s.io',
        resource: 'clusterroles',
        name: roleName,
      });
      if (!escalateHit) continue;
      addEdge(node.id, CLUSTER_ADMIN, 'escalate-clusterrole', 'certain', {
        permission: `update clusterroles/${roleName} + escalate clusterroles/${roleName}`,
        action: `kubectl patch clusterrole ${roleName} --type=json -p '[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`,
        rule: escalateHit.rule,
        source: escalateHit.source,
        objects: [`clusterrole/${roleName}`],
        notes: [
          `该角色已经通过现有绑定授予本主体权限，因此把 * 写进去即可立即生效`,
          'escalate 关闭了“只能授予自己已拥有的权限”校验',
        ],
      });
    }

    // --- escalate an already-bound Role ----------------------------------
    for (const ns of model.namespaces) {
      const boundRoleNames = new Set<string>();
      for (const g of grants) {
        if (g.scope.kind === 'namespace' && g.scope.namespace === ns && g.source.roleKind === 'Role') {
          boundRoleNames.add(g.source.roleName);
        }
      }
      for (const roleName of boundRoleNames) {
        const updateHit =
          canInNamespace(grants, 'update', 'rbac.authorization.k8s.io', 'roles', ns, roleName) ??
          canInNamespace(grants, 'patch', 'rbac.authorization.k8s.io', 'roles', ns, roleName);
        if (!updateHit) continue;
        const escalateHit = canInNamespace(grants, 'escalate', 'rbac.authorization.k8s.io', 'roles', ns, roleName);
        if (!escalateHit) continue;
        const target = ensureNsWildcardNode(ns, 'escalate-role', {
          permission: `update roles/${roleName} + escalate roles/${roleName}`,
          action: `kubectl patch role ${roleName} -n ${ns} ... schema.*`,
          rule: escalateHit.rule,
          source: escalateHit.source,
          objects: [`role/${ns}/${roleName}`],
        });
        addEdge(node.id, target, 'escalate-role', 'certain', {
          permission: `update roles/${roleName} + escalate roles/${roleName} in ${ns}`,
          action: `kubectl patch role ${roleName} -n ${ns} --type=json -p '[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'`,
          rule: escalateHit.rule,
          source: escalateHit.source,
          objects: [`role/${ns}/${roleName}`],
        });
      }
    }

    // --- escalate + create role + bind it (namespace) --------------------
    for (const ns of model.namespaces) {
      const createRole = canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'roles', ns);
      const escalateAny = canInNamespace(grants, 'escalate', 'rbac.authorization.k8s.io', 'roles', ns, 'attacker-created');
      const createRb =
        canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'rolebindings', ns) ??
        canInNamespace(grants, 'patch', 'rbac.authorization.k8s.io', 'rolebindings', ns) ??
        canInNamespace(grants, 'update', 'rbac.authorization.k8s.io', 'rolebindings', ns);
      const bindAny = findAllowance(grants, {
        verb: 'bind',
        apiGroup: 'rbac.authorization.k8s.io',
        resource: 'roles',
        namespace: ns,
        // No name: a rule restricted by resourceNames cannot cover a role the
        // attacker is about to create, so this only matches unrestricted rules.
      });
      if (!(createRole && escalateAny && createRb && bindAny)) continue;
      // `escalate` with resourceNames cannot cover a freshly-created role name.
      if ((escalateAny.rule.resourceNames ?? []).length > 0) continue;
      const evidence: EdgeEvidence = {
        permission: `create roles + escalate roles + create rolebindings + bind roles/* in ${ns}`,
        action: `kubectl create role pwn -n ${ns} --verb='*' --resource='*' && kubectl create rolebinding pwn -n ${ns} --role=pwn --user=<me>`,
        rule: escalateAny.rule,
        source: escalateAny.source,
        objects: [`namespace/${ns}`],
        notes: ['四个动词可能来自不同角色；按角色逐个审计会漏掉这种组合'],
      };
      addEdge(node.id, ensureNsWildcardNode(ns, 'escalate-create-bind', evidence), 'escalate-create-bind', 'certain', evidence);
    }

    // --- escalate + create ClusterRole + bind it (cluster) ---------------
    const canCreateClusterRole = canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'clusterroles', '');
    const escalateClusterAny = canInNamespace(grants, 'escalate', 'rbac.authorization.k8s.io', 'clusterroles', '', 'attacker-created');
    const canCreateCrb = canInNamespace(grants, 'create', 'rbac.authorization.k8s.io', 'clusterrolebindings', '');
    const bindClusterAny = findAllowance(grants, {
      verb: 'bind',
      apiGroup: 'rbac.authorization.k8s.io',
      resource: 'clusterroles',
    });
    if (
      canCreateClusterRole &&
      escalateClusterAny &&
      canCreateCrb &&
      bindClusterAny &&
      (escalateClusterAny.rule.resourceNames ?? []).length === 0
    ) {
      const evidence: EdgeEvidence = {
        permission: 'create clusterroles + escalate clusterroles + create clusterrolebindings + bind clusterroles/*',
        action: `kubectl create clusterrole pwn --verb='*' --resource='*' && kubectl create clusterrolebinding pwn --clusterrole=pwn --user=<me>`,
        rule: escalateClusterAny.rule,
        source: escalateClusterAny.source,
        objects: ['clusterrole/pwn', 'clusterrolebinding/pwn'],
      };
      addEdge(node.id, CLUSTER_ADMIN, 'escalate-create-bind', 'certain', evidence);
    }
  }

  function generateWorkloadEdges(node: GraphNode): void {
    const grants = node.grants;

    for (const [ns, sas] of saMap) {
      const podHit = podCreationCapability(grants, ns);
      if (podHit) {
        for (const saName of sas) {
          addEdge(node.id, ensureSaNode(ns, saName), 'pod-create-sa', 'certain', {
            permission: `create pods (${podHit.source.roleKind} ${podHit.source.roleName}) in ${ns}`,
            action: `kubectl run pwn -n ${ns} --image=alpine --restart=Never --overrides='{"spec":{"serviceAccountName":"${saName}"}}' -- sleep 3600`,
            rule: podHit.rule,
            source: podHit.source,
            objects: [`serviceaccount/${ns}/${saName}`, `namespace/${ns}`],
            notes: [
              'Pod 的 serviceAccountName 由创建者指定，API Server 不校验“SA 使用权”',
              `目标 SA 需已存在；${saName === 'default' ? 'default SA 必然存在' : '已在导入数据中出现'}`,
            ],
          });
        }
      }

      const execHit = podExecCapability(grants, ns);
      if (execHit) {
        const podsInNs = model.pods.filter((p) => p.namespace === ns);
        for (const pod of podsInNs) {
          addEdge(node.id, ensureSaNode(ns, pod.serviceAccountName), 'pod-exec', 'certain', {
            permission: `${execHit.result.source.roleKind} ${execHit.result.source.roleName} → ${execHit.via} in ${ns}`,
            action: `kubectl exec -n ${ns} ${pod.name} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
            rule: execHit.result.rule,
            source: execHit.result.source,
            objects: [`pod/${ns}/${pod.name}`, `serviceaccount/${ns}/${pod.serviceAccountName}`],
            notes: ['进入正在运行的 Pod 即可读取其投射的 SA token'],
          });
        }
        // patch/update pods reaches any pod, including ones not in the dump.
        if (!podsInNs.length) {
          notes.push(`节点 ${node.label} 可在 ${ns} 中修改 Pod，但导入数据里该命名空间没有 Pod，无法枚举目标`);
        }
      }

      // Kubelet-style: a node identity can read Secret for pods on it.
      if (!node.synthetic && !node.derived && node.base.kind === 'User' && node.base.name.startsWith('system:node:')) {
        const nodeName = node.base.name.slice('system:node:'.length);
        for (const pod of model.pods.filter((p) => p.namespace === ns && p.nodeName === nodeName)) {
          addEdge(node.id, ensureSaNode(ns, pod.serviceAccountName), 'secret-read-sa-token', 'conditional', {
            permission: `Node authorizer: get secrets referenced by pods on ${nodeName}`,
            action: `读取节点 ${nodeName} 上 Pod 所引用的 Secret`,
            // This is a Node-authorizer decision, not a PolicyRule the ClusterRole
            // lists; citing the ClusterRole rule verbatim is the closest that can
            // be shown, and the note explains the actual check.
            rule: { apiGroups: [''], resources: ['secrets'], verbs: ['get', 'list', 'watch'] },
            source: {
              bindingKind: 'ClusterRoleBinding',
              bindingName: 'system:node（默认绑定，被 Node authorizer 收紧）',
              roleKind: 'ClusterRole',
              roleName: 'system:node',
              subjectKind: 'User',
              subjectName: node.base.name,
              origin: 'builtin',
            },
            objects: [`pod/${ns}/${pod.name}`, `serviceaccount/${ns}/${pod.serviceAccountName}`],
            notes: [
              'system:node 角色本身就有 secrets 的读权限，但运行期由 Node authorizer 收紧到“本节点 Pod 引用”',
              '因此这条边是否成立取决于调度：目标 Pod 必须真的在该节点上',
            ],
          });
        }
      }
    }
  }

  function generateCredentialEdges(node: GraphNode): void {
    const grants = node.grants;
    const tokens = tokenSecrets(model);

    for (const ns of model.namespaces) {
      const readCap = secretReadCapability(
        grants.filter((g) => g.scope.kind === 'cluster' || g.scope.namespace === ns),
        [ns],
      );
      if (readCap) {
        const hit = findAllowance(grants, { verb: 'list', apiGroup: '', resource: 'secrets', namespace: ns }) ??
          findAllowance(grants, { verb: 'get', apiGroup: '', resource: 'secrets', namespace: ns }) ??
          findAllowance(grants, { verb: 'watch', apiGroup: '', resource: 'secrets', namespace: ns });
        const evidence: EdgeEvidence = {
          permission: `get/list/watch secrets in ${ns}`,
          action: `kubectl get secrets -n ${ns} -o yaml`,
          rule: hit?.rule,
          source: hit?.source,
          objects: [`namespace/${ns}`],
          notes: ['Secret 读取本身即信息泄露；类型为 service-account-token 的 Secret 直接包含 SA 凭据'],
        };
        addEdge(node.id, ensureSecretReadNode(ns), 'secret-read-sa-token', 'certain', evidence);

        for (const secret of tokens.filter((t) => t.namespace === ns)) {
          if (!secret.serviceAccount) continue;
          const allowed = findAllowance(grants, {
            verb: 'get',
            apiGroup: '',
            resource: 'secrets',
            namespace: ns,
            name: secret.name,
          });
          const listAllowed = findAllowance(grants, { verb: 'list', apiGroup: '', resource: 'secrets', namespace: ns });
          if (!allowed && !listAllowed) continue;
          addEdge(node.id, ensureSaNode(ns, secret.serviceAccount), 'secret-read-sa-token', 'certain', {
            permission: `read secret ${ns}/${secret.name}`,
            action: `kubectl get secret ${secret.name} -n ${ns} -o jsonpath='{.data.token}' | base64 -d`,
            rule: (allowed ?? listAllowed)!.rule,
            source: (allowed ?? listAllowed)!.source,
            objects: [`secret/${ns}/${secret.name}`, `serviceaccount/${ns}/${secret.serviceAccount}`],
            notes: ['该 Secret 记录了 SA token，读它即取得该 SA 身份'],
          });
        }
      }

      const tokenReq = tokenRequestCapability(grants, ns);
      if (tokenReq) {
        for (const saName of saMap.get(ns) ?? []) {
          addEdge(node.id, ensureSaNode(ns, saName), 'token-request', 'certain', {
            permission: `create serviceaccounts/token in ${ns}`,
            action: `kubectl create token ${saName} -n ${ns}`,
            rule: tokenReq.rule,
            source: tokenReq.source,
            objects: [`serviceaccount/${ns}/${saName}`],
            notes: ['TokenRequest 无需读取任何 Secret；禁用 Secret 读权限无法阻止这条路径'],
          });
        }
      }

      const writeCap = secretWriteCapability(grants, ns);
      if (writeCap) {
        for (const saName of saMap.get(ns) ?? []) {
          addEdge(node.id, ensureSaNode(ns, saName), 'secret-write-sa-token', 'conditional', {
            permission: `create/patch/update secrets in ${ns}`,
            action: `创建 type=kubernetes.io/service-account-token 且注解 kubernetes.io/service-account.name=${saName} 的 Secret，再读回 token`,
            rule: writeCap.rule,
            source: writeCap.source,
            objects: [`serviceaccount/${ns}/${saName}`],
            notes: [
              '1.24+ 默认关闭 LegacyServiceAccountTokenNoAutoGeneration，此手法在较新集群上可能失效',
              '还需要能读回该 Secret 才能取得 token',
            ],
          });
        }
      }
    }
  }

  function generateCsrEdges(node: GraphNode): void {
    const grants = node.grants;
    const createCsr = canInNamespace(grants, 'create', 'certificates.k8s.io', 'certificatesigningrequests', '');
    if (!createCsr) return;
    const canApprove =
      canInNamespace(grants, 'update', 'certificates.k8s.io', 'certificatesigningrequests', '', undefined, 'approval') ??
      canInNamespace(grants, 'patch', 'certificates.k8s.io', 'certificatesigningrequests', '', undefined, 'approval');
    if (!canApprove) return;
    const signerHit =
      findAllowance(grants, {
        verb: 'approve',
        apiGroup: 'certificates.k8s.io',
        resource: 'signers',
        name: 'kubernetes.io/kube-apiserver-client',
      }) ??
      findAllowance(grants, {
        verb: 'approve',
        apiGroup: 'certificates.k8s.io',
        resource: 'signers',
        name: 'kubernetes.io/*',
      }) ??
      findAllowance(grants, {
        verb: 'approve',
        apiGroup: 'certificates.k8s.io',
        resource: 'signers',
      });
    if (!signerHit) return;
    addEdge(node.id, CLUSTER_ADMIN, 'csr-approve', 'conditional', {
      permission: 'create certificatesigningrequests + update …/approval + approve signers/kubernetes.io/*',
      action: `openssl req -new -subj "/CN=system:admin/O=system:masters" ... && kubectl certificate approve <csr>`,
      rule: signerHit.rule,
      source: signerHit.source,
      objects: ['certificatesigningrequest/pwn'],
      notes: [
        'kubernetes.io/kube-apiserver-client 签名器原样使用 CSR 中的 subject',
        '部分托管集群禁用了该签名器或会校验 subject，需实测',
        '审计日志里 create CSR 与 approve 往往是两个不同身份，容易漏看',
      ],
    });
  }

  // -------------------------------------------------------------- adjacency
  const outgoing = new Map<string, GraphEdge[]>();
  const incoming = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from)!.push(edge);
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to)!.push(edge);
  }

  // The picker lists the cluster's own identities. Bootstrap system users
  // (kube-proxy, kube-scheduler, system:masters) exist only because the built-in
  // bindings mention them; showing them by default buries the real subjects.
  // Note this keys off "appears in imported data", NOT "has non-builtin
  // grants": a real ServiceAccount whose only roles happen to be bootstrap
  // ones is still a real object an operator needs to see.
  const principalIds = [...nodes.values()]
    .filter((n) => !n.synthetic && !n.derived && n.imported)
    .map((n) => n.id)
    .sort((a, b) => nodes.get(a)!.label.localeCompare(nodes.get(b)!.label));
  const allPrincipalIds = [...nodes.values()]
    .filter((n) => !n.synthetic && !n.derived)
    .map((n) => n.id)
    .sort((a, b) => nodes.get(a)!.label.localeCompare(nodes.get(b)!.label));

  return { graph: { nodes, edges, outgoing, incoming, principalIds, allPrincipalIds }, notes };
}

// ---------------------------------------------------------------------------
// Path finding
// ---------------------------------------------------------------------------

export interface PathOptions {
  /** Allow edges that depend on version/feature details. Default true. */
  includeConditional?: boolean;
}

/**
 * Shortest path by hop count, breaking ties in favour of `certain` edges.
 * Dijkstra because conditional edges cost slightly more, which keeps the
 * "fewest assumptions" path when hop counts are equal.
 */
export function shortestPath(graph: Graph, startId: string, targetId: string, options: PathOptions = {}): PathResult | null {
  if (!graph.nodes.has(startId) || !graph.nodes.has(targetId)) return null;
  const includeConditional = options.includeConditional ?? true;

  const dist = new Map<string, number>();
  const prev = new Map<string, { from: string; edge: GraphEdge }>();
  const visited = new Set<string>();
  dist.set(startId, 0);

  while (true) {
    let current: string | null = null;
    let best = Infinity;
    for (const [id, d] of dist) {
      if (visited.has(id)) continue;
      if (d < best) {
        best = d;
        current = id;
      }
    }
    if (current === null) break;
    if (current === targetId) break;
    visited.add(current);

    for (const edge of graph.outgoing.get(current) ?? []) {
      if (edge.technique === 'implicit-group') continue;
      if (edge.confidence === 'conditional' && !includeConditional) continue;
      const cost = edge.confidence === 'conditional' ? 1.01 : 1;
      const next = best + cost;
      if (!dist.has(edge.to) || next < dist.get(edge.to)!) {
        dist.set(edge.to, next);
        prev.set(edge.to, { from: current, edge });
      }
    }
  }

  if (!dist.has(targetId)) return null;

  const hops: PathHop[] = [];
  let cursor = targetId;
  const guard = new Set<string>();
  while (cursor !== startId) {
    if (guard.has(cursor)) break;
    guard.add(cursor);
    const step = prev.get(cursor);
    if (!step) return null;
    hops.unshift({
      edge: step.edge,
      fromNode: graph.nodes.get(step.from)!,
      toNode: graph.nodes.get(cursor)!,
    });
    cursor = step.from;
  }

  return {
    start: graph.nodes.get(startId)!,
    end: graph.nodes.get(targetId)!,
    hops,
    reachesClusterAdmin: targetId === CLUSTER_ADMIN,
  };
}

/**
 * Enumerate up to `limit` distinct short paths, so the UI can show alternatives
 * rather than pretending one chain is the only one. Depth-limited DFS that
 * deduplicates by technique sequence.
 */
export function enumeratePaths(
  graph: Graph,
  startId: string,
  targetId: string,
  options: PathOptions & { maxHops?: number; limit?: number } = {},
): PathResult[] {
  const maxHops = options.maxHops ?? 6;
  const limit = options.limit ?? 8;
  const includeConditional = options.includeConditional ?? true;
  if (!graph.nodes.has(startId) || !graph.nodes.has(targetId)) return [];

  const found: PathResult[] = [];
  // Deduplicate by the sequence of *identities* visited, not the technique
  // chain: two routes that bounce through the same principals in a different
  // order are permutations, not genuinely different escape routes.
  const seenSequences = new Set<string>();
  /**
   * Two routes that touch the same set of principals are the same finding with
   * the steps reordered; reporting both wastes the reader's attention. The
   * endpoint set is the right identity, the ordering is not.
   */
  const sequenceOf = (hops: PathHop[]): string =>
    [startId, ...hops.map((h) => h.toNode.id)].sort().join('>');

  const walk = (current: string, visited: Set<string>, hops: PathHop[]): void => {
    if (found.length >= limit) return;
    if (current === targetId) {
      const seq = sequenceOf(hops);
      if (!seenSequences.has(seq)) {
        seenSequences.add(seq);
        found.push({
          start: graph.nodes.get(startId)!,
          end: graph.nodes.get(targetId)!,
          hops: hops.slice(),
          reachesClusterAdmin: targetId === CLUSTER_ADMIN,
        });
      }
      return;
    }
    if (hops.length >= maxHops) return;
    for (const edge of graph.outgoing.get(current) ?? []) {
      if (edge.technique === 'implicit-group') continue;
      if (edge.confidence === 'conditional' && !includeConditional) continue;
      if (visited.has(edge.to)) continue;
      visited.add(edge.to);
      hops.push({ edge, fromNode: graph.nodes.get(current)!, toNode: graph.nodes.get(edge.to)! });
      walk(edge.to, visited, hops);
      hops.pop();
      visited.delete(edge.to);
    }
  };

  walk(startId, new Set([startId]), []);
  return found.sort((a, b) => a.hops.length - b.hops.length);
}

/** All simple-ish shortest paths to cluster-admin, one per starting principal. */
export function pathsToClusterAdmin(graph: Graph, options: PathOptions = {}): Array<{ startId: string; path: PathResult }> {
  const out: Array<{ startId: string; path: PathResult }> = [];
  for (const startId of graph.principalIds) {
    const path = shortestPath(graph, startId, CLUSTER_ADMIN, options);
    if (path) out.push({ startId, path });
  }
  return out.sort((a, b) => a.path.hops.length - b.path.hops.length);
}

/**
 * Principals that can read Secrets in a namespace.
 *
 * Transitive by default: a principal that escalates to cluster-admin can read
 * them too, and saying otherwise would be lying. `directOnly` keeps only the
 * principals whose *own* grants allow the read, which is what most reviewers
 * actually want to see first.
 */
export function whoCanReadSecrets(
  graph: Graph,
  namespace: string,
  options: PathOptions & { directOnly?: boolean; includeBootstrapPrincipals?: boolean } = {},
): Array<{ startId: string; path: PathResult }> {
  const target = `x:secret-read:${namespace}`;
  if (!graph.nodes.has(target)) return [];
  const maxHops = options.directOnly ? 1 : Infinity;
  const pool = options.includeBootstrapPrincipals ? graph.allPrincipalIds : graph.principalIds;
  const out: Array<{ startId: string; path: PathResult }> = [];
  for (const startId of pool) {
    const path = shortestPath(graph, startId, target, { includeConditional: options.includeConditional ?? false });
    if (!path) continue;
    if (path.hops.length > maxHops) continue;
    out.push({ startId, path });
  }
  return out.sort((a, b) => a.path.hops.length - b.path.hops.length);
}

/** Reverse: who can reach a given namespace's full control. */
export function whoCanReachNode(graph: Graph, targetId: string, options: PathOptions = {}): Array<{ startId: string; path: PathResult }> {
  if (!graph.nodes.has(targetId)) return [];
  const out: Array<{ startId: string; path: PathResult }> = [];
  for (const startId of graph.principalIds) {
    const path = shortestPath(graph, startId, targetId, options);
    if (path) out.push({ startId, path });
  }
  return out.sort((a, b) => a.path.hops.length - b.path.hops.length);
}

export { CLUSTER_ADMIN };

// ---------------------------------------------------------------------------
// Principal projection (for the graph view)
// ---------------------------------------------------------------------------

/**
 * The full graph contains intermediate "role acquired" nodes so that each hop
 * can cite exactly one rule. That is right for reading a path, but it makes a
 * whole-cluster diagram unreadable: `builder -> role:admin -> cluster-admin`
 * draws a box nobody wants to see.
 *
 * This projection keeps only real identities (plus the terminal and the
 * synthetic capability nodes) and composes the intermediate role hops into a
 * single edge, preserving the technique chain for the tooltip.
 */
export function projectToPrincipals(graph: Graph): Graph {
  const visible = (id: string): boolean => {
    const node = graph.nodes.get(id);
    if (!node) return false;
    if (id.startsWith('role:')) return false;
    if (node.derived) return false;
    return true;
  };

  const edges: GraphEdge[] = [];
  // Keyed by (from, to, technique): several distinct role chains can reach the
  // same principal with the same action. Keep the shortest one — it is the one
  // a reader would actually try.
  const bestChain = new Map<string, number>();

  const push = (from: string, to: string, chain: GraphEdge[]) => {
    const key = `${from}->${to}:${chain[0].technique}`;
    const prevLength = bestChain.get(key);
    if (prevLength !== undefined && prevLength <= chain.length) return;
    bestChain.set(key, chain.length);
    // The last edge into a synthetic role node is an artifact of how "holding
    // this role" is modelled; the *action* is the one that acquired the role,
    // so the first edge carries both the label and the evidence.
    const primary = chain[0];
    const composed = {
      from,
      to,
      technique: primary.technique,
      confidence: chain.some((e) => e.confidence === 'conditional') ? 'conditional' : 'certain',
      evidence: {
        ...primary.evidence,
        notes: [
          ...(chain.length > 1 ? [`经由：${chain.map((e) => e.technique).join(' → ')}`] : []),
          ...(primary.evidence.notes ?? []),
        ],
      },
      // Record the full technique chain so the UI can explain a composed edge.
      chain: chain.map((e) => e.technique),
    } as GraphEdge & { chain: string[] };
    edges.push(composed);
  };

  for (const startId of graph.nodes.keys()) {
    if (!visible(startId)) continue;
    // Walk through invisible intermediaries, depth-limited.
    const walk = (current: string, chain: GraphEdge[], visited: Set<string>) => {
      for (const edge of graph.outgoing.get(current) ?? []) {
        // Group membership is already folded into each principal's grants and is
        // not an escalation step; drawing it just adds fans of grey lines.
        if (edge.technique === 'implicit-group') continue;
        if (chain.some((e) => e.technique === edge.technique && e.to === edge.to)) continue;
        if (visited.has(edge.to)) continue;
        const nextChain = [...chain, edge];
        if (visible(edge.to)) {
          push(startId, edge.to, nextChain);
          // A visible node can also be an intermediary (rare); stop here so the
          // diagram stays a DAG of meaningful steps.
          continue;
        }
        if (nextChain.length >= 3) continue;
        walk(edge.to, nextChain, new Set([...visited, edge.to]));
      }
    };
    walk(startId, [], new Set([startId]));
  }

  const outgoing = new Map<string, GraphEdge[]>();
  const incoming = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
    outgoing.get(edge.from)!.push(edge);
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to)!.push(edge);
  }

  const nodes = new Map([...graph.nodes].filter(([id]) => visible(id)));
  return {
    nodes,
    edges,
    outgoing,
    incoming,
    principalIds: graph.principalIds.filter(visible),
    allPrincipalIds: graph.allPrincipalIds.filter(visible),
  };
}
