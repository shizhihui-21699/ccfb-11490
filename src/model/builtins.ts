import type { ClusterRoleDef, BindingDef, PolicyRule } from './types';

/**
 * Default ClusterRoles and ClusterRoleBindings created by the API server at
 * bootstrap (or recreated by the bootstrap policy reconciliation loop).
 *
 * Transcribed from:
 *   plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go
 *   (kubernetes v1.31)
 *
 * They are offered as an optional overlay because most `kubectl get -o yaml`
 * dumps omit them — leaving out `cluster-admin` and the aggregation labels
 * would silently break every path through `admin`.
 */

const READ = ['get', 'list', 'watch'];
const READWRITE = ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection'];
const WRITE = ['create', 'update', 'patch', 'delete', 'deletecollection'];

function rule(apiGroups: string[], resources: string[], verbs: string[], resourceNames?: string[]): PolicyRule {
  const r: PolicyRule = { apiGroups, resources, verbs };
  if (resourceNames) r.resourceNames = resourceNames;
  return r;
}

function role(name: string, rules: PolicyRule[], labels: Record<string, string> = {}): ClusterRoleDef {
  return { name, rules, labels, origin: 'builtin' };
}

const LEGACY = '';
const APPS = 'apps';
const EXT = 'extensions';
const BATCH = 'batch';
const AUTOSCALING = 'autoscaling';
const POLICY = 'policy';
const NETWORKING = 'networking.k8s.io';
const COORDINATION = 'coordination.k8s.io';
const DISCOVERY = 'discovery.k8s.io';
const AUTHN = 'authentication.k8s.io';
const AUTHZ = 'authorization.k8s.io';
const CERTS = 'certificates.k8s.io';
const RBAC = 'rbac.authorization.k8s.io';
const STORAGE = 'storage.k8s.io';

export function builtinClusterRoles(): ClusterRoleDef[] {
  const aggregateAdmin = 'rbac.authorization.k8s.io/aggregate-to-admin';
  const aggregateEdit = 'rbac.authorization.k8s.io/aggregate-to-edit';
  const aggregateView = 'rbac.authorization.k8s.io/aggregate-to-view';

  const roles: ClusterRoleDef[] = [
    role('cluster-admin', [
      { apiGroups: ['*'], resources: ['*'], verbs: ['*'] },
      { nonResourceURLs: ['*'], verbs: ['*'] },
    ]),

    role('system:discovery', [
      {
        verbs: ['get'],
        nonResourceURLs: ['/livez', '/readyz', '/healthz', '/version', '/version/', '/openapi', '/openapi/*', '/api', '/api/*', '/apis', '/apis/*'],
      },
    ]),

    role('system:monitoring', [
      {
        verbs: ['get'],
        nonResourceURLs: ['/metrics', '/metrics/slis', '/livez', '/readyz', '/healthz', '/livez/*', '/readyz/*', '/healthz/*'],
      },
    ]),

    role('system:basic-user', [
      rule([AUTHZ], ['selfsubjectaccessreviews', 'selfsubjectrulesreviews'], ['create']),
      rule([AUTHN], ['selfsubjectreviews'], ['create']),
    ]),

    role('system:public-info-viewer', [
      { verbs: ['get'], nonResourceURLs: ['/livez', '/readyz', '/healthz', '/version', '/version/'] },
    ]),

    {
      name: 'admin',
      rules: [],
      labels: {},
      origin: 'builtin',
      aggregationRule: { clusterRoleSelectors: [{ matchLabels: { [aggregateAdmin]: 'true' } }] },
    },

    {
      name: 'edit',
      rules: [],
      labels: { [aggregateAdmin]: 'true' },
      origin: 'builtin',
      aggregationRule: { clusterRoleSelectors: [{ matchLabels: { [aggregateEdit]: 'true' } }] },
    },

    {
      name: 'view',
      rules: [],
      labels: { [aggregateEdit]: 'true' },
      origin: 'builtin',
      aggregationRule: { clusterRoleSelectors: [{ matchLabels: { [aggregateView]: 'true' } }] },
    },

    role(
      'system:aggregate-to-admin',
      [
        rule([AUTHZ], ['localsubjectaccessreviews'], ['create']),
        rule([RBAC], ['roles', 'rolebindings'], READWRITE),
      ],
      { [aggregateAdmin]: 'true' },
    ),

    role(
      'system:aggregate-to-edit',
      [
        rule([LEGACY], ['pods/attach', 'pods/proxy', 'pods/exec', 'pods/portforward', 'secrets', 'services/proxy'], READ),
        // Namespaced escalation: edit can impersonate any SA in the namespace.
        rule([LEGACY], ['serviceaccounts'], ['impersonate']),

        rule([LEGACY], ['pods', 'pods/attach', 'pods/proxy', 'pods/exec', 'pods/portforward'], WRITE),
        rule([LEGACY], ['pods/eviction'], ['create']),
        rule(
          [LEGACY],
          ['replicationcontrollers', 'replicationcontrollers/scale', 'serviceaccounts', 'services', 'services/proxy', 'persistentvolumeclaims', 'configmaps', 'secrets', 'events'],
          WRITE,
        ),
        rule([LEGACY], ['serviceaccounts/token'], ['create']),

        rule([APPS], ['statefulsets', 'statefulsets/scale', 'daemonsets', 'deployments', 'deployments/scale', 'deployments/rollback', 'replicasets', 'replicasets/scale'], WRITE),
        rule([AUTOSCALING], ['horizontalpodautoscalers'], WRITE),
        rule([BATCH], ['jobs', 'cronjobs'], WRITE),
        rule([EXT], ['daemonsets', 'deployments', 'deployments/scale', 'deployments/rollback', 'ingresses', 'replicasets', 'replicasets/scale', 'replicationcontrollers/scale', 'networkpolicies'], WRITE),
        rule([POLICY], ['poddisruptionbudgets'], WRITE),
        rule([NETWORKING], ['networkpolicies', 'ingresses'], WRITE),
        rule([COORDINATION], ['leases'], READWRITE),
      ],
      { [aggregateEdit]: 'true' },
    ),

    role(
      'system:aggregate-to-view',
      [
        rule([LEGACY], ['pods', 'replicationcontrollers', 'replicationcontrollers/scale', 'serviceaccounts', 'services', 'services/status', 'endpoints', 'persistentvolumeclaims', 'persistentvolumeclaims/status', 'configmaps'], READ),
        rule([LEGACY], ['limitranges', 'resourcequotas', 'bindings', 'events', 'pods/status', 'resourcequotas/status', 'namespaces/status', 'replicationcontrollers/status', 'pods/log'], READ),
        rule([LEGACY], ['namespaces'], READ),
        rule([DISCOVERY], ['endpointslices'], READ),
        rule([APPS], ['controllerrevisions', 'statefulsets', 'statefulsets/status', 'statefulsets/scale', 'daemonsets', 'daemonsets/status', 'deployments', 'deployments/status', 'deployments/scale', 'replicasets', 'replicasets/status', 'replicasets/scale'], READ),
        rule([AUTOSCALING], ['horizontalpodautoscalers', 'horizontalpodautoscalers/status'], READ),
        rule([BATCH], ['jobs', 'cronjobs', 'cronjobs/status', 'jobs/status'], READ),
        rule([EXT], ['daemonsets', 'daemonsets/status', 'deployments', 'deployments/scale', 'deployments/status', 'ingresses', 'ingresses/status', 'replicasets', 'replicasets/scale', 'replicasets/status', 'replicationcontrollers/scale', 'networkpolicies'], READ),
        rule([POLICY], ['poddisruptionbudgets', 'poddisruptionbudgets/status'], READ),
        rule([NETWORKING], ['networkpolicies', 'ingresses', 'ingresses/status'], READ),
      ],
      { [aggregateView]: 'true' },
    ),

    role('system:heapster', [
      rule([LEGACY], ['events', 'pods', 'nodes', 'namespaces'], READ),
      rule([EXT], ['deployments'], READ),
    ]),

    role('system:node', [
      rule([AUTHN], ['tokenreviews'], ['create']),
      rule([AUTHZ], ['subjectaccessreviews', 'localsubjectaccessreviews'], ['create']),
      rule([LEGACY], ['services'], READ),
      rule([LEGACY], ['nodes'], ['create', 'get', 'list', 'watch']),
      rule([LEGACY], ['nodes/status'], ['update', 'patch']),
      rule([LEGACY], ['nodes'], ['update', 'patch']),
      rule([LEGACY], ['events'], ['create', 'update', 'patch']),
      rule([LEGACY], ['pods'], READ),
      rule([LEGACY], ['pods'], ['create', 'delete']),
      rule([LEGACY], ['pods/status'], ['update', 'patch']),
      rule([LEGACY], ['pods/eviction'], ['create']),
      // "read access to all secrets" — constrained by the Node authorizer at runtime.
      rule([LEGACY], ['secrets', 'configmaps'], ['get', 'list', 'watch']),
      rule([LEGACY], ['persistentvolumeclaims', 'persistentvolumes'], ['get']),
      rule([LEGACY], ['endpoints'], ['get']),
      rule([CERTS], ['certificatesigningrequests'], ['create', 'get', 'list', 'watch']),
      rule([COORDINATION], ['leases'], ['get', 'create', 'update', 'patch', 'delete']),
      rule([STORAGE], ['volumeattachments'], ['get']),
      rule([LEGACY], ['serviceaccounts/token'], ['create']),
      rule([LEGACY], ['persistentvolumeclaims/status'], ['get', 'update', 'patch']),
      rule([STORAGE], ['csidrivers'], ['get', 'watch', 'list']),
      rule([STORAGE], ['csinodes'], ['get', 'create', 'update', 'patch', 'delete']),
      rule(['node.k8s.io'], ['runtimeclasses'], ['get', 'list', 'watch']),
    ]),

    role('system:node-proxier', [
      rule([LEGACY], ['services', 'endpoints'], ['list', 'watch']),
      rule([LEGACY], ['nodes'], ['get', 'list', 'watch']),
      rule([LEGACY], ['events'], ['create', 'patch', 'update']),
      rule([DISCOVERY], ['endpointslices'], ['list', 'watch']),
    ]),

    role('system:kube-scheduler', [
      rule([LEGACY], ['events'], ['create', 'patch', 'update']),
      rule([COORDINATION], ['leases'], ['create']),
      rule([COORDINATION], ['leases'], ['get', 'update', 'list', 'watch'], ['kube-scheduler']),
      rule([LEGACY], ['nodes'], READ),
      rule([LEGACY], ['pods'], ['get', 'list', 'watch', 'delete']),
      rule([LEGACY], ['pods/binding', 'bindings'], ['create']),
      rule([LEGACY], ['pods/status'], ['patch', 'update']),
      rule([LEGACY], ['services', 'replicationcontrollers'], READ),
      rule([APPS, EXT], ['replicasets'], READ),
      rule([APPS], ['statefulsets'], READ),
      rule([POLICY], ['poddisruptionbudgets'], READ),
      rule([LEGACY], ['persistentvolumeclaims', 'persistentvolumes'], READ),
      rule([AUTHN], ['tokenreviews'], ['create']),
      rule([AUTHZ], ['subjectaccessreviews'], ['create']),
      rule([STORAGE], ['csinodes'], READ),
      rule([LEGACY], ['namespaces'], READ),
      rule([STORAGE], ['csidrivers'], READ),
      rule([STORAGE], ['csistoragecapacities'], READ),
    ]),

    role('system:kube-controller-manager', [
      rule([LEGACY], ['events'], ['create', 'patch', 'update']),
      rule([COORDINATION], ['leases'], ['create']),
      rule([COORDINATION], ['leases'], ['get', 'update'], ['kube-controller-manager']),
      rule([LEGACY], ['secrets', 'serviceaccounts'], ['create']),
      rule([LEGACY], ['secrets'], ['delete']),
      rule([LEGACY], ['namespaces', 'secrets', 'serviceaccounts', 'configmaps'], ['get']),
      rule([LEGACY], ['secrets', 'serviceaccounts'], ['update']),
      rule([AUTHN], ['tokenreviews'], ['create']),
      rule([AUTHZ], ['subjectaccessreviews'], ['create']),
      rule(['*'], ['*'], ['list', 'watch']),
      rule([LEGACY], ['serviceaccounts/token'], ['create']),
    ]),

    role('system:kube-dns', [rule([LEGACY], ['endpoints', 'services'], ['list', 'watch'])]),

    role('system:volume-scheduler', [
      rule([LEGACY], ['persistentvolumes'], ['get', 'list', 'watch', 'update', 'patch']),
      rule([STORAGE], ['storageclasses'], READ),
      rule([LEGACY], ['persistentvolumeclaims'], ['get', 'list', 'watch', 'update', 'patch']),
    ]),

    role('system:kubelet-api-admin', [
      rule([LEGACY], ['nodes'], READ),
      rule([LEGACY], ['nodes'], ['proxy']),
      rule([LEGACY], ['nodes/proxy', 'nodes/metrics', 'nodes/stats', 'nodes/log'], ['*']),
    ]),

    role('system:node-bootstrapper', [
      rule([CERTS], ['certificatesigningrequests'], ['create', 'get', 'list', 'watch']),
    ]),

    role('system:auth-delegator', [
      rule([AUTHN], ['tokenreviews'], ['create']),
      rule([AUTHZ], ['subjectaccessreviews'], ['create']),
    ]),

    role('system:kube-aggregator', [rule([LEGACY], ['services', 'endpoints'], READ)]),

    role('system:persistent-volume-provisioner', [
      rule([LEGACY], ['persistentvolumes'], ['get', 'list', 'watch', 'create', 'delete']),
      rule([LEGACY], ['persistentvolumeclaims'], ['get', 'list', 'watch', 'update']),
      rule([STORAGE], ['storageclasses'], READ),
      rule([LEGACY], ['events'], ['watch']),
      rule([LEGACY], ['events'], ['create', 'patch', 'update']),
    ]),

    role('system:certificates.k8s.io:certificatesigningrequests:nodeclient', [
      rule([CERTS], ['certificatesigningrequests'], ['create']),
      rule([CERTS], ['certificatesigningrequests/selfnodeclient'], ['create']),
    ]),

    role('system:certificates.k8s.io:certificatesigningrequests:selfnodeclient', [
      rule([CERTS], ['certificatesigningrequests/selfnodeclient'], ['create']),
    ]),

    role('system:aggregator:apiservices', [rule(['apiregistration.k8s.io'], ['apiservices'], READWRITE)]),
  ];

  return roles;
}

/**
 * Default ClusterRoleBindings the control plane installs. Note that most of
 * these bind to system users/groups rather than to clusters' own SAs; they are
 * here so a `--as=system:serviceaccount:...` path or a compromised node can be
 * modelled. Only a few are meaningful in a pure RBAC dump.
 */
export function builtinClusterRoleBindings(): BindingDef[] {
  const b = (name: string, roleName: string, subjects: Array<{ kind: 'User' | 'Group' | 'ServiceAccount'; name: string; namespace?: string }>): BindingDef => ({
    kind: 'ClusterRoleBinding',
    name,
    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: roleName },
    subjects: subjects.map((s) => ({ apiGroup: s.kind === 'ServiceAccount' ? '' : 'rbac.authorization.k8s.io', ...s })),
    origin: 'builtin',
  });

  return [
    b('cluster-admin', 'cluster-admin', [{ kind: 'Group', name: 'system:masters' }]),
    b('system:monitoring', 'system:monitoring', [{ kind: 'Group', name: 'system:monitoring' }]),
    b('system:discovery', 'system:discovery', [{ kind: 'Group', name: 'system:authenticated' }]),
    b('system:basic-user', 'system:basic-user', [{ kind: 'Group', name: 'system:authenticated' }]),
    b('system:public-info-viewer', 'system:public-info-viewer', [
      { kind: 'Group', name: 'system:authenticated' },
      { kind: 'Group', name: 'system:unauthenticated' },
    ]),
    b('system:node-proxier', 'system:node-proxier', [{ kind: 'User', name: 'system:kube-proxy' }]),
    b('system:kube-controller-manager', 'system:kube-controller-manager', [{ kind: 'User', name: 'system:kube-controller-manager' }]),
    b('system:kube-dns', 'system:kube-dns', [{ kind: 'ServiceAccount', name: 'kube-dns', namespace: 'kube-system' }]),
    b('system:kube-scheduler', 'system:kube-scheduler', [{ kind: 'User', name: 'system:kube-scheduler' }]),
    b('system:volume-scheduler', 'system:volume-scheduler', [{ kind: 'User', name: 'system:kube-scheduler' }]),
  ];
}

/** Labels the API server puts on roles so the aggregation controller can find them. */
export const AGGREGATION_LABELS = {
  admin: 'rbac.authorization.k8s.io/aggregate-to-admin',
  edit: 'rbac.authorization.k8s.io/aggregate-to-edit',
  view: 'rbac.authorization.k8s.io/aggregate-to-view',
};
