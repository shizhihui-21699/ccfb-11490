import type { Reference, TechniqueCategory, TechniqueSpec } from '../model/types';

const RBAC_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/';
const IMPERSONATION_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/';
const CSR_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/';
const SA_DOC = 'https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/';
const WEBHOOK_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/';
const NODE_AUTHZ_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/authorization/#node';
const KUBELET_DOC = 'https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/';
const POLICE = 'https://github.com/PaloAltoNetworks/rbac-police';
const KUBEHOUND = 'https://github.com/DataDog/KubeHound';

/**
 * The catalog of escalation primitives. Each entry answers three questions an
 * auditor needs: what API access it requires, what it buys the attacker, and
 * which admission/feature-gate/version caveats can make it fail in practice.
 *
 * The `requirement` strings are the *exact* RBAC permissions, using the same
 * notation as `kubectl auth can-i`.
 */
export const TECHNIQUES: TechniqueSpec[] = [
  // -------------------------------------------------------------- workload
  {
    id: 'pod-create-sa',
    nameZh: '创建 Pod 并挂载任意 ServiceAccount',
    nameEn: 'Create pods with an arbitrary serviceAccountName',
    category: 'workload',
    severity: 'critical',
    requirement: 'create pods (或 deployments/daemonsets/statefulsets/jobs/cronjobs) in <namespace>',
    rationale:
      'Pod 的 spec.serviceAccountName 由创建者自由指定，API Server 没有任何“SA 使用权”鉴权（upstream 没有 use 动词）。只要能在命名空间建 Pod，就能以该命名空间内任意已存在的 SA 身份与 API Server 通信；挂载的 token 会被投射进容器。',
    limitations: [
      '目标 SA 必须已存在（ServiceAccount admission 插件会拒绝不存在的 SA），但每个命名空间的 default SA 一定存在。',
      'Pod Security Admission 的 baseline/restricted 级别不影响 SA 挂载本身。',
      '若命名空间启用了强制 PSA restricted，仍可用非特权容器完成，因此不构成阻碍。',
    ],
    references: [
      { label: 'RBAC 文档：edit 角色“allows … running Pods as any ServiceAccount”', url: RBAC_DOC },
      { label: 'configure-service-account：pod 的 serviceAccountName 字段', url: SA_DOC },
      { label: 'rbac-police assign_sa 策略', url: POLICE },
    ],
    hidden: false,
  },
  {
    id: 'pod-exec',
    nameZh: 'Exec / Attach / 临时容器进入已运行 Pod',
    nameEn: 'Exec into an existing pod',
    category: 'workload',
    severity: 'high',
    requirement: 'create pods/exec（或 pods/attach、update pods/ephemeralcontainers、patch pods）in <namespace>',
    rationale:
      '进入已在运行的 Pod 即可读到该 Pod 投射的 SA token，等价于取得该 Pod 的 SA 身份。若该 Pod 挂载了宿主目录或 privileged，还可进一步逃逸到节点。',
    limitations: [
      '只能作用于该命名空间中真实存在的 Pod，需要先枚举 Pod。',
      '若 Pod 的 automountServiceAccountToken=false 且无其他凭据，则拿不到 token（但通常仍可读到应用自身的 Secret 环境变量）。',
    ],
    references: [
      { label: 'rbac-police pods_exec / pods_ephemeral_ctrs 策略', url: POLICE },
      { label: 'Kubernetes 临时容器文档', url: 'https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/' },
    ],
    hidden: true,
  },

  // ------------------------------------------------------------ credential
  {
    id: 'token-request',
    nameZh: '通过 TokenRequest 为任意 SA 签发令牌',
    nameEn: 'Mint a token via the serviceaccounts/token subresource',
    category: 'credential',
    severity: 'critical',
    requirement: 'create serviceaccounts/token in <namespace>',
    rationale:
      'TokenRequest 子资源是现代集群获取 SA token 的正规途径。持有 create 权限即可为命名空间内任意 SA 申请短期 token，无需读取任何 Secret——因此“禁止读 Secret”并不能防住这条路径。',
    limitations: [
      '签发的 token 默认有有效期（通常 1 小时），但可重复申请。',
      '部分托管集群会限制 token 的 audience 或节点绑定，需实测。',
    ],
    references: [
      { label: 'rbac-police token_request 策略', url: POLICE },
      { label: 'Managing Service Accounts（TokenRequest）', url: 'https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/' },
    ],
    hidden: false,
  },
  {
    id: 'secret-read-sa-token',
    nameZh: '读取 Secret 中的 SA token',
    nameEn: 'Read a service-account-token Secret',
    category: 'credential',
    severity: 'critical',
    requirement: 'get/list secrets in <namespace>',
    rationale:
      '类型为 kubernetes.io/service-account-token 的 Secret（或带 kubernetes.io/service-account.name 注解的 Secret）里直接存放该 SA 的长期 token。能读 Secret 就等于能拿到其中所有 SA 的身份，这也是 view 角色被刻意禁止读 Secret 的原因。',
    limitations: [
      '1.24 起默认不再为新 Secret 自动生成 token，但既有的长期 token Secret 仍然有效。',
      'list 权限可通过枚举获得 Secret 名，无需事先知道名字。',
    ],
    references: [
      { label: 'RBAC 文档：view 不授予 Secret 读权限的原因', url: RBAC_DOC },
      { label: '手动创建长期 token Secret', url: SA_DOC },
      { label: 'rbac-police retrieve_token_secrets 策略', url: POLICE },
    ],
    hidden: false,
  },
  {
    id: 'secret-write-sa-token',
    nameZh: '自建 service-account-token Secret 取得令牌',
    nameEn: 'Forge a token Secret for a target SA',
    category: 'credential',
    severity: 'high',
    requirement: 'create OR patch/update secrets in <namespace>（并具备读回该 Secret 的能力）',
    rationale:
      '创建带 kubernetes.io/service-account.name 注解、type=kubernetes.io/service-account-token 的 Secret 后，token 控制器会为该 SA 签发 token 并写回同一 Secret。攻击者只要还能读回它，就获得了该 SA 身份。',
    limitations: [
      'LegacyServiceAccountTokenNoAutoGeneration 在 1.24 GA 后默认关闭该行为，1.24+ 集群上此手法可能失效；需实测集群版本。',
      '只有 create 而没有 get 时无法读回 token（可用 server-side apply 的 patch 取回部分字段，但不含 data）。',
    ],
    references: [
      { label: 'rbac-police issue_token_secrets 策略', url: POLICE },
      { label: '手动创建长期 token Secret', url: SA_DOC },
    ],
    hidden: true,
  },

  // --------------------------------------------------------- impersonation
  {
    id: 'impersonate-serviceaccount',
    nameZh: '冒充 ServiceAccount',
    nameEn: 'Impersonate a service account',
    category: 'impersonation',
    severity: 'critical',
    requirement: 'impersonate serviceaccounts in <namespace>（apiGroup ""）',
    rationale:
      'impersonate 动词直接让请求以目标身份执行。对 serviceaccounts 的授权是命名空间作用域，因此 RoleBinding 即可在本命名空间内冒充任意 SA；被冒充的 SA 可能在其他命名空间甚至集群级别拥有权限。',
    limitations: ['只能冒充该命名空间内的 SA（attributes 带 namespace）。', '审计日志会记录 impersonate 头，隐蔽性差。'],
    references: [
      { label: 'User Impersonation 文档', url: IMPERSONATION_DOC },
      { label: 'rbac-police impersonate 策略', url: POLICE },
    ],
    hidden: false,
  },
  {
    id: 'impersonate-user',
    nameZh: '冒充 User',
    nameEn: 'Impersonate a user',
    category: 'impersonation',
    severity: 'critical',
    requirement: 'impersonate users（apiGroup ""，可能被 resourceNames 限定）',
    rationale:
      '冒用某个用户名即继承该用户在全部绑定中的权限。冒充是集群作用域的（Role 无法授予对 users 的 impersonate），因此一旦可冒充高权限用户即可直达集群管理员。',
    limitations: ['resourceNames 可能把可冒充的对象限定为特定用户名。', '审计日志可见。'],
    references: [{ label: 'User Impersonation 文档', url: IMPERSONATION_DOC }],
    hidden: false,
  },
  {
    id: 'impersonate-group',
    nameZh: '冒充 Group（含 system:masters）',
    nameEn: 'Impersonate a group',
    category: 'impersonation',
    severity: 'critical',
    requirement: 'impersonate groups（apiGroup ""）',
    rationale:
      'system:masters 组被 API Server 内置的 privileged group authorizer 直接放行，与 RBAC 无关。能冒充 groups 的攻击者可以直接带上 Impersonate-Group: system:masters，瞬间获得集群管理员，无需任何 RBAC 规则配合。',
    limitations: ['resourceNames 可能限定可冒充的组名。', '审计日志可见。'],
    references: [
      { label: 'User Impersonation：groups 资源', url: IMPERSONATION_DOC },
      { label: 'kubernetes PR/代码：privilegedGroupAuthorizer', url: 'https://github.com/kubernetes/kubernetes/blob/v1.31.4/staging/src/k8s.io/apiserver/pkg/authorization/authorizerfactory/builtin.go' },
    ],
    hidden: true,
  },
  {
    id: 'impersonate-node',
    nameZh: '冒充 Node 身份',
    nameEn: 'Impersonate a node identity',
    category: 'impersonation',
    severity: 'high',
    requirement: 'impersonate users（resourceNames 覆盖 system:node:*）+ Node authorizer',
    rationale:
      'NODE 身份被 Node authorizer 授予读取“本节点上所有 Pod 引用的 Secret”的权限。冒充某个节点即可读取该节点上全部 Secret，其中包括高权限工作负载的 token。',
    limitations: [
      '需要 Node authorizer 已启用（多数发行版默认启用）。',
      '只能读到该节点上实际存在的 Pod 所引用的 Secret，覆盖面取决于调度。',
    ],
    references: [
      { label: 'Node 授权模式', url: NODE_AUTHZ_DOC },
      { label: 'rbac-police 对 node 的处理说明', url: POLICE },
    ],
    hidden: true,
  },

  // ------------------------------------------------------------- RBAC write
  {
    id: 'bind-clusterrole',
    nameZh: 'bind ClusterRole（配合创建 ClusterRoleBinding）',
    nameEn: 'Bind a ClusterRole cluster-wide',
    category: 'rbac-write',
    severity: 'critical',
    requirement: 'create|patch clusterrolebindings + bind clusterroles/<name>（或 bind clusterroles/*）',
    rationale:
      'API Server 只在“创建或修改绑定”时校验：你要么已经拥有目标角色的全部权限，要么显式持有对该角色的 bind 动词。bind 是对“授予权限”这一动作的绕过开关，持有它即可把 cluster-admin 授予自己或自己控制的 SA。patch 已有绑定的 subjects 同样有效——API Server 只禁止改 roleRef。',
    limitations: [
      '两个条件必须同时满足：写绑定的权限与对目标 ClusterRole 的 bind 权限。',
      'bind 的校验命名空间即为绑定所在命名空间；ClusterRoleBinding 的命名空间为空，因此只能由集群级 bind 规则满足。',
      '“已拥有全部权限”的比较按作用域进行：只在某个命名空间内通配，不覆盖集群级角色。',
    ],
    references: [
      { label: 'RBAC：Restrictions on role binding creation', url: RBAC_DOC + '#restrictions-on-role-binding-creation-or-update' },
      { label: 'rbac-police bind_roles 策略', url: POLICE },
    ],
    hidden: false,
  },
  {
    id: 'bind-role',
    nameZh: 'bind Role（命名空间内）',
    nameEn: 'Bind a namespaced Role',
    category: 'rbac-write',
    severity: 'high',
    requirement: 'create rolebindings in <namespace> + bind roles/<name> in <namespace>',
    rationale:
      '命名空间内的 bind 允许把该命名空间的任意 Role（或通过 RoleBinding 引入的 ClusterRole）授予任意主体，包括自己控制的 SA。这是从“只能编辑”跨到“能改 RBAC”的关键一步。',
    limitations: ['作用域仅限该命名空间；跨命名空间需要额外路径。'],
    references: [{ label: 'RBAC：role-grantor 示例', url: RBAC_DOC + '#restrictions-on-role-binding-creation-or-update' }],
    hidden: false,
  },
  {
    id: 'escalate-clusterrole',
    nameZh: 'escalate 改写已绑定的 ClusterRole',
    nameEn: 'Escalate an already-bound ClusterRole',
    category: 'rbac-write',
    severity: 'critical',
    requirement: 'update 或 patch clusterroles/<name> + escalate clusterroles（或 clusterroles/*）',
    rationale:
      'escalate 动词关闭了“只能授予自己所拥有的权限”这一保护。若你恰好已经被绑定到某个 ClusterRole（哪怕只是 view），就可以直接往该角色里写入 `*`，借助现有绑定获得集群管理员——不需要任何 bind 或创建绑定的权限。`patch` 与 `update` 会走到同一个存储层校验，因此二者任一即可。这条路径在审计中极难发现，因为它改的是“公共角色”。',
    limitations: [
      '需要对该 ClusterRole 有 update 或 patch 权限；仅有 escalate 而无写权限无效。',
      '改写公共角色会影响所有绑定它的主体，容易在 diff/审计中被发现。',
    ],
    references: [
      { label: 'RBAC：Restrictions on role creation or update', url: RBAC_DOC + '#restrictions-on-role-creation-or-update' },
      { label: 'rbac-police escalate_roles 策略', url: POLICE },
    ],
    hidden: true,
  },
  {
    id: 'escalate-role',
    nameZh: 'escalate 改写已绑定的 Role',
    nameEn: 'Escalate an already-bound Role',
    category: 'rbac-write',
    severity: 'high',
    requirement: 'update roles/<name> + escalate roles in <namespace>',
    rationale: '与 ClusterRole 版本同理，但作用域被限制在命名空间内：可把该空间内已有的绑定提升为 `*`。',
    limitations: ['仅命名空间内提权；通常需要再接一条跨命名空间的路径。'],
    references: [{ label: 'RBAC：Restrictions on role creation or update', url: RBAC_DOC }],
    hidden: true,
  },
  {
    id: 'escalate-create-bind',
    nameZh: 'escalate 新建角色并自行绑定',
    nameEn: 'Create a wildcard role and bind it',
    category: 'rbac-write',
    severity: 'critical',
    requirement: 'create roles + escalate roles + create rolebindings + bind roles/* in <namespace>',
    rationale:
      '没有现成的高权限角色时，攻击者可以先用 escalate 创建一个 `*` 角色，再用 bind 把它绑给自己。四个动词分属不同角色时依然可组合，这是权限审计按“单个角色”检查时最容易漏掉的情形。',
    limitations: ['四个动词必须在同一命名空间内同时具备。'],
    references: [{ label: 'rbac-police escalate_roles + bind_roles 组合', url: POLICE }],
    hidden: true,
  },

  // --------------------------------------------------------------- admission
  {
    id: 'csr-approve',
    nameZh: 'CSR 签发任意身份证书',
    nameEn: 'Approve a CSR with an arbitrary subject',
    category: 'admission',
    severity: 'critical',
    requirement:
      'create certificatesigningrequests + update certificatesigningrequests/approval + approve signers/<kubernetes.io/*>',
    rationale:
      'CSR 的 subject 由申请者自填。若同时具备“创建 CSR”和“批准 CSR（approve signers）”两项权限，就可以申请一张 CommonName=任意用户名、O=system:masters 的客户端证书，随后用它与 API Server 认证，成为集群管理员。这两个权限往往来自不同角色，单独看都不像提权。',
    limitations: [
      'kubernetes.io/kube-apiserver-client 签名器会原样使用 CSR subject；部分托管集群禁用了该签名器或强制 subject 校验。',
      'approve 需要针对 signers 资源、resourceName 覆盖 kubernetes.io/kube-apiserver-client。',
    ],
    references: [
      { label: 'Certificate Signing Requests：Request signing 与 RBAC', url: CSR_DOC },
      { label: 'rbac-police approve_csrs 策略', url: POLICE },
    ],
    hidden: true,
  },
  {
    id: 'webhook-inject',
    nameZh: '篡改 MutatingWebhook 注入 Pod',
    nameEn: 'Abuse a mutating webhook to inject into pods',
    category: 'admission',
    severity: 'high',
    requirement: 'create/patch/update mutatingwebhookconfigurations（admissionregistration.k8s.io）',
    rationale:
      '可写 MutatingWebhookConfiguration 的攻击者能对任意命名空间中被准入的 Pod 注入 sidecar 或特权容器（也可通过 sideEffects 等机制读取被准入对象的完整内容）。由此获得目标 Pod 的 SA 身份，并可能在节点上取得代码执行。',
    limitations: [
      '需要 webhook 后端可被 API Server 访问（自建 Service 或外部 URL）。',
      '集群可能启用了 webhook 的 namespaceSelector 约束或对 system 命名空间豁免。',
      '这些配置通常受高权限保护，且变更会被审计。',
    ],
    references: [
      { label: 'Dynamic Admission Control', url: WEBHOOK_DOC },
      { label: 'rbac-police control_webhooks 策略', url: POLICE },
    ],
    hidden: true,
  },

  // -------------------------------------------------------------------- infra
  {
    id: 'node-proxy',
    nameZh: 'nodes/proxy 调用 Kubelet API',
    nameEn: 'Reach the kubelet API through nodes/proxy',
    category: 'infra',
    severity: 'high',
    requirement: 'get/create nodes/proxy（或 nodes/*）',
    rationale:
      'API Server 会以自身凭据把 nodes/proxy 请求转发给 kubelet。拿到该权限即可调用 kubelet 的 exec/run 接口，在节点上的任意 Pod 中执行命令，从而读取该 Pod 的 SA token。',
    limitations: [
      'kubelet 需允许来自 API Server 的请求（默认允许）。',
      '需要知道节点名；可通过 list nodes 获得。',
      'Kubelet 的 exec 接口在部分发行版被关闭（readOnlyPort 或 feature gate）。',
    ],
    references: [
      { label: 'Kubelet authentication/authorization', url: KUBELET_DOC },
      { label: 'rbac-police nodes_proxy 策略', url: POLICE },
    ],
    hidden: true,
  },
  {
    id: 'pv-hostpath',
    nameZh: 'HostPath PV + PVC 逃逸到节点',
    nameEn: 'Mount the node filesystem via a hostPath PV',
    category: 'infra',
    severity: 'high',
    requirement: 'create persistentvolumes + create pods/persistentvolumeclaims in <namespace>',
    rationale:
      '拥有集群级 persistentvolumes 写权限时，可以创建一个 hostPath 指向 / 或 /var/lib/kubelet 的 PV，再用 Pod 挂载它，读写节点文件系统（例如植入 kubelet 凭据或静态 Pod），最终取得节点与集群控制权。',
    limitations: [
      'PodSecurity 的 baseline 已禁止 hostPath，因此目标命名空间必须未启用 PSA 或处于 privileged 级别。',
      '需要 PVC 成功绑定到该 PV（可用 storageClassName 与容量控制）。',
    ],
    references: [
      { label: 'rbac-police 关于 hostPath 的讨论', url: KUBEHOUND },
      { label: 'Pod Security Standards：hostPath', url: 'https://kubernetes.io/docs/concepts/security/pod-security-standards/' },
    ],
    hidden: true,
  },
  {
    id: 'implicit-group',
    nameZh: '隐式组成员关系',
    nameEn: 'Implicit group membership',
    category: 'credential',
    severity: 'info',
    requirement: '（无需 RBAC 权限，由认证层赋予）',
    rationale:
      '所有已认证主体都自动属于 system:authenticated；ServiceAccount 还额外属于 system:serviceaccounts 与 system:serviceaccounts:<namespace>。因此任何绑定到这些组的角色对它们天然生效，这条边不需要任何显式权限。',
    limitations: ['组成员关系来自认证层，若使用自定义 OIDC 分组，导入的 RBAC 数据无法体现。'],
    references: [{ label: 'Authenticating：用户与组', url: 'https://kubernetes.io/docs/reference/access-authn-authz/authentication/' }],
    hidden: false,
  },
];

export const TECHNIQUE_BY_ID = new Map(TECHNIQUES.map((t) => [t.id, t]));

export const CATEGORY_LABELS: Record<TechniqueCategory, string> = {
  'rbac-write': 'RBAC 写入',
  impersonation: '身份冒充',
  workload: '工作负载',
  credential: '凭据获取',
  admission: '准入控制',
  infra: '基础设施',
};

export const SEVERITY_LABELS: Record<TechniqueSpec['severity'], string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  info: '提示',
};

/** All techniques, grouped in catalog order, for the docs panel. */
export function techniquesByCategory(): Array<{ category: TechniqueCategory; items: TechniqueSpec[] }> {
  const order: TechniqueCategory[] = ['rbac-write', 'impersonation', 'workload', 'credential', 'admission', 'infra'];
  return order.map((category) => ({ category, items: TECHNIQUES.filter((t) => t.category === category) }));
}

export type { Reference };
