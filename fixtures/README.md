# 测试用集群快照 — 植入了哪些路径

`cluster.yaml` 是一个刻意做成“看起来很普通”的集群快照：CI 的 ServiceAccount 只能建 Pod，监控 SA 只能在自己命名空间里冒充别人，支付系统的角色是聚合出来的、清单里 `rules:` 为空。

下面列出每一条植入路径，以及为什么它值得单独审计。`tests/paths.test.ts` 中的 `PATH A` … `PATH E` 用例逐条校验这些链路。

---

## PATH A — “CI 只会建 Pod”

```
ci/builder  --create pods-->  ci/deployer  --bind cluster-admin-->  cluster-admin
```

- `builder` 只持有 `ci-pod-runner`：`pods` 的 `create/get/list`，外加 `pods/exec`。**没有任何 RBAC 写权限。**
- `deployer` 持有 `release-binding-granter`：`create clusterrolebindings` + 对 `cluster-admin` 的 `bind`。
- 关键点：**Pod 的 `serviceAccountName` 由创建者自由指定**，API Server 没有 `use` 动词。所以在 `ci` 里能建 Pod，就等于能以 `deployer` 身份运行代码。

审计提示：按角色逐个看，`ci-pod-runner` 是无害的。必须把“能建 Pod”和“命名空间里有哪些 SA”放在一起看才会暴露。

## PATH A-alt — 更短的一条：CSR

```
ci/builder  --create pods-->  ci/cert-bot  --CSR create + approve-->  cluster-admin
```

`builder` 能在 `ci` 里以任意 SA 起 Pod，包括 `cert-bot`。`cert-bot` 同时具备
`create certificatesigningrequests`、`update .../approval` 和 `approve signers/kubernetes.io/kube-apiserver-client`。
三者合起来可以申请并批准一张 `CN=system:admin/O=system:masters` 的客户端证书。

这是整个快照里**最短**的路径（2 跳），也是为什么“有路径就报警”比“按 hop 数排序”更重要：最短的那条往往不是最显眼的那条。

## PATH B — 命名空间内的冒充 + 改写自己的角色

```
metrics/default  --impersonate serviceaccounts-->  metrics/prometheus
                 --update + escalate 自己的 ClusterRole-->  cluster-admin
```

- `metrics/default` 只持有 `sa-impersonator`：对 `serviceaccounts` 的 `impersonate`，**作用域仅限 `metrics`**。
- `metrics/prometheus` 被绑定到 `metrics-scraper-cluster`，同时持有 `metrics-role-editor`：
  对 `metrics-scraper-cluster` 的 `update/patch` 与 `escalate`。

`escalate` 关闭了“只能授予自己已拥有的权限”的校验，而 prometheus **已经**被绑定到那个角色——于是往角色里写一条 `*` 就立即生效，不需要任何 `bind`，也不需要创建新的绑定。

审计提示：`escalate` 单独看像是“只是维护角色”，真正危险的是“持有 escalate + 已被绑定到该角色”这个组合。

## PATH C — 聚合角色把 Secret 读取藏起来了

```
payments/default  --aggregated ClusterRole-->  get/list secrets in payments
                 --read token Secret-->  payments/breakglass  --cluster-admin-->  cluster-admin
```

- `payments-operator` 的清单里 `rules: []`，靠 `aggregationRule` 从带
  `rbac.example.com/aggregate-to-payments: "true"` 标签的 ClusterRole 收集规则。
  **不展开聚合就看不到它有任何权限。**
- 展开后它给出 `secrets` 的 `get/list/watch` 和 `serviceaccounts/token` 的 `create`。
- 命名空间里存在 `breakglass` 这个“应急用”的 SA，被 ClusterRoleBinding 到 `cluster-admin`，
  且 `breakglass-token` 是一个长期 token Secret。

审计提示：`kubectl get clusterrole payments-operator -o yaml` 会给出空 rules；
必须用 `kubectl get clusterrole payments-operator -o json | jq .rules` 看控制面回填后的结果，
或者检查标签选中的那些角色。

## PATH D — 冒充 `system:masters`（隐蔽）

```
alice@example.com  --impersonate groups-->  system:masters  ==  cluster-admin
```

`system:masters` 由 API Server 内置的 `privilegedGroupAuthorizer` 直接放行，
**不查询 RBAC**。所以这条路径不需要任何 ClusterRoleBinding，也不会出现在
“哪些角色被绑定到 cluster-admin”的检查里。

只有一条规则：`resources: ["groups"], verbs: ["impersonate"]`。它看起来比
`impersonate users` 温和，实际等价。

## PATH E — CSR 伪造（隐蔽）

见 PATH A-alt。这里 `cert-bot` 是直接持有者，不经 Pod。

权限要求被拆成三条规则、来自同一个 ClusterRole：

```yaml
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests"]
  verbs: ["create", "get", "list", "watch"]
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/approval"]
  verbs: ["update"]
- apiGroups: ["certificates.k8s.io"]
  resources: ["signers"]
  resourceNames: ["kubernetes.io/kube-apiserver-client"]
  verbs: ["approve"]
```

`kubectl auth can-i` 单看任意一条都不会报红。

---

## 反向查询的样本

| 命名空间 | 直接可读 Secret 的主体 | 其中携带 SA token 的 Secret |
| --- | --- | --- |
| `ci` | `ci/deployer`（`deployer-role`） | `deployer-token` → `ci/deployer` |
| `payments` | `payments/default`（`payments-operator` 聚合） | `breakglass-token` → `payments/breakglass` |
| `metrics` | 无 | — |
| `kube-system` | 无（仅内置主体） | — |

`kube-system` 一行是刻意的负样本：确认命名空间级的 `deployer-role`（它确实能读 `ci` 的 Secret）
没有泄漏到别的命名空间。
