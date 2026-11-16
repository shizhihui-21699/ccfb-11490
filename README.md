# RBAC 提权路径分析

一个纯前端的 Kubernetes RBAC 提权路径分析器。导入 `kubectl get -o yaml` 导出的
Role、ClusterRole、RoleBinding、ClusterRoleBinding、Pod、ServiceAccount、Secret，
它把这些对象建成一张提权图，并回答两类问题：

1. **正向**：某个主体（用户 / 组 / ServiceAccount）到 `cluster-admin` 的最短路径是什么？每一跳的权限依据是什么？
2. **反向**：谁能读某个命名空间的 Secret？

所有计算都在浏览器里完成，YAML 不会离开页面。

## 快速开始

```bash
npm install
npm run build     # 产出单文件 dist/index.html，可直接双击打开
npm test          # 67 个用例
npm run typecheck
```

`dist/index.html` 是完全自包含的（JS 与 CSS 都内联），不发起任何网络请求。

## 导出数据

```bash
kubectl get ns,clusterroles,clusterrolebindings,roles,rolebindings,serviceaccounts,pods,secrets \
  -A -o yaml > cluster-rbac.yaml
```

也接受单对象粘贴、多文档流、`kind: List` 包装（`kubectl get -o yaml` 对多对象实际就是这么输出的）。

**关于内置角色**：多数导出不包含 API Server 引导时创建的角色。页面顶上有一个“内置角色”开关，
默认打开，会按 k8s v1.31 的 `bootstrappolicy` 补齐 `cluster-admin` / `admin` / `edit` / `view`
及其聚合标签。关掉它可以看到“只看集群里真实存在的对象”是什么结论——通常 `bind cluster-admin`
这类路径会失去终点。

## 它认哪些手法

清单见应用内的“手法清单”页，每一条都写了所需权限、为什么能提权、以及现实中可能失效的前提。
按类别：

- **RBAC 写入**：`bind`（ClusterRole / Role）、`escalate`（改写已绑定角色）、`escalate + create + bind` 组合
- **身份冒充**：`impersonate serviceaccounts` / `users` / `groups`，其中冒充 `system:masters` 组直接等于管理员
- **工作负载**：建 Pod 并挂载任意 SA（API Server 没有 `use` 动词）、exec / attach / 临时容器进入已有 Pod
- **凭据获取**：读 `service-account-token` Secret、TokenRequest（`serviceaccounts/token`）、自建 token Secret
- **准入控制**：CSR 伪造（`create` + `approve signers`）、篡改 MutatingWebhook
- **基础设施**：`nodes/proxy` 打 Kubelet API、hostPath PV、以及隐式组成员关系

标“隐蔽”的条目是审计里最容易漏的那类：单看每个权限都无害，组合起来才是提权。

## 引擎怎么算的

`src/model/rbac.ts` 的匹配函数逐条对应 upstream 的
`pkg/apis/rbac/v1/evaluation_helpers.go`（`VerbMatches` / `APIGroupMatches` /
`ResourceMatches` / `ResourceNameMatches` / `NonResourceURLMatches`）。刻意做到一字不差：
比 API Server 严格会产生假阴性，更宽松会产生走不通的路径。

几个容易做错、这里明确处理了的点：

| 点 | 处理方式 |
| --- | --- |
| `resourceNames` | 规则限定了名字时，**无名请求**不匹配（`ResourceNameMatches` 的 `requestedName == ""` 分支） |
| 子资源 | `pods/exec` 不等于 `pods`；同时也支持上游的 `*/exec` 写法 |
| RoleBinding 引用 ClusterRole | 规则只在该 RoleBinding 的命名空间生效 |
| 服务账号主体 | `subject.namespace` 为空时取绑定所在命名空间（`appliesToUser`） |
| 聚合角色 | 完全按 ClusterRoleAggregationController：选中者的规则并入，**聚合角色自己的 `rules` 被覆盖**，迭代到不动点以支持链式聚合 |
| `bind` 校验 | 需要 `create rolebindings/clusterrolebindings` **并且**对目标角色有 `bind`；`bind` 的作用域是绑定所在命名空间，ClusterRoleBinding 因此只能由集群级规则满足 |
| `escalate` 校验 | 需要 `update/patch` 目标角色 **并且** `escalate`；还必须已经被绑定到该角色，否则改完不生效 |
| `system:masters` | 硬编码为超级用户，不要求 ClusterRoleBinding |
| 集群级子资源 | `nodes/proxy` 无法由 RoleBinding 授予 |

### 图模型

节点是主体（外加 `cluster-admin`、命名空间通配、Secret 可读这几种合成节点）。每条边是一次提权动作，
携带：所需权限、原始 `PolicyRule`、来自哪个 Binding→Role、攻击者会执行的具体命令、以及这类手法的现实限制。

路径用 Dijkstra 求最短路；“需满足条件”的边权重稍高，所以跳数相同时优先选没有额外前提的路径。
“查看其他路径”会枚举最多 10 条不同的手法序列——同一个入口常常有好几条独立的路，关掉其中一条不代表安全。

图视图默认把中间的角色节点折叠掉（否则一张图里全是“已获得 ClusterRole xxx”的方框），
勾选“显示角色节点”可以看到完整的三段式：主体 → 获得角色 → 该角色带来的下一步。

## 显式不做的事

- **不考虑 Admission / Node authorizer 的运行时约束**。`NodeRestriction` 会限制 kubelet 身份；
  `edit` 角色在默认配置下不能建特权 Pod 但仍能建普通 Pod 并挂 SA——这些细节在证据块的“前提/限制”里说明，但没有建模成图中的条件。
- **不评估 PodSecurity 是否拦截某个 Pod 规格**。PSA baseline 禁 hostPath，所以 hostPath 路径标为“需满足条件”。
- **不判断 Secret 内容**。只要类型/注解/键看起来是 SA token，就当作凭据处理。
- **数据是静态快照**。结论请用 `kubectl auth can-i` 复核。

## 代码结构

```
src/model/     类型、RBAC 匹配、YAML 解析、聚合展开、内置引导策略
src/engine/    手法目录（techniques.ts）、请求判定（query.ts）、建图与寻路（graph.ts）
web/           React 界面
tests/         67 个用例，含 5 条植入路径、负样本与回归用例
fixtures/      示例集群快照，及植入路径说明
```

`src/model` 与 `src/engine` 不依赖 DOM，可以单独在 Node 里跑（测试就是这么做的）。
