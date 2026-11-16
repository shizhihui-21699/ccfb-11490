import { loadAll } from 'js-yaml';
import type {
  BindingDef,
  ClusterRoleDef,
  Diagnostic,
  LabelSelector,
  PodDef,
  PolicyRule,
  RoleDef,
  SecretDef,
  ServiceAccountDef,
  Subject,
} from './types';

export interface ParsedObjects {
  clusterRoles: ClusterRoleDef[];
  roles: RoleDef[];
  roleBindings: BindingDef[];
  clusterRoleBindings: BindingDef[];
  serviceAccounts: ServiceAccountDef[];
  pods: PodDef[];
  secrets: SecretDef[];
  namespaces: Set<string>;
  diagnostics: Diagnostic[];
  /** Object kinds we saw but do not model. */
  ignoredKinds: Map<string, number>;
}

type Dict = Record<string, unknown>;

function asDict(v: unknown): Dict {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Dict) : {};
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function strList(v: unknown): string[] {
  return asArray(v).filter((x): x is string => typeof x === 'string');
}

function labels(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(asDict(v))) {
    if (typeof val === 'string') out[k] = val;
  }
  return out;
}

const KNOWN_KINDS = new Set([
  'Role',
  'ClusterRole',
  'RoleBinding',
  'ClusterRoleBinding',
  'Pod',
  'ServiceAccount',
  'Secret',
  'Namespace',
]);

/**
 * Parses anything `kubectl get ... -o yaml` produces: single objects, multi-doc
 * streams, `kind: List` wrappers (what `kubectl get -o yaml` actually emits for
 * multiple objects), and `kubectl get -o yaml` output with no apiVersion.
 */
export function parseYamlDocuments(text: string): ParsedObjects {
  const out: ParsedObjects = {
    clusterRoles: [],
    roles: [],
    roleBindings: [],
    clusterRoleBindings: [],
    serviceAccounts: [],
    pods: [],
    secrets: [],
    namespaces: new Set(),
    diagnostics: [],
    ignoredKinds: new Map(),
  };

  const docs: unknown[] = [];
  try {
    for (const d of loadAll(text, { json: true })) {
      if (d !== undefined && d !== null) docs.push(d);
    }
  } catch (err) {
    out.diagnostics.push({ level: 'error', message: `YAML 解析失败: ${(err as Error).message}` });
    return out;
  }

  const flattened: Dict[] = [];
  const flatten = (node: unknown) => {
    const dict = asDict(node);
    if (dict.kind === 'List' || dict.kind === 'SecretList' || dict.kind === 'PodList' || Array.isArray(dict.items)) {
      for (const item of asArray(dict.items)) flatten(item);
      return;
    }
    if (Object.keys(dict).length > 0) flattened.push(dict);
  };
  for (const d of docs) flatten(d);

  for (const doc of flattened) {
    consumeObject(doc, out);
  }

  // Every namespace mentioned anywhere is a namespace we know about.
  const rememberNs = (ns: string | undefined) => {
    if (ns) out.namespaces.add(ns);
  };
  out.roles.forEach((r) => rememberNs(r.namespace));
  out.roleBindings.forEach((r) => rememberNs(r.namespace));
  out.clusterRoleBindings.forEach((b) => b.subjects.forEach((s) => rememberNs(s.namespace)));
  out.pods.forEach((p) => rememberNs(p.namespace));
  out.serviceAccounts.forEach((s) => rememberNs(s.namespace));
  out.secrets.forEach((s) => rememberNs(s.namespace));

  return out;
}

function consumeObject(doc: Dict, out: ParsedObjects): void {
  const kind = asString(doc.kind);
  const meta = asDict(doc.metadata);
  const name = asString(meta.name) ?? '';
  const namespace = asString(meta.namespace);

  if (!kind) {
    out.diagnostics.push({ level: 'warning', message: '跳过缺少 kind 的文档' });
    return;
  }

  if (!KNOWN_KINDS.has(kind)) {
    out.ignoredKinds.set(kind, (out.ignoredKinds.get(kind) ?? 0) + 1);
    return;
  }

  if (!name) {
    out.diagnostics.push({ level: 'warning', message: `${kind} 缺少 metadata.name，已跳过`, object: kind });
    return;
  }

  switch (kind) {
    case 'Namespace': {
      out.namespaces.add(name);
      return;
    }
    case 'ClusterRole': {
      const aggregationRule = asDict(doc.aggregationRule);
      const selectors = asArray(aggregationRule.clusterRoleSelectors).map(parseSelector);
      out.clusterRoles.push({
        name,
        rules: asArray(doc.rules).map(parsePolicyRule),
        aggregationRule: selectors.length > 0 ? { clusterRoleSelectors: selectors } : undefined,
        labels: labels(meta.labels),
        origin: 'imported',
      });
      return;
    }
    case 'Role': {
      if (!namespace) {
        out.diagnostics.push({ level: 'error', message: `Role/${name} 缺少 namespace，已跳过`, object: `Role/${name}` });
        return;
      }
      out.roles.push({
        namespace,
        name,
        rules: asArray(doc.rules).map(parsePolicyRule),
        labels: labels(meta.labels),
        origin: 'imported',
      });
      return;
    }
    case 'RoleBinding': {
      if (!namespace) {
        out.diagnostics.push({ level: 'error', message: `RoleBinding/${name} 缺少 namespace，已跳过`, object: `RoleBinding/${name}` });
        return;
      }
      const binding = parseBinding(doc, 'RoleBinding', name, namespace);
      if (binding) out.roleBindings.push(binding);
      return;
    }
    case 'ClusterRoleBinding': {
      const binding = parseBinding(doc, 'ClusterRoleBinding', name, undefined);
      if (binding) out.clusterRoleBindings.push(binding);
      return;
    }
    case 'ServiceAccount': {
      if (!namespace) {
        out.diagnostics.push({ level: 'error', message: `ServiceAccount/${name} 缺少 namespace，已跳过`, object: `ServiceAccount/${name}` });
        return;
      }
      const automount = doc.automountServiceAccountToken;
      out.serviceAccounts.push({
        namespace,
        name,
        secrets: asArray(doc.secrets)
          .map((s) => asString(asDict(s).name))
          .filter((s): s is string => !!s),
        automountServiceAccountToken: typeof automount === 'boolean' ? automount : null,
        origin: 'imported',
      });
      return;
    }
    case 'Pod': {
      if (!namespace) {
        out.diagnostics.push({ level: 'error', message: `Pod/${name} 缺少 namespace，已跳过`, object: `Pod/${name}` });
        return;
      }
      const spec = asDict(doc.spec);
      out.pods.push({
        namespace,
        name,
        serviceAccountName: asString(spec.serviceAccountName) ?? asString(spec.serviceAccount) ?? 'default',
        nodeName: asString(spec.nodeName) ?? undefined,
        labels: labels(meta.labels),
      });
      return;
    }
    case 'Secret': {
      if (!namespace) {
        out.diagnostics.push({ level: 'error', message: `Secret/${name} 缺少 namespace，已跳过`, object: `Secret/${name}` });
        return;
      }
      const annotations = labels(meta.annotations);
      out.secrets.push({
        namespace,
        name,
        type: asString(doc.type) ?? 'Opaque',
        serviceAccountName: annotations['kubernetes.io/service-account.name'],
        keys: Object.keys(asDict(doc.data)),
      });
      return;
    }
  }
}

function parseBinding(doc: Dict, kind: 'RoleBinding' | 'ClusterRoleBinding', name: string, namespace: string | undefined): BindingDef | null {
  const roleRef = asDict(doc.roleRef);
  const refKind = asString(roleRef.kind);
  const refName = asString(roleRef.name);
  if (!refName || (refKind !== 'Role' && refKind !== 'ClusterRole')) {
    return null;
  }
  const subjects: Subject[] = [];
  for (const s of asArray(doc.subjects)) {
    const dict = asDict(s);
    const subjectKind = asString(dict.kind);
    const subjectName = asString(dict.name);
    if (!subjectName) continue;
    if (subjectKind !== 'User' && subjectKind !== 'Group' && subjectKind !== 'ServiceAccount') continue;
    subjects.push({
      apiGroup: asString(dict.apiGroup),
      kind: subjectKind,
      name: subjectName,
      namespace: asString(dict.namespace) ?? (subjectKind === 'ServiceAccount' && kind === 'RoleBinding' ? namespace : undefined),
    });
  }
  return {
    kind,
    name,
    namespace,
    roleRef: {
      apiGroup: asString(roleRef.apiGroup) ?? 'rbac.authorization.k8s.io',
      kind: refKind,
      name: refName,
    },
    subjects,
    origin: 'imported',
  };
}

function parseSelector(v: unknown): LabelSelector {
  const dict = asDict(v);
  const expressions = asArray(dict.matchExpressions).map((e) => {
    const ed = asDict(e);
    const op = asString(ed.operator);
    return {
      key: asString(ed.key) ?? '',
      operator: (op === 'NotIn' || op === 'Exists' || op === 'DoesNotExist' ? op : 'In') as
        | 'In'
        | 'NotIn'
        | 'Exists'
        | 'DoesNotExist',
      values: strList(ed.values),
    };
  });
  return { matchLabels: labels(dict.matchLabels), matchExpressions: expressions.filter((e) => e.key) };
}

export function parsePolicyRule(v: unknown): PolicyRule {
  const dict = asDict(v);
  const rule: PolicyRule = {
    apiGroups: strList(dict.apiGroups),
    resources: strList(dict.resources),
    verbs: strList(dict.verbs),
  };
  const urls = strList(dict.nonResourceURLs);
  if (urls.length) rule.nonResourceURLs = urls;
  const names = strList(dict.resourceNames);
  if (names.length) rule.resourceNames = names;
  return rule;
}
