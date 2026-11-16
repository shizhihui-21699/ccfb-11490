import type { ClusterModel, Diagnostic, Grant, GrantSource, Principal } from './types';
import { builtinClusterRoleBindings, builtinClusterRoles } from './builtins';
import { resolveClusterRoles } from './aggregate';
import { parseYamlDocuments } from './parse';

export interface BuildOptions {
  /** Include the default bootstrap ClusterRoles/Bindings an API server installs. */
  includeBootstrap?: boolean;
}

export function buildModel(yamlText: string, options: BuildOptions = {}): ClusterModel {
  const parsed = parseYamlDocuments(yamlText);
  const diagnostics: Diagnostic[] = [...parsed.diagnostics];

  const includeBootstrap = options.includeBootstrap ?? true;
  const clusterRoleDefs = includeBootstrap
    ? [...builtinClusterRoles().filter((b) => !parsed.clusterRoles.some((i) => i.name === b.name)), ...parsed.clusterRoles]
    : parsed.clusterRoles;

  if (includeBootstrap) {
    for (const builtin of builtinClusterRoles()) {
      if (!parsed.clusterRoles.some((i) => i.name === builtin.name)) {
        diagnostics.push({
          level: 'info',
          message: `内置 ClusterRole ${builtin.name} 未在导入数据中出现，已使用 v1.31 引导策略补齐`,
          object: `ClusterRole/${builtin.name}`,
        });
      }
    }
  } else {
    for (const name of ['cluster-admin', 'admin', 'edit', 'view']) {
      if (!parsed.clusterRoles.some((i) => i.name === name)) {
        diagnostics.push({
          level: 'warning',
          message: `未启用内置角色，且导入数据中缺少 ${name}，相关权限将判定为不可达`,
          object: `ClusterRole/${name}`,
        });
      }
    }
  }

  const clusterRoles = resolveClusterRoles(clusterRoleDefs);

  const roles = new Map<string, Map<string, import('./types').RoleDef>>();
  for (const role of parsed.roles) {
    let ns = roles.get(role.namespace);
    if (!ns) {
      ns = new Map();
      roles.set(role.namespace, ns);
    }
    if (ns.has(role.name)) {
      diagnostics.push({ level: 'warning', message: `Role ${role.namespace}/${role.name} 重复定义，后者覆盖前者` });
    }
    ns.set(role.name, role);
  }

  const clusterRoleBindings = includeBootstrap
    ? [...builtinClusterRoleBindings().filter((b) => !parsed.clusterRoleBindings.some((i) => i.name === b.name)), ...parsed.clusterRoleBindings]
    : parsed.clusterRoleBindings;

  const users = new Set<string>();
  const groups = new Set<string>();
  const noteSubject = (s: { kind: string; name: string }) => {
    if (s.kind === 'User') users.add(s.name);
    if (s.kind === 'Group') groups.add(s.name);
  };
  // Only bindings that came from the dump define the cluster's own subjects.
  // Bootstrap bindings mention system users (`system:kube-scheduler`,
  // `system:masters`); folding those in would mark every imported user as
  // "builtin-only" the moment any built-in binding exists.
  parsed.clusterRoleBindings.forEach((b) => b.subjects.forEach(noteSubject));
  parsed.roleBindings.forEach((b) => b.subjects.forEach(noteSubject));

  // Resolve dangling references up front so the UI can warn.
  for (const b of [...clusterRoleBindings, ...parsed.roleBindings]) {
    if (b.roleRef.kind === 'ClusterRole' && !clusterRoles.has(b.roleRef.name)) {
      diagnostics.push({
        level: 'warning',
        message: `${b.kind} ${b.namespace ? b.namespace + '/' : ''}${b.name} 引用了不存在的 ClusterRole ${b.roleRef.name}`,
        object: `${b.kind}/${b.name}`,
      });
    }
    if (b.roleRef.kind === 'Role') {
      const ns = b.namespace!;
      if (!roles.get(ns)?.has(b.roleRef.name)) {
        diagnostics.push({
          level: 'warning',
          message: `${b.kind} ${ns}/${b.name} 引用了不存在的 Role ${b.roleRef.name}`,
          object: `${b.kind}/${b.name}`,
        });
      }
    }
  }

  return {
    clusterRoles,
    roles,
    roleBindings: parsed.roleBindings,
    clusterRoleBindings,
    serviceAccounts: parsed.serviceAccounts,
    pods: parsed.pods,
    secrets: parsed.secrets,
    namespaces: [...parsed.namespaces].sort(),
    users,
    groups,
    diagnostics,
    bootstrapIncluded: includeBootstrap,
  };
}

// ---------------------------------------------------------------------------
// Effective permissions
// ---------------------------------------------------------------------------

/**
 * Which namespaced bindings apply to a principal, and in which namespace the
 * resulting rules are in effect.
 *
 * A RoleBinding grants its role's rules only within its own namespace. A
 * ClusterRoleBinding grants its ClusterRole's rules cluster-wide.
 */
export function grantsForPrincipal(model: ClusterModel, principal: Principal): Grant[] {
  return grantsForPrincipalWithGroups(model, principal, implicitGroups(principal));
}

/**
 * Groups the authenticator assigns automatically. `system:authenticated` covers
 * every authenticated principal; ServiceAccounts also join the two SA groups.
 * RBAC cannot revoke these, so they must be part of any permission calculation.
 */
export function implicitGroups(principal: Principal): string[] {
  switch (principal.kind) {
    case 'ServiceAccount':
      return ['system:authenticated', 'system:serviceaccounts', `system:serviceaccounts:${principal.namespace}`];
    case 'User':
      return ['system:authenticated'];
    case 'Group':
      // Selecting a group as the subject means "anyone in this group", so the
      // group's own name is the membership set.
      return [principal.name];
  }
}

/**
 * Grants for a principal, including those inherited from `groups`.
 *
 * This is the RBAC rule resolver's `appliesTo(user, subjects)`: a binding
 * applies if any subject matches the user's name *or any group the user is in*.
 * Pass the principal's effective groups (implicit + explicitly impersonated).
 */
export function grantsForPrincipalWithGroups(
  model: ClusterModel,
  principal: Principal,
  groups: string[],
): Grant[] {
  const grants: Grant[] = [];
  const groupSet = new Set(groups);

  const subjectMatches = (subject: import('./types').Subject, bindingNamespace?: string): GrantSource['subjectKind'] | null => {
    switch (subject.kind) {
      case 'User':
        return principal.kind === 'User' && principal.name === subject.name ? 'User' : null;
      case 'Group':
        return groupSet.has(subject.name) ? 'Group' : null;
      case 'ServiceAccount': {
        if (principal.kind !== 'ServiceAccount') return null;
        const ns = subject.namespace ?? bindingNamespace;
        if (ns === principal.namespace && subject.name === principal.name) return 'ServiceAccount';
        return null;
      }
    }
  };

  for (const binding of model.clusterRoleBindings) {
    for (const subject of binding.subjects) {
      if (!subjectMatches(subject, binding.namespace)) continue;
      if (binding.roleRef.kind === 'ClusterRole') {
        const role = model.clusterRoles.get(binding.roleRef.name);
        if (!role) continue;
        for (const rule of role.rules) {
          grants.push({
            rule,
            scope: { kind: 'cluster' },
            source: {
              bindingKind: 'ClusterRoleBinding',
              bindingName: binding.name,
              roleKind: 'ClusterRole',
              roleName: role.def.name,
              subjectKind: subject.kind,
              subjectName: subject.name,
              subjectNamespace: subject.namespace,
              origin: binding.origin,
            },
          });
        }
      }
      // A ClusterRoleBinding to a Role is invalid; the API server rejects it.
    }
  }

  for (const binding of model.roleBindings) {
    const namespace = binding.namespace!;
    for (const subject of binding.subjects) {
      if (!subjectMatches(subject, namespace)) continue;
      if (binding.roleRef.kind === 'Role') {
        const role = model.roles.get(namespace)?.get(binding.roleRef.name);
        if (!role) continue;
        for (const rule of role.rules) {
          grants.push({
            rule,
            scope: { kind: 'namespace', namespace },
            source: {
              bindingKind: 'RoleBinding',
              bindingName: binding.name,
              bindingNamespace: namespace,
              roleKind: 'Role',
              roleName: role.name,
              roleNamespace: namespace,
              subjectKind: subject.kind,
              subjectName: subject.name,
              subjectNamespace: subject.namespace,
              origin: binding.origin,
            },
          });
        }
      } else {
        // RoleBinding referencing a ClusterRole: rules apply within the namespace.
        const role = model.clusterRoles.get(binding.roleRef.name);
        if (!role) continue;
        for (const rule of role.rules) {
          grants.push({
            rule,
            scope: { kind: 'namespace', namespace },
            source: {
              bindingKind: 'RoleBinding',
              bindingName: binding.name,
              bindingNamespace: namespace,
              roleKind: 'ClusterRole',
              roleName: role.def.name,
              subjectKind: subject.kind,
              subjectName: subject.name,
              subjectNamespace: subject.namespace,
              origin: binding.origin,
            },
          });
        }
      }
    }
  }

  return grants;
}
