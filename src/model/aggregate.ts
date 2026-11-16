import type { ClusterRoleDef, LabelSelector, PolicyRule, ResolvedClusterRole } from './types';
import { compactRule } from './rbac';

function selectorMatches(selector: LabelSelector, labels: Record<string, string>): boolean {
  for (const [k, v] of Object.entries(selector.matchLabels ?? {})) {
    if (labels[k] !== v) return false;
  }
  for (const expr of selector.matchExpressions ?? []) {
    const has = Object.prototype.hasOwnProperty.call(labels, expr.key);
    const value = labels[expr.key];
    switch (expr.operator) {
      case 'In':
        if (!has || !(expr.values ?? []).includes(value)) return false;
        break;
      case 'NotIn':
        if (has && (expr.values ?? []).includes(value)) return false;
        break;
      case 'Exists':
        if (!has) return false;
        break;
      case 'DoesNotExist':
        if (has) return false;
        break;
    }
  }
  return true;
}

function ruleKey(rule: PolicyRule): string {
  return compactRule(rule) + '|' + JSON.stringify(rule);
}

/**
 * Expands `aggregationRule` the way the ClusterRoleAggregationController does:
 * every ClusterRole matching a selector contributes its rules, duplicates are
 * dropped, and the aggregated role's own `rules` field is *overwritten*.
 *
 * The real controller also populates the rules field on the aggregated role,
 * which means aggregated roles can themselves be selected by another
 * aggregated role. We iterate to a fixed point to model that eventual state.
 */
export function resolveClusterRoles(defs: ClusterRoleDef[]): Map<string, ResolvedClusterRole> {
  const byName = new Map<string, ClusterRoleDef>();
  for (const def of defs) byName.set(def.name, def);

  const result = new Map<string, ResolvedClusterRole>();
  for (const def of defs) {
    result.set(def.name, {
      def,
      rules: def.rules.slice(),
      aggregatedFrom: [],
      aggregated: !!def.aggregationRule,
    });
  }

  const aggregateNames = defs.filter((d) => d.aggregationRule).map((d) => d.name);
  // A handful of passes is enough; the controller converges the same way.
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    for (const name of aggregateNames) {
      const resolved = result.get(name)!;
      const selectors = resolved.def.aggregationRule?.clusterRoleSelectors ?? [];
      const rules: PolicyRule[] = [];
      const seen = new Set<string>();
      const sources: string[] = [];
      for (const selector of selectors) {
        const matches = [...result.values()]
          .filter((r) => r.def.name !== name && selectorMatches(selector, r.def.labels))
          .sort((a, b) => a.def.name.localeCompare(b.def.name));
        for (const match of matches) {
          if (!sources.includes(match.def.name)) sources.push(match.def.name);
          for (const rule of match.rules) {
            const key = ruleKey(rule);
            if (seen.has(key)) continue;
            seen.add(key);
            rules.push(rule);
          }
        }
      }
      const before = JSON.stringify(resolved.rules);
      const after = JSON.stringify(rules);
      const srcBefore = resolved.aggregatedFrom.join(',');
      const srcAfter = sources.join(',');
      if (before !== after || srcBefore !== srcAfter) {
        resolved.rules = rules;
        resolved.aggregatedFrom = sources;
        changed = true;
      }
    }
    if (!changed) break;
  }

  return result;
}
