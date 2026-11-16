import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import type { ClusterModel, GraphEdge, GraphNode, PathHop, PathResult, TechniqueSpec } from '../src/model/types';
import { principalId, principalLabel } from '../src/model/types';
import { buildModel } from '../src/model/model';
import {
  buildGraph,
  CLUSTER_ADMIN,
  enumeratePaths,
  pathsToClusterAdmin,
  projectToPrincipals,
  shortestPath,
  whoCanReadSecrets,
  type Graph,
} from '../src/engine/graph';
import { CATEGORY_LABELS, SEVERITY_LABELS, TECHNIQUE_BY_ID, techniquesByCategory } from '../src/engine/techniques';
import { compactRule } from '../src/model/rbac';
import { DEMO_YAML } from './demoData';
import { Chip, Empty, Mono, Panel, SectionLabel, Stat } from './ui';

type Tab = 'paths' | 'secrets' | 'graph' | 'import' | 'techniques';

interface Analysis {
  model: ClusterModel;
  graph: Graph;
}

const SEVERITY_ORDER: Record<TechniqueSpec['severity'], number> = { critical: 0, high: 1, medium: 2, info: 3 };

function useAnalysis(yaml: string, includeBootstrap: boolean): { analysis: Analysis | null; error: string | null } {
  return useMemo(() => {
    if (!yaml.trim()) return { analysis: null, error: null };
    try {
      const model = buildModel(yaml, { includeBootstrap });
      const { graph } = buildGraph(model);
      return { analysis: { model, graph }, error: null };
    } catch (err) {
      return { analysis: null, error: (err as Error).message };
    }
  }, [yaml, includeBootstrap]);
}

// ---------------------------------------------------------------------------
// Small display helpers
// ---------------------------------------------------------------------------

function techniqueOf(edge: GraphEdge): TechniqueSpec | undefined {
  return TECHNIQUE_BY_ID.get(edge.technique);
}

function edgeTone(edge: GraphEdge): 'critical' | 'high' | 'info' {
  const severity = techniqueOf(edge)?.severity ?? 'high';
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  return 'info';
}

function nodeShortLabel(node: GraphNode): string {
  if (node.synthetic?.kind === 'cluster-admin') return 'cluster-admin';
  if (node.synthetic?.kind === 'namespace-wildcard') return `ns:${node.synthetic.namespace} 完全控制`;
  if (node.synthetic?.kind === 'read-all-secrets') return `可读 ${node.synthetic.namespace} 的 Secret`;
  if (node.base.kind === 'ServiceAccount') return `sa:${node.base.namespace}/${node.base.name}`;
  if (node.base.kind === 'Group') return `group:${node.base.name}`;
  return `user:${node.base.name}`;
}

/** Rough pixel width of a node label at 10px monospace, plus box padding. */
function nodeWidth(label: string): number {
  const shown = label.length > 26 ? 24 : label.length;
  return Math.min(Math.max(shown * 6.4 + 22, 76), 200);
}

function principalKindTag(id: string): string {
  if (id.startsWith('sa:')) return 'SA';
  if (id.startsWith('group:')) return 'GRP';
  if (id.startsWith('user:')) return 'USR';
  return '—';
}

// ---------------------------------------------------------------------------
// Hop rendering — the "逐跳依据" requirement
// ---------------------------------------------------------------------------

function EvidenceBlock({ hop }: { hop: PathHop }) {
  const { edge } = hop;
  const tech = techniqueOf(edge);
  const ev = edge.evidence;
  // The hop already lists the conditions specific to this occurrence; only add
  // catalog limitations the reader has not just seen.
  const alreadyShown = new Set([...(ev.notes ?? []), ev.action, ev.permission]);
  const extraLimitations = (tech?.limitations ?? []).filter((l) => !alreadyShown.has(l));
  return (
    <div className={`evidence ${edge.confidence}`}>
      <div className="evidence-row">
        <span className="lbl">所需权限</span>
        <span className="val">
          <span className="mono">{ev.permission}</span>
        </span>
      </div>
      {ev.source && (
        <div className="evidence-row">
          <span className="lbl">来源</span>
          <span className="val">
            <Mono>
              {ev.source.bindingKind}/{ev.source.bindingNamespace ? `${ev.source.bindingNamespace}/` : ''}
              {ev.source.bindingName}
            </Mono>{' '}
            → <Mono>{ev.source.roleKind}</Mono> <Mono>{ev.source.roleName}</Mono>
            {ev.source.roleNamespace ? <Mono>（{ev.source.roleNamespace}）</Mono> : null}
            {ev.source.origin === 'builtin' && (
              <>
                {' '}
                <Chip tone="info">内置</Chip>
              </>
            )}
          </span>
        </div>
      )}
      {ev.rule && (
        <div className="evidence-row">
          <span className="lbl">规则</span>
          <span className="val">
            <div className="rule-box">{compactRule(ev.rule)}</div>
          </span>
        </div>
      )}
      <div className="evidence-row">
        <span className="lbl">攻击动作</span>
        <span className="val">
          <Mono>{ev.action}</Mono>
        </span>
      </div>
      {ev.objects && ev.objects.length > 0 && (
        <div className="evidence-row">
          <span className="lbl">涉及对象</span>
          <span className="val pill-list">
            {ev.objects.map((o) => (
              <Chip key={o}>
                <Mono>{o}</Mono>
              </Chip>
            ))}
          </span>
        </div>
      )}
      {ev.notes && ev.notes.length > 0 && (
        <div className="evidence-row">
          <span className="lbl">前提 / 限制</span>
          <ul className="notes">
            {ev.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
      {tech && extraLimitations.length > 0 && (
        <div className="evidence-row">
          <span className="lbl">手法限制</span>
          <ul className="notes">
            {extraLimitations.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function PathView({ path, title }: { path: PathResult; title?: string }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const terminal = path.end;
  return (
    <div className="path">
      {title && <h3 style={{ fontSize: 13, marginBottom: 10 }}>{title}</h3>}
      {path.hops.map((hop, index) => {
        const tech = techniqueOf(hop.edge);
        const isOpen = expanded === index;
        return (
          <div className="hop" key={`${hop.edge.from}-${hop.edge.to}-${index}`}>
            <div className="hop-rail">
              <span className="hop-num">{index + 1}</span>
              <span className="hop-line" />
            </div>
            <div className="hop-body">
              <div className="hop-title">
                <span>{tech?.nameZh ?? hop.edge.technique}</span>
                {tech && <Chip tone={edgeTone(hop.edge)}>{SEVERITY_LABELS[tech.severity]}</Chip>}
                <Chip tone={hop.edge.confidence === 'certain' ? 'accent' : 'high'}>
                  {hop.edge.confidence === 'certain' ? '确定可行' : '需满足条件'}
                </Chip>
                {tech?.hidden && <span className="hidden-badge">隐蔽</span>}
                <span className="spacer" />
                <button className="ghost" onClick={() => setExpanded(isOpen ? null : index)}>
                  {isOpen ? '收起依据' : '展开依据'}
                </button>
              </div>
              <div className="hop-from-to">
                <b>{nodeShortLabel(hop.fromNode)}</b>
                <span aria-hidden>→</span>
                <b>{nodeShortLabel(hop.toNode)}</b>
              </div>
              {isOpen && <EvidenceBlock hop={hop} />}
            </div>
          </div>
        );
      })}
      <div className="hop" style={{ marginTop: 2 }}>
        <div className="hop-rail">
          <span className="hop-num" aria-hidden style={{ background: terminal.synthetic?.kind === 'cluster-admin' ? 'var(--critical)' : 'var(--accent)' }}>
            ✓
          </span>
        </div>
        <div className="hop-body" style={{ paddingBottom: 0 }}>
          {terminal.synthetic?.kind === 'cluster-admin' ? (
            <div className="terminal-node">
              <span className="t">到达 cluster-admin（集群管理员）</span>
              <span className="d">
                共 {path.hops.length} 跳。每一步都能在导入的 RBAC 对象中找到对应规则与主体。
              </span>
            </div>
          ) : (
            <div className="terminal-node" style={{ borderColor: 'var(--border)', background: 'var(--bg-sunken)' }}>
              <span className="t" style={{ color: 'var(--fg)' }}>
                {terminal.label}
              </span>
              <span className="d">{terminal.detail}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Paths tab
// ---------------------------------------------------------------------------

function PathsTab({ analysis }: { analysis: Analysis }) {
  const { graph } = analysis;
  const [selected, setSelected] = useState<string | null>(null);
  const [includeConditional, setIncludeConditional] = useState(true);
  const [filter, setFilter] = useState('');
  const [showAlternatives, setShowAlternatives] = useState(false);

  const allPaths = useMemo(() => pathsToClusterAdmin(graph, { includeConditional }), [graph, includeConditional]);

  const candidates = useMemo(() => {
    const ids = graph.principalIds;
    const needle = filter.trim().toLowerCase();
    const withPath = new Set(allPaths.map((p) => p.startId));
    return ids
      .filter((id) => (needle ? graph.nodes.get(id)!.label.toLowerCase().includes(needle) : true))
      .sort((a, b) => {
        const aHas = withPath.has(a) ? 0 : 1;
        const bHas = withPath.has(b) ? 0 : 1;
        if (aHas !== bHas) return aHas - bHas;
        const ap = allPaths.find((p) => p.startId === a);
        const bp = allPaths.find((p) => p.startId === b);
        if (ap && bp) return ap.path.hops.length - bp.path.hops.length;
        return graph.nodes.get(a)!.label.localeCompare(graph.nodes.get(b)!.label);
      });
  }, [graph, allPaths, filter]);

  const activeId = selected ?? allPaths[0]?.startId ?? candidates[0] ?? null;
  const activeNode = activeId ? graph.nodes.get(activeId) : null;
  const activePath = useMemo(() => {
    if (!activeId) return null;
    return shortestPath(graph, activeId, CLUSTER_ADMIN, { includeConditional });
  }, [graph, activeId, includeConditional]);
  // Enumerated eagerly so the button only appears when alternatives exist:
  // offering "查看其他路径" that opens an empty list is worse than not offering it.
  const alternatives = useMemo(() => {
    if (!activeId) return [];
    const all = enumeratePaths(graph, activeId, CLUSTER_ADMIN, { includeConditional, maxHops: 6, limit: 40 });
    // Show genuinely different routes: drop the shortest (already displayed)
    // and anything longer than necessary to demonstrate another way in.
    const best = all[0]?.hops.length ?? 0;
    // Cap the list: past a handful, the message ("closing one path is not
    // enough") has already landed and the extra rows are noise.
    return all.filter((p, i) => i > 0 && p.hops.length <= best + 3).slice(0, 5);
  }, [graph, activeId, includeConditional]);

  const byTechnique = useMemo(() => {
    const counts = new Map<string, number>();
    for (const edge of graph.edges) {
      if (edge.technique === 'implicit-group') continue;
      counts.set(edge.technique, (counts.get(edge.technique) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [graph]);

  return (
    <div className="col" style={{ gap: 16 }}>
      <Panel bodyClass="tight">
        <div className="row-wrap" style={{ gap: 20 }}>
          <Stat n={allPaths.filter((p) => p.path.hops.length === 1).length} k="一跳直达管理员" />
          <Stat n={allPaths.length} k="可达管理员的主体" />
          <Stat n={graph.principalIds.length} k="可分析主体总数" />
          <Stat n={graph.edges.length} k="提权边" />
          <Stat n={analysis.model.secrets.filter((s) => s.serviceAccountName || s.type === 'kubernetes.io/service-account-token').length} k="SA token Secret" />
        </div>
      </Panel>

      <div className="split">
        <Panel title="主体" bodyClass="tight">
          <div style={{ padding: '2px 2px 8px' }}>
            <input
              type="search"
              placeholder="搜索用户 / 组 / ServiceAccount"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          <div className="scroll-y" style={{ maxHeight: '52vh' }}>
            {candidates.length === 0 && <Empty>没有匹配的主体</Empty>}
            <div className="list">
              {candidates.map((id) => {
                const node = graph.nodes.get(id)!;
                const pathEntry = allPaths.find((p) => p.startId === id);
                return (
                  <button
                    key={id}
                    className="list-item"
                    aria-current={id === activeId}
                    onClick={() => setSelected(id)}
                  >
                    <span className="kind">{principalKindTag(id)}</span>
                    <span className="grow" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {node.base.name}
                      {node.base.kind === 'ServiceAccount' ? <span className="faint"> @{node.base.namespace}</span> : null}
                    </span>
                    {pathEntry ? (
                      <Chip tone={pathEntry.path.hops.length <= 1 ? 'critical' : 'high'}>{pathEntry.path.hops.length} 跳</Chip>
                    ) : (
                      <span className="faint" style={{ fontSize: 10 }}>
                        —
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="divider" />
          <label className="check">
            <input type="checkbox" checked={includeConditional} onChange={(e) => setIncludeConditional(e.target.checked)} />
            包含“需满足条件”的手法
          </label>
          <p className="faint" style={{ fontSize: 11, margin: '6px 0 0', lineHeight: 1.5 }}>
            判为“需满足条件”的多是依赖集群版本（如 1.24 前的长期 token Secret）、准入插件或签名器配置的手法。
          </p>
        </Panel>

        <div className="col" style={{ gap: 16 }}>
          {activeNode && (
            <Panel
              title={
                <span className="row-wrap">
                  <Mono>{nodeShortLabel(activeNode)}</Mono>
                  <Chip tone="info">{activeNode.base.kind}</Chip>
                  {activeNode.builtinOnly && <Chip>仅内置绑定</Chip>}
                </span>
              }
              actions={
                alternatives.length > 0 ? (
                  <button onClick={() => setShowAlternatives((v) => !v)}>
                    {showAlternatives ? '隐藏其他路径' : `查看其他路径（${alternatives.length}）`}
                  </button>
                ) : undefined
              }
            >
              {activePath ? (
                <PathView path={activePath} />
              ) : (
                <div className="banner">
                  <span>✕</span>
                  <span>
                    在该主体的全部绑定中找不到通往 cluster-admin 的路径。它可能只能在个别命名空间内活动，或完全没有权限。
                    {includeConditional ? '' : ' 也可能只存在于“需满足条件”的边里，试试打开上方开关。'}
                  </span>
                </div>
              )}

              {activeNode.held.length > 0 && (
                <>
                  <div className="divider" />
                  <SectionLabel>直接持有的角色</SectionLabel>
                  <div className="pill-list">
                    {activeNode.held.map((h) => (
                      <Chip key={`${h.kind}${h.name}${h.namespace ?? ''}${JSON.stringify(h.scope)}`}>
                        <Mono>{h.kind}</Mono> {h.namespace ? `${h.namespace}/` : ''}
                        {h.name}
                        <span className="faint"> · {h.scope.kind === 'cluster' ? '集群' : '命名空间'}</span>
                      </Chip>
                    ))}
                  </div>
                </>
              )}
            </Panel>
          )}

          {showAlternatives && alternatives.length > 0 && (
            <Panel title={`其他可行路径（${alternatives.length}）`}>
              <div className="col" style={{ gap: 18 }}>
                {alternatives.map((alt, i) => (
                  <div key={i}>
                    <div className="row-wrap" style={{ marginBottom: 8 }}>
                      <Chip>{alt.hops.length} 跳</Chip>
                      <span className="faint" style={{ fontSize: 11.5 }}>
                        {alt.hops.map((h) => techniqueOf(h.edge)?.nameZh ?? h.edge.technique).join(' → ')}
                      </span>
                    </div>
                    <PathView path={alt} />
                    {i < alternatives.length - 1 && <div className="divider" />}
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>

      <Panel title="按手法统计提权边">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>手法</th>
                <th>类别</th>
                <th>严重度</th>
                <th style={{ textAlign: 'right' }}>边数</th>
              </tr>
            </thead>
            <tbody>
              {byTechnique.map(([id, count]) => {
                const tech = TECHNIQUE_BY_ID.get(id);
                if (!tech) return null;
                return (
                  <tr key={id}>
                    <td>
                      {tech.nameZh}
                      {tech.hidden && (
                        <>
                          {' '}
                          <span className="hidden-badge">隐蔽</span>
                        </>
                      )}
                    </td>
                    <td className="muted">{CATEGORY_LABELS[tech.category]}</td>
                    <td>
                      <Chip tone={tech.severity === 'critical' ? 'critical' : tech.severity === 'high' ? 'high' : 'info'}>
                        {SEVERITY_LABELS[tech.severity]}
                      </Chip>
                    </td>
                    <td className="mono" style={{ textAlign: 'right' }}>
                      {count}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Secrets tab (reverse query)
// ---------------------------------------------------------------------------

function SecretsTab({ analysis }: { analysis: Analysis }) {
  const { graph, model } = analysis;
  const namespaces = useMemo(() => {
    const fromSecrets = new Set(model.secrets.map((s) => s.namespace));
    return [...new Set([...fromSecrets, ...model.namespaces])].sort();
  }, [model]);
  const [namespace, setNamespace] = useState<string>(namespaces[0] ?? '');
  const [directOnly, setDirectOnly] = useState(true);

  const readers = useMemo(() => {
    if (!namespace) return [];
    return whoCanReadSecrets(graph, namespace, { directOnly });
  }, [graph, namespace, directOnly]);

  const secretsHere = model.secrets.filter((s) => s.namespace === namespace);
  const tokenHere = secretsHere.filter((s) => s.serviceAccountName || s.type === 'kubernetes.io/service-account-token');

  const graphHasNs = graph.nodes.has(`x:secret-read:${namespace}`);

  return (
    <div className="col" style={{ gap: 16 }}>
      <Panel
        title="谁能读某个命名空间的 Secret"
        actions={
          <div className="row-wrap" style={{ gap: 12 }}>
            <label className="check">
              <input type="checkbox" checked={directOnly} onChange={(e) => setDirectOnly(e.target.checked)} />
              仅直接可读
            </label>
            <select value={namespace} onChange={(e) => setNamespace(e.target.value)} style={{ width: 'auto' }}>
              {namespaces.map((ns) => (
                <option key={ns} value={ns}>
                  {ns}
                </option>
              ))}
            </select>
          </div>
        }
      >
        <div className="row-wrap" style={{ gap: 20, marginBottom: 14 }}>
          <Stat n={readers.length} k={directOnly ? '直接可读主体' : '可达主体（含间接）'} />
          <Stat n={secretsHere.length} k="该命名空间 Secret" />
          <Stat n={tokenHere.length} k="含 SA token" />
        </div>

        {!graphHasNs && (
          <div className="banner" style={{ marginBottom: 12 }}>
            <span>i</span>
            <span>没有任何绑定允许读取该命名空间的 Secret。</span>
          </div>
        )}

        {readers.length === 0 ? (
          <Empty>没有主体{graphHasNs ? '直接' : ''}可读该命名空间的 Secret。</Empty>
        ) : (
          <div className="col" style={{ gap: 10 }}>
            {readers.map(({ startId, path }) => {
              const node = graph.nodes.get(startId)!;
              const hop = path.hops[path.hops.length - 1];
              const firstHop = path.hops[0];
              return (
                <details key={startId} className="panel" style={{ boxShadow: 'none' }}>
                  <summary
                    style={{
                      padding: '8px 12px',
                      cursor: 'pointer',
                      listStyle: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      fontSize: 12.5,
                    }}
                  >
                    <Mono>{nodeShortLabel(node)}</Mono>
                    {path.hops.length === 1 ? (
                      <Chip tone="critical">直接</Chip>
                    ) : (
                      <Chip tone="high">{path.hops.length} 跳</Chip>
                    )}
                    <span className="spacer" />
                    {path.hops.length > 1 && (
                      <span className="faint" style={{ fontSize: 11 }}>
                        先 {techniqueOf(firstHop.edge)?.nameZh ?? firstHop.edge.technique}
                      </span>
                    )}
                  </summary>
                  <div style={{ padding: '0 12px 12px' }}>
                    {path.hops.length === 1 ? (
                      <div className="evidence certain">
                        <div className="evidence-row">
                          <span className="lbl">所需权限</span>
                          <span className="val mono">{hop.edge.evidence.permission}</span>
                        </div>
                        {hop.edge.evidence.source && (
                          <div className="evidence-row">
                            <span className="lbl">来源</span>
                            <span className="val">
                              <Mono>
                                {hop.edge.evidence.source.bindingKind}/{hop.edge.evidence.source.bindingName}
                              </Mono>{' '}
                              → <Mono>{hop.edge.evidence.source.roleName}</Mono>
                            </span>
                          </div>
                        )}
                        {hop.edge.evidence.rule && (
                          <div className="evidence-row">
                            <span className="lbl">规则</span>
                            <span className="val">
                              <div className="rule-box">{compactRule(hop.edge.evidence.rule)}</div>
                            </span>
                          </div>
                        )}
                      </div>
                    ) : (
                      <PathView path={path} />
                    )}
                  </div>
                </details>
              );
            })}
          </div>
        )}
      </Panel>

      {secretsHere.length > 0 && (
        <Panel title={`${namespace} 中的 Secret`}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>类型</th>
                  <th>关联 SA</th>
                  <th>键</th>
                </tr>
              </thead>
              <tbody>
                {secretsHere.map((s) => (
                  <tr key={s.name}>
                    <td className="mono">{s.name}</td>
                    <td className="mono muted">{s.type}</td>
                    <td>
                      {s.serviceAccountName ? <Mono>{s.serviceAccountName}</Mono> : <span className="faint">—</span>}
                    </td>
                    <td className="mono faint">{s.keys.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {tokenHere.length > 0 && (
            <p className="muted" style={{ fontSize: 11.5, margin: '10px 0 0' }}>
              其中 {tokenHere.length} 个 Secret 直接携带 ServiceAccount 凭据，读取即等同取得对应身份。
            </p>
          )}
        </Panel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Graph tab
// ---------------------------------------------------------------------------

interface LayoutNode {
  id: string;
  x: number;
  y: number;
  depth: number;
  node: GraphNode;
}

function GraphTab({ analysis }: { analysis: Analysis }) {
  const [focus, setFocus] = useState<string>(CLUSTER_ADMIN);
  const [maxDepth, setMaxDepth] = useState(4);
  const [hover, setHover] = useState<string | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  // Default to the principal projection: intermediate "role acquired" nodes
  // make a whole-cluster diagram unreadable. Toggle exposes them again.
  const graph = useMemo(
    () => (showDetail ? analysis.graph : projectToPrincipals(analysis.graph)),
    [analysis.graph, showDetail],
  );

  /** BFS backwards from the focus node, so we draw "who can reach it". */
  const layout = useMemo(() => {
    const root = graph.nodes.has(focus) ? focus : CLUSTER_ADMIN;
    const depth = new Map<string, number>();
    depth.set(root, 0);
    const queue = [root];
    while (queue.length) {
      const current = queue.shift()!;
      const d = depth.get(current)!;
      if (d >= maxDepth) continue;
      for (const edge of graph.incoming.get(current) ?? []) {
        if (depth.has(edge.from)) continue;
        depth.set(edge.from, d + 1);
        queue.push(edge.from);
      }
    }

    const byDepth = new Map<number, string[]>();
    for (const [id, d] of depth) {
      if (!byDepth.has(d)) byDepth.set(d, []);
      byDepth.get(d)!.push(id);
    }

    // Lay rows out with the real node widths so wide labels never collide; the
    // canvas grows horizontally and scrolls if a row gets crowded.
    const NODE_H = 30;
    const GAP = 14;
    const PAD = 22;
    const nodes: LayoutNode[] = [];
    const rows = [...byDepth.entries()].sort((a, b) => a[0] - b[0]);
    const rowWidths = rows.map(([, ids]) =>
      ids.reduce((sum, id) => sum + nodeWidth(nodeShortLabel(graph.nodes.get(id)!)) + GAP, 0),
    );
    const canvasWidth = Math.max(560, ...rowWidths.map((w) => w + PAD * 2));

    for (const [d, ids] of rows) {
      ids.sort((a, b) => nodeShortLabel(graph.nodes.get(a)!).localeCompare(nodeShortLabel(graph.nodes.get(b)!)));
      const rowWidth = ids.reduce((sum, id) => sum + nodeWidth(nodeShortLabel(graph.nodes.get(id)!)) + GAP, 0) - GAP;
      let x = Math.max(PAD, (canvasWidth - rowWidth) / 2);
      for (const id of ids) {
        const node = graph.nodes.get(id)!;
        const w = nodeWidth(nodeShortLabel(node));
        nodes.push({ id, x: x + w / 2, y: 38 + d * 92, depth: d, node });
        x += w + GAP;
      }
    }
    return { nodes, canvasWidth, nodeHeight: NODE_H };
  }, [graph, focus, maxDepth]);

  const { nodes: layoutNodes, canvasWidth, nodeHeight } = layout;

  const positions = useMemo(() => new Map(layoutNodes.map((n) => [n.id, n])), [layoutNodes]);
  const visibleEdges = useMemo(
    () => graph.edges.filter((e) => positions.has(e.from) && positions.has(e.to)),
    [graph.edges, positions],
  );
  const height = Math.max(...layoutNodes.map((n) => n.y), 200) + 70;

  const focusOptions = useMemo(() => {
    const interesting = [
      { id: CLUSTER_ADMIN, label: 'cluster-admin（反向查看谁能到达）' },
      ...analysis.model.namespaces.map((ns) => ({ id: `x:secret-read:${ns}`, label: `可读 ${ns} 的 Secret` })),
      ...analysis.model.namespaces.map((ns) => ({ id: `x:ns-wildcard:${ns}`, label: `${ns} 完全控制` })),
    ];
    return interesting.filter((o) => graph.nodes.has(o.id));
  }, [graph, analysis.model.namespaces]);

  // A focus node can disappear when switching projections; fall back to the root.
  const effectiveFocus = graph.nodes.has(focus) ? focus : CLUSTER_ADMIN;

  if (!graph.nodes.has(effectiveFocus)) {
    return <Panel title="提权图"><Empty>当前投影下没有可绘制的节点。</Empty></Panel>;
  }

  if (layoutNodes.length <= 1) {
    return (
      <Panel title="提权图">
        <div className="row-wrap" style={{ marginBottom: 14 }}>
          <select value={focus} onChange={(e) => setFocus(e.target.value)} style={{ width: 'auto', minWidth: 260 }}>
            {focusOptions.map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </div>
        <Empty>该节点没有任何前驱（没有主体能到达它）。</Empty>
      </Panel>
    );
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      <Panel
        title="提权图（反向：谁 →
          目标）"
        actions={
          <div className="row-wrap" style={{ gap: 10 }}>
            <select value={focus} onChange={(e) => setFocus(e.target.value)} style={{ width: 'auto', minWidth: 240 }}>
              {focusOptions.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
            <label className="check">
              深度
              <select value={maxDepth} onChange={(e) => setMaxDepth(Number(e.target.value))} style={{ width: 'auto' }}>
                {[2, 3, 4, 5].map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
            <label className="check">
              <input type="checkbox" checked={showDetail} onChange={(e) => setShowDetail(e.target.checked)} />
              显示角色节点
            </label>
          </div>
        }
      >
        <div className="banner" style={{ marginBottom: 12 }}>
          <span>i</span>
          <span>
            图中每条边都是一次提权动作；悬停可看清手法与权限。只有前 {maxDepth} 跳内的前驱会被画出，节点太多时可调小深度或改用“主体”页签逐条查看。
          </span>
        </div>
        <div className="graph-canvas">
          <svg width={canvasWidth} height={height} viewBox={`0 0 ${canvasWidth} ${height}`} style={{ display: 'block', minWidth: canvasWidth }}>
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--border-strong)" />
              </marker>
              <marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--accent)" />
              </marker>
            </defs>
            {visibleEdges.map((edge, i) => {
              const a = positions.get(edge.from)!;
              const b = positions.get(edge.to)!;
              const hot = hover === edge.from || hover === edge.to;
              const midY = (a.y + b.y) / 2;
              return (
                <path
                  key={i}
                  d={`M ${a.x} ${a.y + nodeHeight / 2 + 1} C ${a.x} ${midY}, ${b.x} ${midY}, ${b.x} ${b.y - nodeHeight / 2 - 1}`}
                  fill="none"
                  stroke={hot ? 'var(--accent)' : 'var(--border-strong)'}
                  strokeWidth={hot ? 1.8 : 1.1}
                  markerEnd={hot ? 'url(#arrow-hot)' : 'url(#arrow)'}
                  opacity={hover && !hot ? 0.3 : 0.85}
                />
              );
            })}
            {layoutNodes.map((n) => {
              const isFocus = n.id === effectiveFocus;
              const isSynthetic = !!n.node.synthetic;
              const fill = isFocus
                ? 'var(--critical-soft)'
                : isSynthetic
                  ? 'var(--info-soft)'
                  : n.node.base.kind === 'ServiceAccount'
                    ? 'var(--accent-soft)'
                    : 'var(--bg-raised)';
              const stroke = isFocus ? 'var(--critical)' : isSynthetic ? 'var(--info)' : 'var(--border-strong)';
              const text = nodeShortLabel(n.node);
              const w = nodeWidth(text);
              return (
                <g
                  key={n.id}
                  onMouseEnter={() => setHover(n.id)}
                  onMouseLeave={() => setHover(null)}
                  style={{ cursor: 'pointer' }}
                >
                  <rect
                    x={n.x - w / 2}
                    y={n.y - nodeHeight / 2}
                    width={w}
                    height={nodeHeight}
                    rx={5}
                    fill={fill}
                    stroke={stroke}
                    strokeWidth={isFocus ? 1.8 : 1}
                  />
                  <text
                    x={n.x}
                    y={n.y + 4}
                    textAnchor="middle"
                    fontSize={10}
                    fontFamily="var(--mono)"
                    fill="var(--fg)"
                    style={{ pointerEvents: 'none' }}
                  >
                    {text.length > 26 ? text.slice(0, 24) + '…' : text}
                  </text>
                  {hover === n.id && (
                    <g style={{ pointerEvents: 'none' }}>
                      {(() => {
                        const boxX = Math.min(Math.max(n.x - 150, 4), canvasWidth - 304);
                        return (
                          <>
                            <rect x={boxX} y={n.y + 22} width={300} height={46} rx={4} fill="var(--bg-raised)" stroke="var(--border-strong)" />
                            <text x={boxX + 8} y={n.y + 38} fontSize={9.5} fill="var(--fg-muted)" fontFamily="var(--mono)">
                              {n.node.label.length > 46 ? n.node.label.slice(0, 44) + '…' : n.node.label}
                            </text>
                            <text x={boxX + 8} y={n.y + 54} fontSize={9.5} fill="var(--fg-faint)">
                              {new Set(n.node.held.map((h) => `${h.kind}:${h.namespace ?? ''}:${h.name}`)).size} 个角色 ·{' '}
                              {n.node.grants.length} 条规则
                              {n.node.derived ? ' · 已提权获得' : ''}
                            </text>
                          </>
                        );
                      })()}
                    </g>
                  )}
                </g>
              );
            })}
            {[...new Set(layoutNodes.map((n) => n.depth))].map((d) => (
              <text key={d} x={6} y={40 + d * 96 + 4} fontSize={9} fill="var(--fg-faint)" fontFamily="var(--mono)">
                {d === 0 ? 'target' : `+${d}`}
              </text>
            ))}
          </svg>
        </div>
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Techniques catalog tab
// ---------------------------------------------------------------------------

function TechniquesTab({ analysis }: { analysis: Analysis | null }) {
  const [category, setCategory] = useState<string>('all');
  const [query, setQuery] = useState('');
  const groups = techniquesByCategory();
  const needle = query.trim().toLowerCase();

  const usedIds = useMemo(() => {
    if (!analysis) return new Set<string>();
    return new Set(analysis.graph.edges.map((e) => e.technique));
  }, [analysis]);

  return (
    <div className="col" style={{ gap: 16 }}>
      <Panel
        title="社区公认的提权手法清单"
        actions={
          <input
            type="search"
            placeholder="搜索手法 / 权限"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ width: 220 }}
          />
        }
      >
        <div className="row-wrap" style={{ gap: 6, marginBottom: 14 }}>
          <button className={category === 'all' ? 'primary' : ''} onClick={() => setCategory('all')}>
            全部
          </button>
          {groups.map((g) => (
            <button key={g.category} className={category === g.category ? 'primary' : ''} onClick={() => setCategory(g.category)}>
              {CATEGORY_LABELS[g.category]}
            </button>
          ))}
        </div>

        <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
          每条手法都写明所需权限（<Mono>kubectl auth can-i</Mono> 的写法）、为什么足以提权、以及现实中可能失效的前提。标有
          <span className="hidden-badge" style={{ margin: '0 4px' }}>
            隐蔽
          </span>
          的条目是审计中最容易漏掉的一类：它们往往由两个看起来都无害的权限组合而成。
        </p>

        <div className="col" style={{ gap: 18 }}>
          {groups
            .filter((g) => category === 'all' || g.category === category)
            .map((g) => {
              const items = g.items.filter((t) => {
                if (!needle) return true;
                return (
                  t.nameZh.toLowerCase().includes(needle) ||
                  t.nameEn.toLowerCase().includes(needle) ||
                  t.requirement.toLowerCase().includes(needle)
                );
              });
              if (items.length === 0) return null;
              return (
                <div key={g.category}>
                  <SectionLabel>{CATEGORY_LABELS[g.category]}</SectionLabel>
                  <div className="tech-grid">
                    {items.map((t) => (
                      <article className="tech-card" key={t.id}>
                        <h3>
                          {t.nameZh}
                          <Chip tone={t.severity === 'critical' ? 'critical' : t.severity === 'high' ? 'high' : 'info'}>
                            {SEVERITY_LABELS[t.severity]}
                          </Chip>
                          {t.hidden && <span className="hidden-badge">隐蔽</span>}
                          {usedIds.has(t.id) && <Chip tone="accent">本图命中</Chip>}
                        </h3>
                        <div className="en">{t.nameEn}</div>
                        <div className="req">{t.requirement}</div>
                        <div className="why">{t.rationale}</div>
                        <div className="limits">
                          现实限制
                          <ul>
                            {t.limitations.map((l) => (
                              <li key={l}>{l}</li>
                            ))}
                          </ul>
                        </div>
                        <div className="refs">
                          {t.references.map((r) => (
                            <a key={r.url} href={r.url} target="_blank" rel="noreferrer">
                              {r.label}
                            </a>
                          ))}
                        </div>
                      </article>
                    ))}
                  </div>
                </div>
              );
            })}
        </div>
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Import tab
// ---------------------------------------------------------------------------

function ImportTab({
  yaml,
  setYaml,
  includeBootstrap,
  setIncludeBootstrap,
  analysis,
  error,
}: {
  yaml: string;
  setYaml: (v: string) => void;
  includeBootstrap: boolean;
  setIncludeBootstrap: (v: boolean) => void;
  analysis: Analysis | null;
  error: string | null;
}) {
  const [dragOver, setDragOver] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const loadFiles = useCallback(
    async (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const texts: string[] = [];
      for (const file of Array.from(files)) {
        texts.push(await file.text());
      }
      setYaml(texts.join('\n---\n'));
    },
    [setYaml],
  );

  const counts = analysis
    ? {
        clusterRoles: analysis.model.clusterRoles.size,
        roles: [...analysis.model.roles.values()].reduce((n, m) => n + m.size, 0),
        bindings: analysis.model.roleBindings.length + analysis.model.clusterRoleBindings.length,
        sa: analysis.model.serviceAccounts.length,
        pods: analysis.model.pods.length,
        secrets: analysis.model.secrets.length,
        ns: analysis.model.namespaces.length,
      }
    : null;

  const warnings = analysis?.model.diagnostics.filter((d) => d.level !== 'info') ?? [];
  const infos = analysis?.model.diagnostics.filter((d) => d.level === 'info') ?? [];

  return (
    <div className="col" style={{ gap: 16 }}>
      <Panel title="导入集群 RBAC 快照">
        <div className="col" style={{ gap: 12 }}>
          <div className="banner">
            <span>i</span>
            <span>
              支持 <Mono>kubectl get -o yaml</Mono> 的任意组合：多文档流、<Mono>kind: List</Mono> 包装、单对象粘贴均可。
              需要的对象：Role、ClusterRole、RoleBinding、ClusterRoleBinding、ServiceAccount、Pod、Secret（Namespaces 可选）。
            </span>
          </div>

          <pre style={{ fontSize: 11 }}>{`kubectl get ns,clusterroles,clusterrolebindings,roles,rolebindings,serviceaccounts,pods,secrets \\
  -A -o yaml > cluster-rbac.yaml`}</pre>

          <div
            className={`dropzone${dragOver ? ' over' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              void loadFiles(e.dataTransfer.files);
            }}
            onClick={() => fileInput.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') fileInput.current?.click();
            }}
          >
            <div className="big">把 YAML 拖进来，或点击选择文件</div>
            <div className="small">纯前端解析，数据不会离开这个页面</div>
            <input
              ref={fileInput}
              type="file"
              accept=".yaml,.yml,.json,.txt"
              multiple
              hidden
              onChange={(e) => void loadFiles(e.target.files)}
            />
          </div>

          <div className="row-wrap">
            <button onClick={() => setYaml(DEMO_YAML)}>载入示例集群</button>
            <button className="ghost" onClick={() => setYaml('')}>
              清空
            </button>
            <span className="spacer" />
            <Mono>{yaml.split('\n').length} 行</Mono>
          </div>

          <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} spellCheck={false} placeholder="在此粘贴 YAML…" />

          <label className="check">
            <input type="checkbox" checked={includeBootstrap} onChange={(e) => setIncludeBootstrap(e.target.checked)} />
            合并 API Server 内置的引导角色（cluster-admin / admin / edit / view 及其聚合标签）
          </label>
          <p className="faint" style={{ fontSize: 11.5, margin: 0, lineHeight: 1.55 }}>
            多数 <Mono>kubectl get</Mono> 导出并不包含这些角色。关掉它们会让 <Mono>bind cluster-admin</Mono> 这类路径失去终点，
            但也能让你看到“只看集群里真实存在的对象”时的结论。
          </p>
        </div>
      </Panel>

      {error && (
        <div className="banner err">
          <span>!</span>
          <span>解析失败：{error}</span>
        </div>
      )}

      {counts && (
        <Panel title="解析结果">
          <div className="row-wrap" style={{ gap: 20, marginBottom: 14 }}>
            <Stat n={counts.clusterRoles} k="ClusterRole" />
            <Stat n={counts.roles} k="Role" />
            <Stat n={counts.bindings} k="绑定" />
            <Stat n={counts.sa} k="ServiceAccount" />
            <Stat n={counts.pods} k="Pod" />
            <Stat n={counts.secrets} k="Secret" />
            <Stat n={counts.ns} k="命名空间" />
          </div>

          {warnings.length > 0 && (
            <div className="col" style={{ gap: 6, marginBottom: 10 }}>
              {warnings.slice(0, 12).map((d, i) => (
                <div key={i} className={`banner ${d.level === 'error' ? 'err' : 'warn'}`}>
                  <span>{d.level === 'error' ? '✕' : '!'}</span>
                  <span>
                    {d.object && <Mono>{d.object}</Mono>} {d.message}
                  </span>
                </div>
              ))}
              {warnings.length > 12 && <div className="faint">… 另有 {warnings.length - 12} 条</div>}
            </div>
          )}

          {infos.length > 0 && (
            <details>
              <summary className="muted" style={{ fontSize: 11.5, cursor: 'pointer' }}>
                内置补全说明（{infos.length}）
              </summary>
              <div className="col" style={{ gap: 4, marginTop: 8 }}>
                {infos.slice(0, 10).map((d, i) => (
                  <div key={i} className="faint" style={{ fontSize: 11.5 }}>
                    · {d.message}
                  </div>
                ))}
              </div>
            </details>
          )}
        </Panel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// App shell
// ---------------------------------------------------------------------------

export default function App() {
  const [yaml, setYaml] = useState<string>(DEMO_YAML);
  const [includeBootstrap, setIncludeBootstrap] = useState(true);
  const [tab, setTab] = useState<Tab>('paths');
  const [theme, setTheme] = useState<'system' | 'light' | 'dark'>(() => {
    try {
      return (localStorage.getItem('rbac-lens-theme') as 'system' | 'light' | 'dark') ?? 'system';
    } catch {
      return 'system';
    }
  });

  const deferredYaml = useDeferredValue(yaml);
  const { analysis, error } = useAnalysis(deferredYaml, includeBootstrap);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('rbac-lens-theme', theme);
    } catch {
      /* private mode: theme just doesn't persist */
    }
  }, [theme]);

  const adminCount = useMemo(
    () => (analysis ? pathsToClusterAdmin(analysis.graph).length : 0),
    [analysis],
  );

  // Without builtins, `cluster-admin` usually is not in the dump, so every path
  // terminates nowhere. Say so instead of showing an empty result list.
  const missingClusterAdmin = !!analysis && !analysis.model.clusterRoles.has('cluster-admin');

  const tabs: Array<{ id: Tab; label: string; badge?: string }> = [
    { id: 'paths', label: '提权路径', badge: adminCount ? String(adminCount) : undefined },
    { id: 'secrets', label: 'Secret 反查' },
    { id: 'graph', label: '提权图' },
    { id: 'import', label: '导入数据' },
    { id: 'techniques', label: '手法清单' },
  ];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>RBAC 提权路径分析</h1>
          <span className="sub">kubernetes role / binding / pod / serviceaccount → shortest path to cluster-admin</span>
        </div>
        <span className="spacer" />
        <div className="row-wrap">
          <label className="check">
            <input
              type="checkbox"
              checked={includeBootstrap}
              onChange={(e) => setIncludeBootstrap(e.target.checked)}
              aria-label="合并内置角色"
            />
            内置角色
          </label>
          <select
            value={theme}
            onChange={(e) => setTheme(e.target.value as typeof theme)}
            style={{ width: 'auto' }}
            aria-label="主题"
          >
            <option value="system">跟随系统</option>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </div>
      </header>

      <nav className="sidebar" aria-label="视图">
        <div className="col" style={{ gap: 2 }}>
          {tabs.map((t) => (
            <button key={t.id} className="list-item" aria-current={tab === t.id} onClick={() => setTab(t.id)}>
              <span className="grow" style={{ fontWeight: 'inherit' }}>
                {t.label}
              </span>
              {t.badge && <Chip tone="critical">{t.badge}</Chip>}
            </button>
          ))}
        </div>

        <div className="divider" />

        {analysis ? (
          <>
            <SectionLabel>当前数据</SectionLabel>
            <div className="col" style={{ gap: 3, fontSize: 11.5 }}>
              <span className="muted">
                {analysis.graph.principalIds.length} 个可分析主体
              </span>
              <span className="muted">{analysis.graph.edges.length} 条提权边</span>
              <span className="muted">
                {analysis.model.namespaces.length} 个命名空间
              </span>
            </div>
            {adminCount > 0 ? (
              <div className="banner err" style={{ marginTop: 10, fontSize: 11 }}>
                <span>!</span>
                <span>{adminCount} 个主体存在通往 cluster-admin 的路径</span>
              </div>
            ) : (
              <div className="banner" style={{ marginTop: 10, fontSize: 11 }}>
                <span>✓</span>
                <span>未发现通往 cluster-admin 的路径</span>
              </div>
            )}
          </>
        ) : (
          <p className="faint" style={{ fontSize: 11.5 }}>
            尚未导入数据。
          </p>
        )}

        <div className="divider" />
        <p className="faint" style={{ fontSize: 10.5, lineHeight: 1.6, margin: 0 }}>
          全部计算在浏览器内完成。结论基于静态 RBAC 语义，未考虑 Admission Webhook、NodeRestriction
          等运行时约束，重要结论请用 <Mono>kubectl auth can-i</Mono> 复核。
        </p>
      </nav>

      <main className="main">
        {error && (
          <div className="banner err" style={{ marginBottom: 14 }}>
            <span>!</span>
            <span>YAML 解析失败：{error}</span>
          </div>
        )}

        {tab === 'paths' && missingClusterAdmin && (
          <div className="banner warn" style={{ marginBottom: 14 }}>
            <span>!</span>
            <span>
              当前数据里没有 <Mono>cluster-admin</Mono> 这个 ClusterRole，所有路径都无法判定终点。
              勾选顶部的“内置角色”，或从集群导出时包含 <Mono>kubectl get clusterroles -A -o yaml</Mono>。
            </span>
          </div>
        )}
        {tab === 'paths' && (analysis ? <PathsTab analysis={analysis} /> : <Empty>先在“导入数据”页粘贴 YAML，或载入示例。</Empty>)}
        {tab === 'secrets' && (analysis ? <SecretsTab analysis={analysis} /> : <Empty>尚无数据。</Empty>)}
        {tab === 'graph' && (analysis ? <GraphTab analysis={analysis} /> : <Empty>尚无数据。</Empty>)}
        {tab === 'import' && (
          <ImportTab
            yaml={yaml}
            setYaml={setYaml}
            includeBootstrap={includeBootstrap}
            setIncludeBootstrap={setIncludeBootstrap}
            analysis={analysis}
            error={error}
          />
        )}
        {tab === 'techniques' && <TechniquesTab analysis={analysis} />}
      </main>
    </div>
  );
}

void principalId;
void principalLabel;
