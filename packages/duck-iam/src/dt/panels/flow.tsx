import React from 'react'
import { Refresh } from '../components/icons'
import { JsonTree } from '../components/json-tree'
import { DetailEmpty, FilterBar, ListItem, ListShell, Section, SplitView } from '../components/layout'
import { Badge, Button } from '../components/ui'
import { cn } from '../lib/cn'
import type { IamIFlowEntry, IamIFlowRecorder } from '../lib/flow'
import { useIamDevtoolsStyles } from '../lib/styles'

function pad(n: number, w = 2) {
  return String(n).padStart(w, '0')
}
function fmtTime(ts: number) {
  const d = new Date(ts)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}
function fmtAgo(ts: number, now: number) {
  const ms = Math.max(0, now - ts)
  if (ms < 1000) return `${ms}ms ago`
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`
  return `${Math.floor(ms / 3_600_000)}h ago`
}

function ActionChip({ action }: { action: string }) {
  return <code className="iam-dt-chip iam-dt-chip--action">{action}</code>
}
function ResourceChip({ resource, resourceId }: { resource: string; resourceId?: string }) {
  return (
    <code className="iam-dt-chip iam-dt-chip--resource">
      {resource}
      {resourceId && <span className="iam-dt-chip__id">#{resourceId}</span>}
    </code>
  )
}
function SubjectChip({ id }: { id: string }) {
  const initial = id.replace(/^u-/, '').charAt(0).toUpperCase() || '?'
  return (
    <div className="iam-dt-subject">
      <span aria-hidden className="iam-dt-subject__avatar">
        {initial}
      </span>
      <code>{id}</code>
    </div>
  )
}

/**
 * The live decision log from an {@link IamIFlowRecorder}: newest first, with allow/deny filters and a detail pane.
 * Never calls the engine, so opening it cannot perturb what it measures.
 */
export function IamFlowPanel({ flow }: { flow: IamIFlowRecorder }) {
  useIamDevtoolsStyles()
  const [entries, setEntries] = React.useState<readonly IamIFlowEntry[]>(() => flow.list())
  const [selected, setSelected] = React.useState<number | null>(null)
  const [filter, setFilter] = React.useState('')
  const [showAllow, setShowAllow] = React.useState(true)
  const [showDeny, setShowDeny] = React.useState(true)
  const [now, setNow] = React.useState(Date.now())
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => {
    const off = flow.subscribe(() => setEntries(flow.list().slice()))
    return off
  }, [flow])
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const q = filter.trim().toLowerCase()
  const filtered = entries.filter((e) => {
    if (!showAllow && e.allowed) return false
    if (!showDeny && !e.allowed) return false
    if (!q) return true
    return (
      e.subjectId.toLowerCase().includes(q) ||
      e.action.toLowerCase().includes(q) ||
      e.resource.toLowerCase().includes(q) ||
      (e.resourceId ?? '').toLowerCase().includes(q)
    )
  })

  const current = selected != null ? (flow.get(selected) ?? null) : null
  const counts = React.useMemo(() => {
    let allow = 0,
      deny = 0
    for (const e of entries) e.allowed ? allow++ : deny++
    return { allow, deny }
  }, [entries])

  const copyEntry = async () => {
    if (!current) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(current, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {}
  }

  return (
    <SplitView
      left={
        <ListShell
          count={filtered.length}
          title="Flow"
          toolbar={
            <Button onClick={() => flow.clear()}>
              <Refresh size={10} /> clear
            </Button>
          }>
          <FilterBar onChange={setFilter} placeholder="Filter by subject, action, resource" value={filter} />
          <div className="iam-dt-flow__filters">
            <FilterPill active={showAllow} onClick={() => setShowAllow((v) => !v)} tone="allow">
              allow <span className="iam-dt-pill__count">{counts.allow}</span>
            </FilterPill>
            <FilterPill active={showDeny} onClick={() => setShowDeny((v) => !v)} tone="deny">
              deny <span className="iam-dt-pill__count">{counts.deny}</span>
            </FilterPill>
          </div>
          {filtered.length === 0 && (
            <DetailEmpty
              message={
                entries.length === 0
                  ? 'No access checks recorded yet. Interact with the app to see live flow.'
                  : 'No matches.'
              }
            />
          )}
          {filtered.map((e) => (
            <ListItem
              active={selected === e.id}
              dot={e.allowed ? '#84cc16' : '#ef4444'}
              key={e.id}
              onClick={() => setSelected(e.id)}
              primary={
                <span className="iam-dt-row" style={{ gap: 6 }}>
                  <span className="iam-dt-action">{e.action}</span>
                  <span className="iam-dt-soft">on</span>
                  <span className="iam-dt-resource">{e.resource}</span>
                  {e.resourceId && <span className="iam-dt-soft">#{e.resourceId}</span>}
                </span>
              }
              secondary={
                <span className="iam-dt-row" style={{ gap: 6 }}>
                  {e.subjectId}
                  <Dot />
                  {fmtAgo(e.ts, now)}
                  {typeof e.durationMs === 'number' && (
                    <>
                      <Dot />
                      {e.durationMs.toFixed(1)}ms
                    </>
                  )}
                </span>
              }
            />
          ))}
        </ListShell>
      }
      right={
        !current ? (
          <DetailEmpty message="Pick a check on the left to inspect." />
        ) : (
          <div className="iam-dt-frame">
            <header className="iam-dt-flow__head">
              <Badge tone={current.allowed ? 'allow' : 'deny'}>{current.allowed ? 'allow' : 'deny'}</Badge>
              <ActionChip action={current.action} />
              <span className="iam-dt-soft">on</span>
              <ResourceChip resource={current.resource} resourceId={current.resourceId} />
              <span className="iam-dt-flow__time">
                {fmtTime(current.ts)}
                {typeof current.durationMs === 'number' && (
                  <>
                    <Dot />
                    {current.durationMs.toFixed(2)}ms
                  </>
                )}
              </span>
            </header>
            <div className="iam-dt-flow__scroll">
              <Section title="Subject">
                <div className="iam-dt-row">
                  <SubjectChip id={current.subjectId} />
                  {current.scope && <Badge tone="info">scope: {current.scope}</Badge>}
                </div>
              </Section>
              {current.reason && (
                <Section title="Reason">
                  <p className="iam-dt-flow__reason">{current.reason}</p>
                </Section>
              )}
              {(current.decidingPolicy || current.decidingRule) && (
                <Section title="Deciding">
                  <div className="iam-dt-row">
                    {current.decidingPolicy && <Kv k="policy" v={current.decidingPolicy} />}
                    {current.decidingRule && <Kv k="rule" v={current.decidingRule} />}
                  </div>
                </Section>
              )}
              {current.environment && Object.keys(current.environment).length > 0 && (
                <Section defaultOpen={false} title="Environment">
                  <JsonTree data={current.environment} defaultOpen />
                </Section>
              )}
              <Section defaultOpen={false} title="Raw entry">
                <JsonTree data={current} defaultOpen />
              </Section>
            </div>
            <footer className="iam-dt-flow__foot">
              <Button onClick={copyEntry} variant="ghost">
                {copied ? 'copied' : 'copy entry'}
              </Button>
            </footer>
          </div>
        )
      }
    />
  )
}

function FilterPill({
  active,
  tone,
  onClick,
  children,
}: {
  active: boolean
  tone: 'allow' | 'deny'
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      aria-pressed={active}
      className={cn('iam-dt-pill', tone === 'allow' ? 'iam-dt-pill--allow' : 'iam-dt-pill--deny')}
      onClick={onClick}
      type="button">
      {children}
    </button>
  )
}

function Dot() {
  return <span aria-hidden className="iam-dt-dot" />
}

function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div className="iam-dt-kv">
      <span className="iam-dt-kv__k">{k}</span>
      <code className="iam-dt-kv__v">{v}</code>
    </div>
  )
}
