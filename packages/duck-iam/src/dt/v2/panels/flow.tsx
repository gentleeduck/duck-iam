'use client'

import { cn } from '@gentleduck/libs/cn'
import { Button } from '@gentleduck/registry-ui/button'
import { Separator } from '@gentleduck/registry-ui/separator'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@gentleduck/registry-ui/table'
import { Check, Copy, Radio, Trash2 } from 'lucide-react'
import React from 'react'
import type { IamIFlowEntry, IamIFlowRecorder } from '../../lib/flow'
import {
  IamV2Action,
  IamV2Avatar,
  IamV2Chip,
  IamV2Empty,
  IamV2Hint,
  IamV2Kv,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Search,
  IamV2Section,
  IamV2Split,
  IamV2Toggle,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE, iamV2Decision, iamV2Dot } from '../lib/tone'

function pad(value: number, width = 2): string {
  return String(value).padStart(width, '0')
}

/** `14:03:11.482` - wall-clock, to line a decision up against an app log. */
function clockTime(ts: number): string {
  const d = new Date(ts)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

/** Coarse relative age, re-rendered once a second by the panel's own ticker. */
function relativeAge(ts: number, now: number): string {
  const ms = Math.max(0, now - ts)
  if (ms < 1000) return `${ms}ms ago`
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`
  return `${Math.floor(ms / 3_600_000)}h ago`
}

/**
 * One decision as a table row.
 * NOTE: a real `button` stretched over the row keeps it keyboard-reachable, which a clickable `tr` is not.
 */
function FlowRow({
  active,
  entry,
  now,
  onSelect,
}: {
  active: boolean
  entry: IamIFlowEntry
  now: number
  onSelect: () => void
}) {
  const verdict = entry.allowed ? 'allow' : 'deny'
  return (
    <TableRow className="relative cursor-pointer border-border" data-state={active ? 'selected' : undefined}>
      <TableCell className="w-px p-0 ps-3">
        <button
          aria-current={active ? 'true' : undefined}
          className="after:absolute after:inset-0 focus-visible:outline-none focus-visible:after:ring-1 focus-visible:after:ring-ring focus-visible:after:ring-inset"
          onClick={onSelect}
          type="button">
          <span className="sr-only">{`${verdict}: ${entry.action} on ${entry.resource} for ${entry.subjectId}`}</span>
          <span aria-hidden className={cn('block size-1.5 rounded-full', iamV2Dot(iamV2Decision(entry.allowed)))} />
        </button>
      </TableCell>
      <TableCell className="py-1.5 ps-2 pe-3">
        <IamV2Chip tone={iamV2Decision(entry.allowed)}>{verdict}</IamV2Chip>
      </TableCell>
      <TableCell className="max-w-0 truncate px-3 py-1.5">
        <span className={IAM_V2_MONO}>
          <span className={IAM_V2_ACTION}>{entry.action}</span>
          <span className="text-muted-foreground"> on </span>
          <span className={IAM_V2_RESOURCE}>{entry.resource}</span>
          {entry.resourceId && <span className="text-muted-foreground">#{entry.resourceId}</span>}
        </span>
      </TableCell>
      <TableCell className="hidden px-3 py-1.5 sm:table-cell">
        <span className="flex items-center gap-1.5">
          <IamV2Avatar id={entry.subjectId} />
          <code className={cn(IAM_V2_MONO, 'truncate text-muted-foreground')}>{entry.subjectId}</code>
        </span>
      </TableCell>
      <TableCell className="hidden whitespace-nowrap px-3 py-1.5 text-end text-[0.6875rem] text-muted-foreground tabular-nums md:table-cell">
        {relativeAge(entry.ts, now)}
      </TableCell>
      <TableCell className="whitespace-nowrap px-3 py-1.5 text-end text-[0.6875rem] text-muted-foreground tabular-nums">
        {typeof entry.durationMs === 'number' ? `${entry.durationMs.toFixed(1)}ms` : '—'}
      </TableCell>
    </TableRow>
  )
}

/**
 * Live decision log from the {@link IamIFlowRecorder}, with verdict filters and a detail pane.
 * Takes no engine, so it carries no devtools guard; `side="end"` gives the table the flexible column.
 */
export function IamFlowPanelV2({ flow }: { flow: IamIFlowRecorder }) {
  const [entries, setEntries] = React.useState<readonly IamIFlowEntry[]>(() => flow.list())
  const [selected, setSelected] = React.useState<number | null>(null)
  const [filter, setFilter] = React.useState('')
  const [showAllow, setShowAllow] = React.useState(true)
  const [showDeny, setShowDeny] = React.useState(true)
  const [now, setNow] = React.useState(() => Date.now())
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => flow.subscribe(() => setEntries(flow.list())), [flow])
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const query = filter.trim().toLowerCase()
  const filtered = entries.filter((entry) => {
    if (!showAllow && entry.allowed) return false
    if (!showDeny && !entry.allowed) return false
    if (!query) return true
    return (
      entry.subjectId.toLowerCase().includes(query) ||
      entry.action.toLowerCase().includes(query) ||
      entry.resource.toLowerCase().includes(query) ||
      (entry.resourceId ?? '').toLowerCase().includes(query)
    )
  })

  const counts = React.useMemo(() => {
    let allow = 0
    let deny = 0
    for (const entry of entries) {
      if (entry.allowed) allow++
      else deny++
    }
    return { allow, deny }
  }, [entries])

  const current = selected === null ? null : (flow.get(selected) ?? null)

  const copyEntry = () => {
    if (!current) return
    void navigator.clipboard
      .writeText(JSON.stringify(current, null, 2))
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      })
      // Clipboard is permission-gated and missing over plain http; swallow rather than leak an unhandled rejection.
      .catch(() => setCopied(false))
  }

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          !current ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-4">
              <IamV2Empty
                description="Pick a check to see the subject, the reason and the rule that decided it."
                icon={<Radio />}
                title="No check selected"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <IamV2Chip tone={iamV2Decision(current.allowed)}>{current.allowed ? 'allow' : 'deny'}</IamV2Chip>
                <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{current.action}</code>
                <span className="text-muted-foreground text-xs">on</span>
                <code className={cn(IAM_V2_MONO, IAM_V2_RESOURCE)}>
                  {current.resource}
                  {current.resourceId && <span className="text-muted-foreground">#{current.resourceId}</span>}
                </code>
                <span className="ms-auto text-[0.6875rem] text-muted-foreground tabular-nums">
                  {clockTime(current.ts)}
                  {typeof current.durationMs === 'number' && ` · ${current.durationMs.toFixed(2)}ms`}
                </span>
              </div>
              <IamV2PaneBody>
                <IamV2Section title="Subject">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/40 py-0.5 ps-1 pe-2">
                      <IamV2Avatar id={current.subjectId} />
                      <code className={IAM_V2_MONO}>{current.subjectId}</code>
                    </span>
                    {current.scope && <IamV2Kv label="scope" value={current.scope} />}
                  </div>
                </IamV2Section>
                {current.reason && (
                  <IamV2Section title="Reason">
                    <p className="text-muted-foreground text-xs leading-relaxed">{current.reason}</p>
                  </IamV2Section>
                )}
                {(current.decidingPolicy || current.decidingRule) && (
                  <IamV2Section title="Deciding">
                    <div className="flex flex-wrap gap-2">
                      {current.decidingPolicy && <IamV2Kv label="policy" value={current.decidingPolicy} />}
                      {current.decidingRule && <IamV2Kv label="rule" value={current.decidingRule} />}
                    </div>
                  </IamV2Section>
                )}
                {current.environment && Object.keys(current.environment).length > 0 && (
                  <IamV2Section defaultOpen={false} title="Environment">
                    <IamV2Json data={current.environment} />
                  </IamV2Section>
                )}
                <IamV2Section defaultOpen={false} title="Raw entry">
                  <IamV2Json data={current} />
                </IamV2Section>
                <div>
                  <Button className="h-7 gap-1.5 px-2 text-xs" onClick={copyEntry} size="sm" variant="outline">
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? 'copied' : 'copy entry'}
                  </Button>
                </div>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <>
            <IamV2PaneHeader
              actions={
                <IamV2Action label="Clear recorded decisions" onClick={() => flow.clear()}>
                  <Trash2 size={12} />
                  clear
                </IamV2Action>
              }
              count={filtered.length}
              title="Flow"
            />
            <div className="flex shrink-0 flex-wrap items-center gap-3 border-border border-b p-3">
              <div className="min-w-[16rem] flex-1">
                <IamV2Search onChange={setFilter} placeholder="Filter by subject, action or resource" value={filter} />
              </div>
              <IamV2Toggle
                checked={showAllow}
                count={counts.allow}
                label="allow"
                onChange={setShowAllow}
                tone="allow"
              />
              <IamV2Toggle checked={showDeny} count={counts.deny} label="deny" onChange={setShowDeny} tone="deny" />
              <Separator className="hidden h-4 lg:block" orientation="vertical" />
              <IamV2Hint keys={['Tab', '␣']}>to open a row</IamV2Hint>
            </div>
            {filtered.length === 0 ? (
              <div className="flex min-h-0 flex-1 items-center justify-center p-6">
                <IamV2Empty
                  description={
                    entries.length === 0
                      ? 'Bind the recorder to your engine’s afterEvaluate hook, then use the app.'
                      : 'No recorded check matches the current filter.'
                  }
                  icon={<Radio />}
                  title={entries.length === 0 ? 'Nothing recorded yet' : 'No matches'}
                />
              </div>
            ) : (
              <div className="min-h-0 flex-1 overflow-auto">
                {/* No sticky header: `Table` wraps itself in its own `overflow-auto`, so `sticky` never engages. */}
                <Table className="text-xs">
                  <TableHeader className="bg-card">
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="w-px p-0">
                        <span className="sr-only">select</span>
                      </TableHead>
                      <TableHead className="h-8 ps-2 pe-3 text-[0.625rem] uppercase tracking-wider">verdict</TableHead>
                      <TableHead className="h-8 px-3 text-[0.625rem] uppercase tracking-wider">request</TableHead>
                      <TableHead className="hidden h-8 px-3 text-[0.625rem] uppercase tracking-wider sm:table-cell">
                        subject
                      </TableHead>
                      <TableHead className="hidden h-8 px-3 text-end text-[0.625rem] uppercase tracking-wider md:table-cell">
                        when
                      </TableHead>
                      <TableHead className="h-8 px-3 text-end text-[0.625rem] uppercase tracking-wider">took</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((entry) => (
                      <FlowRow
                        active={selected === entry.id}
                        entry={entry}
                        key={entry.id}
                        now={now}
                        onSelect={() => setSelected(entry.id)}
                      />
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </>
        }
        side="end"
      />
    </IamV2Root>
  )
}
