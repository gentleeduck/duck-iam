'use client'

import { cn } from '@gentleduck/libs/cn'
import { FileText, RefreshCw } from 'lucide-react'
import React from 'react'
import type { AccessControl } from '../../../core/types'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDevtoolsEngine } from '../../lib/types'
import {
  IamV2Action,
  IamV2Alert,
  IamV2Chip,
  IamV2Disclosure,
  IamV2Empty,
  IamV2ListRow,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Search,
  IamV2Section,
  IamV2SkeletonRows,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE } from '../lib/tone'

/** One rule, collapsed to its effect / priority / action / resource line. */
function RuleRow({ rule }: { rule: AccessControl.IRule }) {
  return (
    <IamV2Disclosure
      summary={
        <>
          <code className={cn(IAM_V2_MONO, 'text-foreground')}>{rule.id}</code>
          <IamV2Chip tone={rule.effect === 'allow' ? 'allow' : 'deny'}>{rule.effect}</IamV2Chip>
          <IamV2Chip tone="neutral">p{rule.priority}</IamV2Chip>
          <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{rule.actions.join(', ')}</code>
          <span className="text-muted-foreground text-xs">on</span>
          <code className={cn(IAM_V2_MONO, IAM_V2_RESOURCE)}>{rule.resources.join(', ')}</code>
        </>
      }>
      {rule.description && <p className="text-muted-foreground text-xs leading-relaxed">{rule.description}</p>}
      {rule.conditions && <IamV2Json data={rule.conditions} label="conditions" />}
    </IamV2Disclosure>
  )
}

/** Read-only browser for the adapter's policies, re-read via `engine.admin.listPolicies()` on each refresh. */
export function IamPoliciesPanelV2({ engine }: { engine: IamIDevtoolsEngine }) {
  const [policies, setPolicies] = React.useState<AccessControl.IPolicy[]>([])
  const [selected, setSelected] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [filter, setFilter] = React.useState('')
  const [loading, setLoading] = React.useState(true)

  const load = React.useCallback(async () => {
    try {
      setError(null)
      setLoading(true)
      setPolicies(await engine.admin.listPolicies())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [engine])

  React.useEffect(() => {
    void load()
  }, [load])

  // Below every hook. Guarded here, not only in the shell, because the panel is exported alone.
  if (!isDevtoolsAllowed(engine)) return null

  const query = filter.trim().toLowerCase()
  const filtered = policies.filter(
    (policy) => policy.id.toLowerCase().includes(query) || (policy.name ?? '').toLowerCase().includes(query),
  )
  const current = policies.find((policy) => policy.id === selected) ?? null

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          !current ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Choose a policy on the left to read its rules and conditions."
                icon={<FileText />}
                title="No policy selected"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <code className={cn(IAM_V2_MONO, 'font-medium text-foreground')}>{current.id}</code>
                {current.name && <span className="text-muted-foreground text-xs">{current.name}</span>}
                <IamV2Chip tone="info">{current.algorithm}</IamV2Chip>
                {current.version != null && <IamV2Chip tone="neutral">v{current.version}</IamV2Chip>}
                <span className="ms-auto text-[0.6875rem] text-muted-foreground tabular-nums">
                  {current.rules.length} rules
                </span>
              </div>
              <IamV2PaneBody>
                {current.description && (
                  <IamV2Section title="Description">
                    <p className="text-muted-foreground text-xs leading-relaxed">{current.description}</p>
                  </IamV2Section>
                )}
                <IamV2Section title={`Rules (${current.rules.length})`}>
                  <div className="flex flex-col gap-1.5">
                    {current.rules.map((rule) => (
                      <RuleRow key={rule.id} rule={rule} />
                    ))}
                  </div>
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Raw policy">
                  <IamV2Json data={current} />
                </IamV2Section>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <>
            <IamV2PaneHeader
              actions={
                <IamV2Action label="Reload policies" onClick={() => void load()}>
                  <RefreshCw size={12} />
                  refresh
                </IamV2Action>
              }
              count={filtered.length}
              title="Policies"
            />
            <div className="shrink-0 border-border border-b p-3">
              <IamV2Search onChange={setFilter} placeholder="Filter policies" value={filter} />
            </div>
            <IamV2PaneBody className="gap-1">
              {error && <IamV2Alert tone="error">{error}</IamV2Alert>}
              {!error && loading && policies.length === 0 && <IamV2SkeletonRows />}
              {!error && !loading && filtered.length === 0 && (
                <IamV2Empty
                  description={policies.length === 0 ? 'The adapter holds no policies.' : 'Nothing matches the filter.'}
                  icon={<FileText />}
                  title={policies.length === 0 ? 'No policies' : 'No matches'}
                />
              )}
              {filtered.map((policy) => (
                <IamV2ListRow
                  active={selected === policy.id}
                  description={`${policy.rules.length} rules · ${policy.algorithm}`}
                  key={policy.id}
                  onSelect={() => setSelected(policy.id)}
                  title={<code className={IAM_V2_MONO}>{policy.id}</code>}
                  tone="info"
                  trailing={<IamV2Chip tone="neutral">{policy.rules.length}</IamV2Chip>}
                />
              ))}
            </IamV2PaneBody>
          </>
        }
      />
    </IamV2Root>
  )
}
