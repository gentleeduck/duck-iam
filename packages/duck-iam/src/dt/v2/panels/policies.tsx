'use client'

import { cn } from '@gentleduck/libs/cn'
import { FileText } from 'lucide-react'
import type { AccessControl } from '../../../core/types'
import { isDevtoolsAllowed } from '../../lib/guard'
import { useIamListPanel } from '../../lib/list-panel'
import type { IamEnginePanelProps } from '../../lib/types'
import {
  IamV2Chip,
  IamV2DescriptionSection,
  IamV2Disclosure,
  IamV2Empty,
  IamV2ListRow,
  IamV2PaneBody,
  IamV2Root,
  IamV2Section,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IamV2ListBrowser } from '../components/list-browser'
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
export function IamPoliciesPanelV2({ engine }: IamEnginePanelProps) {
  const { current, error, filter, filtered, items, loading, reload, selected, setFilter, setSelected } =
    useIamListPanel<AccessControl.IPolicy>(() => engine.admin.listPolicies())

  // Below every hook. Guarded here, not only in the shell, because the panel is exported alone.
  if (!isDevtoolsAllowed(engine)) return null

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
                <IamV2DescriptionSection text={current.description} />
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
          <IamV2ListBrowser
            emptyIcon={<FileText />}
            error={error}
            filter={filter}
            filtered={filtered}
            items={items}
            loading={loading}
            noun="policies"
            reload={reload}
            reloadLabel="Reload policies"
            renderRow={(policy) => (
              <IamV2ListRow
                active={selected === policy.id}
                description={`${policy.rules.length} rules · ${policy.algorithm}`}
                key={policy.id}
                onSelect={() => setSelected(policy.id)}
                title={<code className={IAM_V2_MONO}>{policy.id}</code>}
                tone="info"
                trailing={<IamV2Chip tone="neutral">{policy.rules.length}</IamV2Chip>}
              />
            )}
            searchPlaceholder="Filter policies"
            setFilter={setFilter}
            title="Policies"
          />
        }
      />
    </IamV2Root>
  )
}
