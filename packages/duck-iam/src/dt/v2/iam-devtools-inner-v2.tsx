'use client'

import { cn } from '@gentleduck/libs/cn'
import { Separator } from '@gentleduck/registry-ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@gentleduck/registry-ui/tabs'
import { Activity, FileText, Gauge, ScanSearch, ShieldCheck, UserRound, Users } from 'lucide-react'
import React from 'react'
import type { IamIFlowRecorder } from '../lib/flow'
import { isDevtoolsAllowed } from '../lib/guard'
import type { IamIDecisionInput, IamIDevtoolsEngine, IamIDevtoolsMetrics, IamPanelKey } from '../lib/types'
import { IamV2Empty, IamV2Hint, IamV2Root } from './components/chrome'
import { type IamV2Tone, iamV2Dot } from './lib/tone'
import { IamDecisionInspectorV2 } from './panels/decision'
import { IamFlowPanelV2 } from './panels/flow'
import { IamMetricsPanelV2 } from './panels/metrics'
import { IamPoliciesPanelV2 } from './panels/policies'
import { IamRolesPanelV2 } from './panels/roles'
import { IamSubjectsPanelV2 } from './panels/subjects'

/**
 * Props for the v2 panel body - the tab strip and whichever panel is open.
 *
 * Deliberately the same shape as v1's `IIamDevtoolsInnerProps` minus `theme`:
 * v2 has no palette to pin, because it renders in the host's duck-ui theme by
 * construction. `engine` is the only requirement; `metrics` and `flow` are
 * opt-in wiring on the consumer's side and their tabs say so when absent.
 */
export interface IIamDevtoolsInnerV2Props {
  defaultRequest?: Partial<IamIDecisionInput>
  embedded?: boolean
  engine: IamIDevtoolsEngine
  flow?: IamIFlowRecorder
  initialPanel?: IamPanelKey
  metrics?: IamIDevtoolsMetrics
  pollMs?: number
}

const TABS: readonly { icon: React.ReactNode; key: IamPanelKey; label: string; tone: IamV2Tone }[] = [
  { icon: <Activity size={13} />, key: 'flow', label: 'Flow', tone: 'allow' },
  { icon: <ScanSearch size={13} />, key: 'decision', label: 'Decision', tone: 'info' },
  { icon: <FileText size={13} />, key: 'policies', label: 'Policies', tone: 'info' },
  { icon: <Users size={13} />, key: 'roles', label: 'Roles', tone: 'allow' },
  { icon: <UserRound size={13} />, key: 'subjects', label: 'Subjects', tone: 'warn' },
  { icon: <Gauge size={13} />, key: 'metrics', label: 'Metrics', tone: 'deny' },
]

/**
 * Hard-no in production: the admin reads behind these tabs would leak the full
 * auth model. No prop escape hatch by design - see `lib/guard.ts`. The guard
 * sits in a thin wrapper so the inner component's hook order is unconditional.
 */
export function IamDevtoolsInnerV2(props: IIamDevtoolsInnerV2Props) {
  if (!isDevtoolsAllowed(props.engine)) return null
  return <Impl {...props} />
}

function Impl({
  defaultRequest,
  embedded = false,
  engine,
  flow,
  initialPanel = 'flow',
  metrics,
  pollMs,
}: IIamDevtoolsInnerV2Props) {
  const [active, setActive] = React.useState<IamPanelKey>(initialPanel)
  const triggers = React.useRef(new Map<IamPanelKey, HTMLButtonElement>())

  /**
   * Arrow keys move between tabs, Home/End jump to the ends.
   *
   * duck-ui's `TabsTrigger` puts only the selected tab in the tab order, which
   * is the correct half of the tablist pattern - but it ships no roving focus
   * of its own, so without this the other five panels are unreachable from the
   * keyboard and the strip announces a contract it does not honour.
   */
  const onKeyDown = (event: React.KeyboardEvent) => {
    const index = TABS.findIndex((tab) => tab.key === active)
    let next = -1
    if (event.key === 'ArrowRight') next = (index + 1) % TABS.length
    else if (event.key === 'ArrowLeft') next = (index - 1 + TABS.length) % TABS.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = TABS.length - 1
    const tab = next >= 0 ? TABS[next] : undefined
    if (!tab) return
    event.preventDefault()
    setActive(tab.key)
    triggers.current.get(tab.key)?.focus()
  }

  return (
    <IamV2Root className={cn('min-h-0 flex-1', !embedded && 'h-full rounded-lg border border-border')}>
      <Tabs
        className="flex min-h-0 flex-1 flex-col"
        defaultValue={initialPanel}
        onValueChange={(value) => {
          // `IamPanelKey` is closed, and this callback is typed `string`
          // because the component cannot know the caller's union. Narrow by
          // membership rather than assert - a value that is not one of ours
          // means the strip changed underneath us, and rendering no panel
          // beats rendering the wrong one.
          const tab = TABS.find((candidate) => candidate.key === value)
          if (tab) setActive(tab.key)
        }}>
        {/* The strip keeps duck-ui's own `TabsList` look - a pill row on
            `bg-muted` - rather than being flattened into a bar, so the devtool
            reads as a piece of the host's UI kit. Only the density changes. */}
        <div className="flex shrink-0 items-center gap-2 overflow-x-auto border-border border-b bg-card px-2 py-1.5">
          <span className="hidden select-none items-center gap-1.5 ps-1 pe-1 font-medium text-[0.6875rem] text-muted-foreground uppercase tracking-wider md:inline-flex">
            <ShieldCheck aria-hidden size={13} />
            iam
          </span>
          <Separator className="hidden h-5 md:block" orientation="vertical" />
          <TabsList aria-label="duck-iam devtools panels" className="shrink-0 gap-0.5 p-0.5" onKeyDown={onKeyDown}>
            {TABS.map((tab) => (
              <TabsTrigger
                className="h-7 gap-1.5 px-2.5 text-xs"
                key={tab.key}
                ref={(node) => {
                  if (node) triggers.current.set(tab.key, node)
                  else triggers.current.delete(tab.key)
                }}
                value={tab.key}>
                <span aria-hidden className={cn('size-1.5 rounded-full', iamV2Dot(tab.tone))} />
                <span aria-hidden className="hidden text-muted-foreground sm:inline">
                  {tab.icon}
                </span>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
          <span className="ms-auto hidden shrink-0 lg:inline-flex">
            <IamV2Hint keys={['←', '→']}>between panels</IamV2Hint>
          </span>
        </div>

        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="flow">
          {flow ? (
            <IamFlowPanelV2 flow={flow} />
          ) : (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Create one with iamCreateFlowRecorder(), bind it to your engine’s afterEvaluate hook, and pass it as flow={recorder}."
                icon={<Activity />}
                title="No flow recorder wired"
              />
            </div>
          )}
        </TabsContent>
        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="decision">
          <IamDecisionInspectorV2 defaults={defaultRequest} engine={engine} />
        </TabsContent>
        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="policies">
          <IamPoliciesPanelV2 engine={engine} />
        </TabsContent>
        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="roles">
          <IamRolesPanelV2 engine={engine} />
        </TabsContent>
        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="subjects">
          <IamSubjectsPanelV2 engine={engine} />
        </TabsContent>
        <TabsContent className="mt-0 flex min-h-0 flex-1 flex-col" value="metrics">
          <IamMetricsPanelV2 engine={engine} metrics={metrics} pollMs={pollMs} />
        </TabsContent>
      </Tabs>
    </IamV2Root>
  )
}
