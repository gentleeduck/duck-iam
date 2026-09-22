import React from 'react'
import type { IamIFlowRecorder } from './lib/flow'
import { isDevtoolsAllowed } from './lib/guard'
import { type IamDevtoolsTheme, iamDevtoolsThemeAttr, useIamDevtoolsStyles } from './lib/styles'
import type { IamIDecisionInput, IamIDevtoolsEngine, IamIDevtoolsMetrics, IamPanelKey } from './lib/types'
import { IamDecisionInspector } from './panels/decision'
import { IamFlowPanel } from './panels/flow'
import { IamMetricsPanel } from './panels/metrics'
import { IamPoliciesPanel } from './panels/policies'
import { IamRolesPanel } from './panels/roles'
import { IamSubjectsPanel } from './panels/subjects'

/**
 * Props for the panel body. Only `engine` is required; without `metrics`/`flow` those tabs show an empty state.
 * `theme` defaults to following `prefers-color-scheme`.
 */
export interface IIamDevtoolsInnerProps {
  engine: IamIDevtoolsEngine
  metrics?: IamIDevtoolsMetrics
  flow?: IamIFlowRecorder
  initialPanel?: IamPanelKey
  defaultRequest?: Partial<IamIDecisionInput>
  pollMs?: number
  embedded?: boolean
  theme?: IamDevtoolsTheme
}

const TABS: { key: IamPanelKey; label: string; dot: string }[] = [
  { dot: '#3fb950', key: 'flow', label: 'Flow' },
  { dot: '#58a6ff', key: 'decision', label: 'Decision' },
  { dot: '#a371f7', key: 'policies', label: 'Policies' },
  { dot: '#2dd4bf', key: 'roles', label: 'Roles' },
  { dot: '#e3b341', key: 'subjects', label: 'Subjects' },
  { dot: '#f778ba', key: 'metrics', label: 'Metrics' },
]

// SECURITY: renders nothing unless `isDevtoolsAllowed` passes; the admin reads here expose the whole auth model.
// NOTE: the guard lives in this wrapper so the inner component's hook order stays unconditional.
export function IamDevtoolsInner(props: IIamDevtoolsInnerProps) {
  if (!isDevtoolsAllowed(props.engine)) return null
  return <IamDevtoolsInnerImpl {...props} />
}

function IamDevtoolsInnerImpl({
  engine,
  metrics,
  flow,
  initialPanel = 'flow',
  defaultRequest,
  pollMs,
  embedded = false,
  theme = 'auto',
}: IIamDevtoolsInnerProps) {
  useIamDevtoolsStyles()
  const [active, setActive] = React.useState<IamPanelKey>(initialPanel)
  const tabsId = React.useId()
  const tabRefs = React.useRef(new Map<IamPanelKey, HTMLButtonElement>())

  // Arrows and Home/End move between tabs; only the selected tab is tabbable, so the rest need this to be reachable.
  const onTabKeyDown = (e: React.KeyboardEvent) => {
    const idx = TABS.findIndex((t) => t.key === active)
    let next = -1
    if (e.key === 'ArrowRight') next = (idx + 1) % TABS.length
    else if (e.key === 'ArrowLeft') next = (idx - 1 + TABS.length) % TABS.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = TABS.length - 1
    const tab = next >= 0 ? TABS[next] : undefined
    if (!tab) return
    e.preventDefault()
    setActive(tab.key)
    tabRefs.current.get(tab.key)?.focus()
  }

  const content = (
    <>
      <div aria-label="duck-iam devtools panels" className="iam-dt-tabs" onKeyDown={onTabKeyDown} role="tablist">
        {TABS.map((tab) => {
          const isActive = active === tab.key
          return (
            <button
              aria-controls={`${tabsId}-panel`}
              aria-selected={isActive}
              className="iam-dt-tab"
              id={`${tabsId}-tab-${tab.key}`}
              key={tab.key}
              onClick={() => setActive(tab.key)}
              ref={(el) => {
                if (el) tabRefs.current.set(tab.key, el)
                else tabRefs.current.delete(tab.key)
              }}
              role="tab"
              tabIndex={isActive ? 0 : -1}
              type="button">
              <span
                aria-hidden
                className="iam-dt-tab__dot"
                style={{ backgroundColor: tab.dot, boxShadow: isActive ? `0 0 6px ${tab.dot}` : undefined }}
              />
              {tab.label}
            </button>
          )
        })}
      </div>
      <div aria-labelledby={`${tabsId}-tab-${active}`} className="iam-dt-body" id={`${tabsId}-panel`} role="tabpanel">
        {active === 'flow' && flow && <IamFlowPanel flow={flow} />}
        {active === 'flow' && !flow && (
          <div className="iam-dt-empty iam-dt-empty--dashed">
            No flow recorder wired. Pass <code>flow=&#123;recorder&#125;</code> to the devtool and bind it to your
            engine's <code>afterEvaluate</code> hook.
          </div>
        )}
        {active === 'decision' && <IamDecisionInspector defaults={defaultRequest} engine={engine} />}
        {active === 'policies' && <IamPoliciesPanel engine={engine} />}
        {active === 'roles' && <IamRolesPanel engine={engine} />}
        {active === 'subjects' && <IamSubjectsPanel engine={engine} />}
        {active === 'metrics' && <IamMetricsPanel engine={engine} metrics={metrics} pollMs={pollMs} />}
      </div>
    </>
  )

  return (
    <div
      className={embedded ? 'iam-dt iam-dt-frame' : 'iam-dt iam-dt-shell'}
      data-iam-dt-theme={iamDevtoolsThemeAttr(theme)}>
      {content}
    </div>
  )
}
