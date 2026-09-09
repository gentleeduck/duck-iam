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
 * Props for the panel body - the tab strip and whichever panel is open.
 *
 * `engine` is the only requirement. `metrics` and `flow` are the two optional
 * data sources: without them the Telemetry and Flow tabs render empty rather
 * than break, because both are opt-in wiring on the consumer's side (see
 * {@link iamCreateFlowRecorder}). `pollMs` sets how often the live panels
 * re-read the engine; `embedded` drops the panel chrome for a consumer framing
 * it themselves; `theme` pins the palette, and defaults to following the
 * viewer's `prefers-color-scheme`.
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

// Hard-no in production: admin reads here would leak the full auth model.
// No prop escape hatch by design - see lib/guard.ts. The guard sits in a thin
// wrapper so the inner component's hook order stays unconditional.
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

  /**
   * Arrow keys move between tabs, Home/End jump to the ends.
   *
   * Required by the tablist pattern this markup now claims: only the selected
   * tab is in the tab order, so without this the other five panels are
   * unreachable from the keyboard - the strip would announce itself as a
   * tablist and then behave like six unrelated buttons, one of them focusable.
   */
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
