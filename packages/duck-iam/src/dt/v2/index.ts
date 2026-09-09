/**
 * duck-iam devtools **v2** - the same six panels, rebuilt from scratch on
 * duck-ui.
 *
 * ## Which one to import
 *
 * `@gentleduck/iam/dt` (v1) and `@gentleduck/iam/dt/v2` are both supported and
 * make opposite trades on purpose:
 *
 * | | `./dt` (v1) | `./dt/v2` |
 * |---|---|---|
 * | dependencies | none beyond React | `@gentleduck/registry-ui`, `@gentleduck/libs`, `lucide-react` |
 * | styling | one injected stylesheet it owns (`iam-dt-*` classes, `--iam-dt-*` tokens) | Tailwind utilities + duck-ui's semantic tokens |
 * | looks like | itself, everywhere | the app it is docked into |
 * | needs Tailwind? | no | yes, configured to scan this package |
 *
 * Reach for v1 in any app that is not already a duck-ui app - it renders
 * identically with nothing installed and nothing configured. Reach for v2 when
 * the host *is* a duck-ui (or shadcn-token) app and you want the devtool to
 * inherit its theme, radius, font and dark mode instead of sitting in the page
 * as a foreign window.
 *
 * ## What v2 needs from the host
 *
 * Tailwind v4 must scan this package so the utility classes below actually
 * exist in the consumer's stylesheet:
 *
 * ```css
 * @source "../node_modules/@gentleduck/iam/dist/dt/v2";
 * ```
 *
 * and the host must define the duck-ui token set (`--background`, `--card`,
 * `--border`, `--foreground`, `--muted-foreground`, `--primary`, `--ring`,
 * `--destructive`, `--accent`) - which any duck-ui or shadcn theme already
 * does. The five decision colours are *not* taken from there: allow, deny,
 * warn, info and neutral are pinned in `lib/tone.ts`, because a verdict is not
 * a shade a theme gets to reinterpret.
 *
 * Everything else is shared with v1 and imported from `../lib` - the
 * production guard, the flow recorder, the trace formatters and the engine
 * types. Only the presentation is new.
 *
 * @example
 * ```tsx
 * import { IamDevtoolsV2, iamCreateFlowRecorder } from '@gentleduck/iam/dt/v2'
 *
 * const flow = iamCreateFlowRecorder()
 * // ...bind `flow.record` to the engine's afterEvaluate hook...
 *
 * <IamDevtoolsV2 engine={engine} flow={flow} position="bottom" />
 * ```
 */

export type { IamIFlowEntry, IamIFlowRecorder, IamIFlowRecorderOptions } from '../lib/flow'
export { iamCreateFlowRecorder } from '../lib/flow'
export type { IamIDecisionInput, IamIDevtoolsEngine, IamIDevtoolsMetrics, IamPanelKey } from '../lib/types'
export type { IIamDevtoolsInnerV2Props } from './iam-devtools-inner-v2'
export { IamDevtoolsInnerV2 } from './iam-devtools-inner-v2'
export type { IamV2ButtonPosition, IamV2PanelPosition, IIamDevtoolsV2Props } from './iam-devtools-v2'
export { IamDevtoolsV2 } from './iam-devtools-v2'
export type { IamV2Tone } from './lib/tone'
export { IamDecisionInspectorV2 } from './panels/decision'
export { IamFlowPanelV2 } from './panels/flow'
export { IamMetricsPanelV2 } from './panels/metrics'
export { IamPoliciesPanelV2 } from './panels/policies'
export { IamRolesPanelV2 } from './panels/roles'
export { IamSubjectsPanelV2 } from './panels/subjects'
export { IamTraceTreeV2 } from './panels/trace'
