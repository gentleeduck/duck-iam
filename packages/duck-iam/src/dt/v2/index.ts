/**
 * duck-iam devtools v2: the six v1 panels on duck-ui + Tailwind, inheriting the host theme. Use `./dt` (v1) elsewhere.
 * NOTE: the host's Tailwind must `@source "../node_modules/@gentleduck/iam/dist/dt/v2"` and define duck-ui tokens.
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
