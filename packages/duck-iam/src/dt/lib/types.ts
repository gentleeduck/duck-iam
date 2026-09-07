import type { Explain } from '../../core/explain'
import type { AccessControl, IamPrimitives } from '../../core/types'
import type { IamMetrics } from '../../observability/metrics'

/**
 * Minimal engine surface the devtool relies on. Lets consumers pass any
 * concrete `Engine<...>` without variance issues.
 *
 * Narrower than the real engine is the point, but narrower in the wrong place
 * hides drift: this interface once declared four parameters for `can`/`explain`
 * where the engine takes five, so the Decision Inspector's `scope` box could
 * not reach `scope` at all and the compiler had nothing to object to. Only the
 * 5th positional argument drives `enrichSubjectWithScopedRoles`; nothing ever
 * reads `environment.scope`.
 */
export interface IamIDevtoolsEngine {
  can(
    subjectId: string,
    action: string,
    resource: { type: string; id?: string; attributes?: Record<string, IamPrimitives.AttributeValue> },
    environment?: Record<string, unknown>,
    scope?: string,
  ): Promise<unknown>
  explain(
    subjectId: string,
    action: string,
    resource: { type: string; id?: string; attributes?: Record<string, IamPrimitives.AttributeValue> },
    environment?: Record<string, unknown>,
    scope?: string,
  ): Promise<Explain.IResult>
  /**
   * The engine's observability facet, as an object - not the flat
   * `stats()` / `resetStats()` methods it replaced in 3.0.0. Declaring the
   * removed shape here meant the Telemetry panel called `engine.stats()` on a
   * property that is an object, so opening it against any real engine threw
   * `engine.stats is not a function` from a `useState` initializer and took the
   * whole devtools panel down with it. Every devtools test hands in a
   * hand-rolled mock implementing the dead shape, so nothing noticed.
   */
  stats: {
    get(): Record<string, { hits: number; misses: number; size: number }>
    reset(): void
  }
  admin: {
    listPolicies(): Promise<AccessControl.IPolicy[]>
    listRoles(): Promise<AccessControl.IRole[]>
    getPolicy(id: string): Promise<AccessControl.IPolicy | null>
    getRole(id: string): Promise<AccessControl.IRole | null>
    assignRole(subjectId: string, roleId: string, scope?: string): Promise<void>
    revokeRole(subjectId: string, roleId: string, scope?: string): Promise<void>
    setAttributes(subjectId: string, attrs: IamPrimitives.Attributes): Promise<void>
    getAttributes(subjectId: string): Promise<IamPrimitives.Attributes>
    export(): Promise<unknown>
  }
}

/**
 * The metrics aggregator as the Telemetry panel needs it. Structural rather
 * than an import of the concrete aggregator so a consumer can hand in their
 * own - the panel only ever reads a snapshot and offers a reset button.
 */
export interface IamIDevtoolsMetrics {
  snapshot(): IamMetrics.ISnapshot
  reset(): void
}

/**
 * The Decision Inspector's form state. Every field is a string, including the
 * two JSON boxes, because this is what the user is currently typing - half-typed
 * JSON has to be a legal state of the form, so parsing happens at submit and a
 * syntax error is shown rather than thrown.
 */
export interface IamIDecisionInput {
  subjectId: string
  action: string
  resourceType: string
  resourceId: string
  attributesJson: string
  environmentJson: string
  scope: string
}

/** Which devtools panel is open. Also the persisted key, so renaming one resets the user's last tab. */
export type IamPanelKey = 'flow' | 'decision' | 'policies' | 'roles' | 'subjects' | 'metrics'
