import type { Explain } from '../../core/explain'
import type { AccessControl, IamPrimitives } from '../../core/types'
import type { IamMetrics } from '../../observability/metrics'

/**
 * Minimal engine surface the devtools rely on, so any concrete `Engine<...>` fits without variance issues.
 * WARN: keep `can`/`explain` in step with the engine; `scope` is the 5th argument, never `environment.scope`.
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
  /** The engine's observability facet: an object with `get`/`reset`, not methods on the engine. */
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

/** The metrics aggregator as the Telemetry panel needs it; structural, so consumers can pass their own. */
export interface IamIDevtoolsMetrics {
  snapshot(): IamMetrics.ISnapshot
  reset(): void
}

/**
 * The Decision Inspector's form state. All strings, including the JSON boxes, so half-typed JSON is a legal state;
 * parsing happens on submit.
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

/** Which devtools panel is open. */
export type IamPanelKey = 'flow' | 'decision' | 'policies' | 'roles' | 'subjects' | 'metrics'
