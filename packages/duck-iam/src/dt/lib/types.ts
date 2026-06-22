import type { Explain } from '../../core/explain'
import type { AccessControl, IamPrimitives } from '../../core/types'
import type { IamMetrics } from '../../observability/metrics'

/**
 * Minimal engine surface the devtool relies on. Lets consumers pass any
 * concrete `Engine<...>` without variance issues.
 */
export interface IamIDevtoolsEngine {
  can(
    subjectId: string,
    action: string,
    resource: { type: string; id?: string; attributes?: Record<string, IamPrimitives.AttributeValue> },
    environment?: Record<string, unknown>,
  ): Promise<unknown>
  explain(
    subjectId: string,
    action: string,
    resource: { type: string; id?: string; attributes?: Record<string, IamPrimitives.AttributeValue> },
    environment?: Record<string, unknown>,
  ): Promise<Explain.IResult>
  stats(): Record<string, { hits: number; misses: number; size: number }>
  resetStats(): void
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

export interface IamIDevtoolsMetrics {
  snapshot(): IamMetrics.ISnapshot
  reset(): void
}

export interface IamIDecisionInput {
  subjectId: string
  action: string
  resourceType: string
  resourceId: string
  attributesJson: string
  environmentJson: string
  scope: string
}

export type IamPanelKey = 'flow' | 'decision' | 'policies' | 'roles' | 'subjects' | 'metrics'
