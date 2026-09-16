'use client'

import { cn } from '@gentleduck/libs/cn'
import { ArrowRight } from 'lucide-react'
import type { Explain } from '../../../core/explain'
import { formatAttrValue, summarizeTrace } from '../../lib/format'
import { IamV2Chip, IamV2Disclosure, IamV2Empty, IamV2Root } from '../components/chrome'
import { IAM_V2_ACTION, IAM_V2_MONO, iamV2Decision, iamV2Text } from '../lib/tone'

/** One condition leaf: what was asked for, and what the subject actually had. */
function Leaf({ leaf }: { leaf: Explain.ILeafTrace }) {
  const tone = iamV2Decision(leaf.result)
  return (
    <div className="flex flex-col gap-1 rounded-md border border-border bg-background px-2 py-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <IamV2Chip tone={tone}>{leaf.result ? 'pass' : 'fail'}</IamV2Chip>
        <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{leaf.field}</code>
        <code className={cn(IAM_V2_MONO, 'text-muted-foreground')}>{leaf.operator}</code>
      </div>
      <dl className="grid grid-cols-1 gap-x-3 gap-y-0.5 text-[0.6875rem] sm:grid-cols-2">
        <div className="flex min-w-0 gap-1">
          <dt className="shrink-0 text-muted-foreground">expected</dt>
          <dd className="min-w-0 break-all font-mono text-foreground">{formatAttrValue(leaf.expected)}</dd>
        </div>
        <div className="flex min-w-0 gap-1">
          <dt className="shrink-0 text-muted-foreground">actual</dt>
          <dd className={cn('min-w-0 break-all font-mono', iamV2Text(tone))}>{formatAttrValue(leaf.actual)}</dd>
        </div>
      </dl>
    </div>
  )
}

/** An `all` / `any` / `not` group, recursing into whichever it holds. */
function Group({ depth = 0, group }: { depth?: number; group: Explain.IGroupTrace }) {
  return (
    <IamV2Disclosure
      defaultOpen={depth < 2}
      summary={
        <>
          <IamV2Chip tone={iamV2Decision(group.result)}>{group.logic.toUpperCase()}</IamV2Chip>
          <span className="text-[0.6875rem] text-muted-foreground">{summarizeTrace(group)}</span>
        </>
      }>
      {group.children.map((child) =>
        child.type === 'condition' ? (
          <Leaf key={`leaf:${child.field}:${child.operator}`} leaf={child} />
        ) : (
          <Group depth={depth + 1} group={child} key={`group:${child.logic}:${child.children.length}`} />
        ),
      )}
    </IamV2Disclosure>
  )
}

/** One rule's vote: the three match tests, its priority, and whether it matched. */
function Rule({ rule }: { rule: Explain.IRuleTrace }) {
  return (
    <IamV2Disclosure
      defaultOpen={rule.matched}
      summary={
        <>
          <IamV2Chip tone={rule.effect === 'allow' ? 'allow' : 'deny'}>{rule.effect}</IamV2Chip>
          <code className={cn(IAM_V2_MONO, 'text-foreground')}>{rule.ruleId}</code>
          <IamV2Chip tone={rule.actionMatch ? 'allow' : 'neutral'}>action</IamV2Chip>
          <IamV2Chip tone={rule.resourceMatch ? 'allow' : 'neutral'}>resource</IamV2Chip>
          <IamV2Chip tone={rule.conditionsMet ? 'allow' : 'deny'}>conditions</IamV2Chip>
          <IamV2Chip tone="neutral">p{rule.priority}</IamV2Chip>
          {rule.matched && <IamV2Chip tone="info">decided</IamV2Chip>}
        </>
      }>
      <Group group={rule.conditions} />
    </IamV2Disclosure>
  )
}

/**
 * Renders an {@link Explain.IResult} as a tree of policies, rule votes and leaf conditions.
 * Takes a computed result and never touches the engine, so it needs no devtools guard.
 */
export function IamTraceTreeV2({ result }: { result: Explain.IResult }) {
  return (
    <IamV2Root className="gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <IamV2Chip tone={iamV2Decision(result.decision.allowed)}>
          {result.decision.allowed ? 'allowed' : 'denied'}
        </IamV2Chip>
        <span className="text-muted-foreground text-xs">{result.summary}</span>
      </div>
      {result.policies.length === 0 ? (
        <IamV2Empty description="Nothing in the model targeted this request." title="No policies evaluated" />
      ) : (
        result.policies.map((policy) => (
          <div className="flex flex-col gap-1.5 rounded-lg border border-border bg-card p-2" key={policy.policyId}>
            <div className="flex flex-wrap items-center gap-1.5">
              <code className={cn(IAM_V2_MONO, 'font-medium text-foreground')}>
                {policy.policyName ?? policy.policyId}
              </code>
              <IamV2Chip tone={policy.targetMatch ? 'allow' : 'neutral'}>target</IamV2Chip>
              <IamV2Chip tone={policy.result === 'allow' ? 'allow' : 'deny'}>{policy.result}</IamV2Chip>
              <IamV2Chip tone="neutral">{policy.algorithm}</IamV2Chip>
              {policy.decidingRuleId && (
                <IamV2Chip tone="info">
                  <ArrowRight size={10} />
                  {policy.decidingRuleId}
                </IamV2Chip>
              )}
              <span className="ms-auto text-[0.6875rem] text-muted-foreground">{policy.reason}</span>
            </div>
            <div className="flex flex-col gap-1.5">
              {policy.rules.map((rule) => (
                <Rule key={rule.ruleId} rule={rule} />
              ))}
            </div>
          </div>
        ))
      )}
    </IamV2Root>
  )
}
