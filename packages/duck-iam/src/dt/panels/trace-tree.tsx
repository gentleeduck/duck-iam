import type { Explain } from '../../core/explain'
import { ArrowRight } from '../components/icons'
import { CollapsibleGroup } from '../components/layout'
import { Badge } from '../components/ui'
import { formatAttrValue, summarizeTrace } from '../lib/format'
import { useIamDevtoolsStyles } from '../lib/styles'

function LeafNode({ leaf }: { leaf: Explain.ILeafTrace }) {
  return (
    <div className="iam-dt-trace__row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
      <div className="iam-dt-row">
        <Badge tone={leaf.result ? 'allow' : 'deny'}>{leaf.result ? 'PASS' : 'FAIL'}</Badge>
        <code className="iam-dt-action">{leaf.field}</code>
        <code className="iam-dt-mute">{leaf.operator}</code>
      </div>
      <div className="iam-dt-grid-2" style={{ paddingLeft: 4, fontSize: 11 }}>
        <div className="iam-dt-mute">
          expected: <code className="iam-dt-soft">{formatAttrValue(leaf.expected)}</code>
        </div>
        <div className="iam-dt-mute">
          actual:{' '}
          <code className={leaf.result ? 'iam-dt-effect-allow' : 'iam-dt-effect-deny'}>
            {formatAttrValue(leaf.actual)}
          </code>
        </div>
      </div>
    </div>
  )
}

function GroupNode({ group, depth = 0 }: { group: Explain.IGroupTrace; depth?: number }) {
  return (
    <CollapsibleGroup
      defaultOpen={depth < 2}
      detail={group.children.map((child) =>
        child.type === 'condition' ? (
          <LeafNode key={`leaf:${child.field}:${child.operator}`} leaf={child} />
        ) : (
          <GroupNode depth={depth + 1} group={child} key={`group:${child.logic}:${child.children.length}`} />
        ),
      )}
      summary={
        <>
          <Badge tone={group.result ? 'allow' : 'deny'}>{group.logic.toUpperCase()}</Badge>
          <span className="iam-dt-soft" style={{ fontSize: 11 }}>
            {summarizeTrace(group)}
          </span>
        </>
      }
    />
  )
}

function RuleTrace({ rule }: { rule: Explain.IRuleTrace }) {
  return (
    <CollapsibleGroup
      defaultOpen={rule.matched}
      detail={<GroupNode group={rule.conditions} />}
      summary={
        <>
          <span
            className={rule.effect === 'allow' ? 'iam-dt-effect-allow' : 'iam-dt-effect-deny'}
            style={{ fontSize: 10, textTransform: 'uppercase' }}>
            {rule.effect}
          </span>
          <code>{rule.ruleId}</code>
          <Badge tone={rule.actionMatch ? 'allow' : 'neutral'}>act</Badge>
          <Badge tone={rule.resourceMatch ? 'allow' : 'neutral'}>res</Badge>
          <Badge tone={rule.conditionsMet ? 'allow' : 'deny'}>cond</Badge>
          <Badge tone="warn">p{rule.priority}</Badge>
          {rule.matched && <Badge tone="allow">matched</Badge>}
        </>
      }
    />
  )
}

/** Renders an {@link Explain.IResult} as a collapsible tree: each policy consulted, its rule votes, and the decider. */
export function IamTraceTree({ result }: { result: Explain.IResult }) {
  useIamDevtoolsStyles()
  return (
    <div className="iam-dt iam-dt-col">
      <div className="iam-dt-trace__row">
        <Badge tone={result.decision.allowed ? 'allow' : 'deny'}>
          {result.decision.allowed ? 'ALLOWED' : 'DENIED'}
        </Badge>
        <span className="iam-dt-soft" style={{ fontSize: 11 }}>
          {result.summary}
        </span>
      </div>
      {result.policies.length === 0 ? (
        <div className="iam-dt-empty iam-dt-empty--dashed">no policies evaluated</div>
      ) : (
        result.policies.map((p) => (
          <div className="iam-dt-trace__group" key={p.policyId} style={{ padding: 6 }}>
            <div className="iam-dt-row">
              <code className="iam-dt-soft">{p.policyName ?? p.policyId}</code>
              <Badge tone={p.targetMatch ? 'allow' : 'neutral'}>target</Badge>
              <Badge tone={p.result === 'allow' ? 'allow' : 'deny'}>{p.result}</Badge>
              <code className="iam-dt-mute" style={{ fontSize: 10 }}>
                {p.algorithm}
              </code>
              {p.decidingRuleId && (
                <code
                  className="iam-dt-action"
                  style={{ fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <ArrowRight size={10} /> {p.decidingRuleId}
                </code>
              )}
              <span className="iam-dt-detail__meta">{p.reason}</span>
            </div>
            <div className="iam-dt-col" style={{ marginTop: 6 }}>
              {p.rules.map((r) => (
                <RuleTrace key={r.ruleId} rule={r} />
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  )
}
