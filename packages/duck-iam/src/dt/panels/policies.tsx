import type { AccessControl } from '../../core/types'
import { Refresh } from '../components/icons'
import { JsonTree } from '../components/json-tree'
import {
  CollapsibleGroup,
  DescriptionSection,
  DetailEmpty,
  DetailHead,
  FilterBar,
  ListItem,
  ListShell,
  Section,
  SplitView,
} from '../components/layout'
import { Alert, Badge, Button } from '../components/ui'
import { isDevtoolsAllowed } from '../lib/guard'
import { useIamListPanel } from '../lib/list-panel'
import { useIamDevtoolsStyles } from '../lib/styles'
import type { IamEnginePanelProps } from '../lib/types'

/** Read-only browser for the live policies from `engine.admin.listPolicies()`, with the selected policy rules. */
export function IamPoliciesPanel({ engine }: IamEnginePanelProps) {
  useIamDevtoolsStyles()
  const { current, error, filter, filtered, reload, selected, setFilter, setSelected } =
    useIamListPanel<AccessControl.IPolicy>(() => engine.admin.listPolicies())

  // SECURITY: each panel is exported on its own, so it runs the guard itself. Kept below every hook.
  if (!isDevtoolsAllowed(engine)) return null

  return (
    <SplitView
      left={
        <ListShell
          count={filtered.length}
          title="Policies"
          toolbar={
            <Button onClick={reload}>
              <Refresh size={10} /> refresh
            </Button>
          }>
          <FilterBar onChange={setFilter} placeholder="Filter policies" value={filter} />
          {error && <Alert kind="error">{error}</Alert>}
          {filtered.length === 0 && !error && <DetailEmpty message="No policies." />}
          {filtered.map((p) => (
            <ListItem
              active={selected === p.id}
              dot="#c4b5fd"
              key={p.id}
              onClick={() => setSelected(p.id)}
              primary={p.id}
              secondary={
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  {p.rules.length} rules
                  <span className="iam-dt-sep" />
                  {p.algorithm}
                </span>
              }
              trailing={<Badge tone="info">{p.algorithm}</Badge>}
            />
          ))}
        </ListShell>
      }
      right={
        !current ? (
          <DetailEmpty message="Select a policy on the left." />
        ) : (
          <div className="iam-dt-detail">
            <DetailHead>
              <code>{current.id}</code>
              <span className="iam-dt-mute">{current.name}</span>
              <Badge tone="info">{current.algorithm}</Badge>
              {current.version != null && <Badge>v{current.version}</Badge>}
              <span className="iam-dt-detail__meta">{current.rules.length} rules</span>
            </DetailHead>
            <DescriptionSection text={current.description} />
            <Section title={`Rules (${current.rules.length})`}>
              <div className="iam-dt-col">
                {current.rules.map((r) => (
                  <RuleRow key={r.id} rule={r} />
                ))}
              </div>
            </Section>
            <Section defaultOpen={false} title="Raw">
              <JsonTree data={current} defaultOpen />
            </Section>
          </div>
        )
      }
    />
  )
}

function RuleRow({ rule }: { rule: AccessControl.IRule }) {
  return (
    <CollapsibleGroup
      detail={
        <>
          {rule.description && (
            <p className="iam-dt-soft" style={{ fontSize: 11 }}>
              {rule.description}
            </p>
          )}
          {rule.conditions && <JsonTree data={rule.conditions} defaultOpen label="conditions" />}
        </>
      }
      summary={
        <>
          <code>{rule.id}</code>
          <Badge tone={rule.effect === 'allow' ? 'allow' : 'deny'}>{rule.effect}</Badge>
          <Badge>p{rule.priority}</Badge>
          <code className="iam-dt-action">{rule.actions.join(', ')}</code>
          <span className="iam-dt-mute">on</span>
          <code className="iam-dt-resource">{rule.resources.join(', ')}</code>
        </>
      }
    />
  )
}
