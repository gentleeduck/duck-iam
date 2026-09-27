import type { AccessControl } from '../../core/types'
import { CornerUpRight, Refresh } from '../components/icons'
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

/** Read-only browser for roles, their permissions and inheritance; the RBAC counterpart to {@link IamPoliciesPanel}. */
export function IamRolesPanel({ engine }: IamEnginePanelProps) {
  useIamDevtoolsStyles()
  const { current, error, filter, filtered, reload, selected, setFilter, setSelected } =
    useIamListPanel<AccessControl.IRole>(() => engine.admin.listRoles())

  // SECURITY: each panel is exported on its own, so it runs the guard itself. Kept below every hook.
  if (!isDevtoolsAllowed(engine)) return null

  return (
    <SplitView
      left={
        <ListShell
          count={filtered.length}
          title="Roles"
          toolbar={
            <Button onClick={reload}>
              <Refresh size={10} /> refresh
            </Button>
          }>
          <FilterBar onChange={setFilter} placeholder="Filter roles" value={filter} />
          {error && <Alert kind="error">{error}</Alert>}
          {filtered.length === 0 && !error && <DetailEmpty message="No roles." />}
          {filtered.map((r) => (
            <ListItem
              active={selected === r.id}
              dot="#86efac"
              key={r.id}
              onClick={() => setSelected(r.id)}
              primary={r.id}
              secondary={
                <span className="iam-dt-row--inline">
                  {r.permissions.length} perms
                  {r.inherits?.length ? (
                    <>
                      <span className="iam-dt-sep" />
                      <CornerUpRight size={10} /> {r.inherits.join(', ')}
                    </>
                  ) : null}
                </span>
              }
              trailing={<Badge tone="allow">{r.permissions.length}</Badge>}
            />
          ))}
        </ListShell>
      }
      right={
        !current ? (
          <DetailEmpty message="Select a role on the left." />
        ) : (
          <div className="iam-dt-detail">
            <DetailHead>
              <code>{current.id}</code>
              <span className="iam-dt-mute">{current.name}</span>
              {current.scope && <Badge tone="info">scope: {current.scope}</Badge>}
            </DetailHead>
            <DescriptionSection text={current.description} />
            {current.inherits && current.inherits.length > 0 && (
              <Section title="Inherits">
                <div className="iam-dt-row">
                  {current.inherits.map((id) => (
                    <Badge key={id}>{id}</Badge>
                  ))}
                </div>
              </Section>
            )}
            <Section title={`Permissions (${current.permissions.length})`}>
              <div className="iam-dt-col">
                {current.permissions.map((p) => (
                  <PermRow key={`${p.action}:${p.resource}:${p.scope ?? ''}`} perm={p} />
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

function PermRow({ perm }: { perm: AccessControl.IPermission }) {
  const hasDetail = !!perm.conditions || !!perm.scope
  return (
    <CollapsibleGroup
      disabled={!hasDetail}
      detail={perm.conditions && <JsonTree data={perm.conditions} defaultOpen label="conditions" />}
      summary={
        <>
          <code className="iam-dt-action">{perm.action}</code>
          <span className="iam-dt-mute">on</span>
          <code className="iam-dt-resource">{perm.resource}</code>
          {perm.scope && <Badge tone="info">{perm.scope}</Badge>}
          {perm.conditions && <Badge tone="warn">cond</Badge>}
        </>
      }
    />
  )
}
