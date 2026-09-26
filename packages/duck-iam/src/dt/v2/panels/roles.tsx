'use client'

import { cn } from '@gentleduck/libs/cn'
import { CornerUpRight, Users } from 'lucide-react'
import type { AccessControl } from '../../../core/types'
import { isDevtoolsAllowed } from '../../lib/guard'
import { useIamListPanel } from '../../lib/list-panel'
import type { IamEnginePanelProps } from '../../lib/types'
import {
  IamV2Chip,
  IamV2DescriptionSection,
  IamV2Disclosure,
  IamV2Empty,
  IamV2ListRow,
  IamV2PaneBody,
  IamV2Root,
  IamV2Section,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IamV2ListBrowser } from '../components/list-browser'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE } from '../lib/tone'

/** One granted permission; expandable only when it has conditions. */
function PermissionRow({ permission }: { permission: AccessControl.IPermission }) {
  const hasDetail = Boolean(permission.conditions)
  return (
    <IamV2Disclosure
      disabled={!hasDetail}
      summary={
        <>
          <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{permission.action}</code>
          <span className="text-muted-foreground text-xs">on</span>
          <code className={cn(IAM_V2_MONO, IAM_V2_RESOURCE)}>{permission.resource}</code>
          {permission.scope && <IamV2Chip tone="info">{permission.scope}</IamV2Chip>}
          {permission.conditions && <IamV2Chip tone="warn">conditions</IamV2Chip>}
        </>
      }>
      {permission.conditions && <IamV2Json data={permission.conditions} label="conditions" />}
    </IamV2Disclosure>
  )
}

/** Read-only browser for roles, their permissions and inheritance. Assignment lives in the Subjects panel. */
export function IamRolesPanelV2({ engine }: IamEnginePanelProps) {
  const { current, error, filter, filtered, items, loading, reload, selected, setFilter, setSelected } =
    useIamListPanel<AccessControl.IRole>(() => engine.admin.listRoles())

  // Below every hook; guards the whole role catalog.
  if (!isDevtoolsAllowed(engine)) return null

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          !current ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Choose a role on the left to read its permissions and inheritance."
                icon={<Users />}
                title="No role selected"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <code className={cn(IAM_V2_MONO, 'font-medium text-foreground')}>{current.id}</code>
                {current.name && <span className="text-muted-foreground text-xs">{current.name}</span>}
                {current.scope && <IamV2Chip tone="info">scope: {current.scope}</IamV2Chip>}
                <span className="ms-auto text-[0.6875rem] text-muted-foreground tabular-nums">
                  {current.permissions.length} permissions
                </span>
              </div>
              <IamV2PaneBody>
                <IamV2DescriptionSection text={current.description} />
                {current.inherits && current.inherits.length > 0 && (
                  <IamV2Section title="Inherits">
                    <div className="flex flex-wrap gap-1.5">
                      {current.inherits.map((id) => (
                        <IamV2Chip key={id} tone="neutral">
                          <CornerUpRight size={10} />
                          {id}
                        </IamV2Chip>
                      ))}
                    </div>
                  </IamV2Section>
                )}
                <IamV2Section title={`Permissions (${current.permissions.length})`}>
                  <div className="flex flex-col gap-1.5">
                    {current.permissions.map((permission) => (
                      <PermissionRow
                        key={`${permission.action}:${permission.resource}:${permission.scope ?? ''}`}
                        permission={permission}
                      />
                    ))}
                  </div>
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Raw role">
                  <IamV2Json data={current} />
                </IamV2Section>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <IamV2ListBrowser
            emptyIcon={<Users />}
            error={error}
            filter={filter}
            filtered={filtered}
            items={items}
            loading={loading}
            noun="roles"
            reload={reload}
            reloadLabel="Reload roles"
            renderRow={(role) => (
              <IamV2ListRow
                active={selected === role.id}
                description={
                  role.inherits?.length
                    ? `${role.permissions.length} perms · inherits ${role.inherits.join(', ')}`
                    : `${role.permissions.length} perms`
                }
                key={role.id}
                onSelect={() => setSelected(role.id)}
                title={<code className={IAM_V2_MONO}>{role.id}</code>}
                tone="allow"
                trailing={<IamV2Chip tone="neutral">{role.permissions.length}</IamV2Chip>}
              />
            )}
            searchPlaceholder="Filter roles"
            setFilter={setFilter}
            title="Roles"
          />
        }
      />
    </IamV2Root>
  )
}
