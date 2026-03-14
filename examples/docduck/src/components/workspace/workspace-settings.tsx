'use client'

import { TrashIcon, UserPlusIcon } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'
import { Can } from '@/lib/access-client'
import { deleteWorkspace, inviteMember, removeMember, updateMemberRole } from '@/server/actions/workspace'
import { InviteDialog } from './invite-dialog'
import { MemberList } from './member-list'
import { PermissionsDashboard } from './permissions-dashboard'

interface Member {
  id: string
  userId: string
  workspaceId: string
  role: string
  user?: { id: string; name: string; email: string } | undefined
}

interface Workspace {
  id: string
  name: string
  slug: string
  ownerId: string
}

interface Props {
  workspace: Workspace
  members: Member[]
}

export function WorkspaceSettings({ workspace, members }: Props) {
  const router = useRouter()
  const [showInvite, setShowInvite] = useState(false)

  async function handleDeleteWorkspace() {
    if (!confirm(`Delete workspace "${workspace.name}"? This cannot be undone.`)) return
    try {
      await deleteWorkspace(workspace.id)
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  async function handleRoleChange(memberId: string, newRole: string) {
    try {
      await updateMemberRole(workspace.id, memberId, newRole)
      toast.success('Role updated')
      router.refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  async function handleRemoveMember(memberId: string) {
    if (!confirm('Remove this member?')) return
    try {
      await removeMember(workspace.id, memberId)
      toast.success('Member removed')
      router.refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  async function handleInvite(email: string, role: string) {
    try {
      await inviteMember(workspace.id, email, role)
      toast.success('Member invited')
      setShowInvite(false)
      router.refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  return (
    <div className="space-y-8">
      {/* Members Section */}
      <section>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-semibold text-lg">Members</h2>
          <Can action="manage" resource="member">
            <button
              type="button"
              onClick={() => setShowInvite(true)}
              className="flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 font-medium text-primary-foreground text-sm hover:opacity-90">
              <UserPlusIcon className="h-4 w-4" />
              Invite Member
            </button>
          </Can>
        </div>
        <MemberList members={members} onRoleChange={handleRoleChange} onRemove={handleRemoveMember} />
      </section>

      {/* Permissions Dashboard */}
      <section>
        <h2 className="mb-4 font-semibold text-lg">Your Permissions</h2>
        <PermissionsDashboard />
      </section>

      {/* Danger Zone */}
      <Can action="delete" resource="workspace">
        <section className="rounded-lg border border-destructive/30 p-4">
          <h2 className="mb-2 font-semibold text-destructive text-lg">Danger Zone</h2>
          <p className="mb-4 text-muted-foreground text-sm">
            Deleting a workspace removes all documents and member access permanently.
          </p>
          <button
            type="button"
            onClick={handleDeleteWorkspace}
            className="flex items-center gap-2 rounded-md bg-destructive px-4 py-2 font-medium text-destructive-foreground text-sm hover:opacity-90">
            <TrashIcon className="h-4 w-4" />
            Delete Workspace
          </button>
        </section>
      </Can>

      {showInvite && <InviteDialog onInvite={handleInvite} onClose={() => setShowInvite(false)} />}
    </div>
  )
}
