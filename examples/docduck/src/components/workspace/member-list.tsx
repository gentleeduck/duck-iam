'use client'

import { TrashIcon } from 'lucide-react'
import { Can } from '@/lib/access-client'

interface Member {
  id: string
  userId: string
  role: string
  user?: { id: string; name: string; email: string } | undefined
}

interface Props {
  members: Member[]
  onRoleChange: (memberId: string, newRole: string) => void
  onRemove: (memberId: string) => void
}

const ROLES = ['viewer', 'editor', 'admin', 'owner']

export function MemberList({ members, onRoleChange, onRemove }: Props) {
  return (
    <div className="rounded-lg border">
      <div className="grid grid-cols-[1fr_auto_auto] gap-4 border-b px-4 py-2 font-medium text-muted-foreground text-xs uppercase">
        <span>Member</span>
        <span>Role</span>
        <span />
      </div>
      {members.map((member) => (
        <div
          key={member.id}
          className="grid grid-cols-[1fr_auto_auto] items-center gap-4 border-b px-4 py-3 last:border-b-0">
          <div>
            <p className="font-medium text-sm">{member.user?.name ?? 'Unknown'}</p>
            <p className="text-muted-foreground text-xs">{member.user?.email ?? ''}</p>
          </div>
          <Can action="manage" resource="member">
            <select
              value={member.role}
              onChange={(e) => onRoleChange(member.id, e.target.value)}
              className="rounded-md border bg-white px-2 py-1 text-sm">
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </Can>
          <Can
            action="manage"
            resource="member"
            fallback={
              <span className="rounded-full bg-muted px-2 py-0.5 font-medium text-xs capitalize">{member.role}</span>
            }>
            <button
              type="button"
              onClick={() => onRemove(member.id)}
              className="rounded p-1 text-destructive hover:bg-destructive/10"
              title="Remove member">
              <TrashIcon className="h-4 w-4" />
            </button>
          </Can>
        </div>
      ))}
    </div>
  )
}
