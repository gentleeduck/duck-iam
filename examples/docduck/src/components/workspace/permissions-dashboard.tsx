'use client'

import { CheckIcon, ShieldIcon, XIcon } from 'lucide-react'
import { useAccess } from '@/lib/access-client'

const PERMISSION_CHECKS: Array<{ action: string; resource: string; label: string }> = [
  { action: 'create', resource: 'document', label: 'Create documents' },
  { action: 'read', resource: 'document', label: 'Read documents' },
  { action: 'update', resource: 'document', label: 'Update documents' },
  { action: 'delete', resource: 'document', label: 'Delete documents' },
  { action: 'share', resource: 'document', label: 'Share documents' },
  { action: 'update', resource: 'workspace', label: 'Update workspace' },
  { action: 'delete', resource: 'workspace', label: 'Delete workspace' },
  { action: 'manage', resource: 'member', label: 'Manage members' },
]

export function PermissionsDashboard() {
  const { can } = useAccess()

  return (
    <div className="rounded-lg border">
      <div className="flex items-center gap-2 border-b px-4 py-3">
        <ShieldIcon className="h-4 w-4 text-muted-foreground" />
        <span className="font-medium text-sm">Permission Overview</span>
      </div>
      <div className="divide-y">
        {PERMISSION_CHECKS.map(({ action, resource, label }) => {
          const allowed = can(action, resource)
          return (
            <div key={`${action}:${resource}`} className="flex items-center justify-between px-4 py-2">
              <span className="text-sm">{label}</span>
              <span
                className={`flex items-center gap-1 font-medium text-xs ${
                  allowed ? 'text-green-600' : 'text-red-500'
                }`}>
                {allowed ? (
                  <>
                    <CheckIcon className="h-3 w-3" /> Allowed
                  </>
                ) : (
                  <>
                    <XIcon className="h-3 w-3" /> Denied
                  </>
                )}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
