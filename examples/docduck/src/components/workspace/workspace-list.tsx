'use client'

import { FolderIcon } from 'lucide-react'
import Link from 'next/link'

interface WorkspaceMembership {
  workspace: {
    id: string
    name: string
    slug: string
    ownerId: string
    createdAt: string
  }
  role: string
}

export function WorkspaceList({ memberships }: { memberships: WorkspaceMembership[] }) {
  if (memberships.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <FolderIcon className="mx-auto h-10 w-10 text-muted-foreground" />
        <p className="mt-2 text-muted-foreground text-sm">No workspaces yet</p>
        <Link
          href="/workspaces/new"
          className="mt-4 inline-block rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm">
          Create your first workspace
        </Link>
      </div>
    )
  }

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {memberships.map(({ workspace, role }) => (
        <Link
          key={workspace.id}
          href={`/workspaces/${workspace.slug}`}
          className="group rounded-lg border p-4 transition-colors hover:bg-accent">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 text-primary">
                <FolderIcon className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-medium group-hover:underline">{workspace.name}</h3>
                <p className="text-muted-foreground text-xs">/{workspace.slug}</p>
              </div>
            </div>
            <span className="rounded-full bg-muted px-2 py-0.5 font-medium text-xs capitalize">{role}</span>
          </div>
        </Link>
      ))}
    </div>
  )
}
