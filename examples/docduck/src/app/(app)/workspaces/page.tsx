import { WorkspaceList } from '@/components/workspace/workspace-list'
import { getWorkspaces } from '@/server/actions/workspace'

export default async function WorkspacesPage() {
  const memberships = await getWorkspaces()

  // Serialize dates for client component
  const serialized = memberships.map((m) => ({
    ...m,
    workspace: {
      ...m.workspace,
      createdAt: m.workspace.createdAt.toISOString(),
    },
  }))

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="font-bold text-2xl">Workspaces</h1>
          <p className="mt-1 text-muted-foreground text-sm">Select a workspace or create a new one</p>
        </div>
        <a
          href="/workspaces/new"
          className="rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:opacity-90">
          New Workspace
        </a>
      </div>
      <WorkspaceList memberships={serialized} />
    </div>
  )
}
