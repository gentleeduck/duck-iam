import { createWorkspace } from '@/server/actions/workspace'

export default function NewWorkspacePage() {
  return (
    <div className="mx-auto max-w-md">
      <h1 className="mb-6 font-bold text-2xl">Create Workspace</h1>
      <form action={createWorkspace} className="space-y-4">
        <div>
          <label htmlFor="name" className="mb-1 block font-medium text-sm">
            Workspace Name
          </label>
          <input
            id="name"
            name="name"
            type="text"
            required
            placeholder="My Workspace"
            className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <div>
          <label htmlFor="slug" className="mb-1 block font-medium text-sm">
            URL Slug
          </label>
          <input
            id="slug"
            name="slug"
            type="text"
            required
            placeholder="my-workspace"
            pattern="[a-z0-9-]+"
            className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
          <p className="mt-1 text-muted-foreground text-xs">Lowercase letters, numbers, and hyphens only</p>
        </div>
        <button
          type="submit"
          className="w-full rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:opacity-90">
          Create Workspace
        </button>
      </form>
    </div>
  )
}
