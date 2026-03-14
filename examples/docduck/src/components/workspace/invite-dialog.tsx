'use client'

import { XIcon } from 'lucide-react'
import { useState } from 'react'

interface Props {
  onInvite: (email: string, role: string) => Promise<void>
  onClose: () => void
}

export function InviteDialog({ onInvite, onClose }: Props) {
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setLoading(true)
    const formData = new FormData(e.currentTarget)
    await onInvite(formData.get('email') as string, formData.get('role') as string)
    setLoading(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-lg">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="font-semibold text-lg">Invite Member</h3>
          <button type="button" onClick={onClose} className="rounded p-1 hover:bg-accent">
            <XIcon className="h-4 w-4" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="email" className="mb-1 block font-medium text-sm">
              Email Address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              required
              placeholder="user@example.com"
              className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div>
            <label htmlFor="role" className="mb-1 block font-medium text-sm">
              Role
            </label>
            <select id="role" name="role" className="w-full rounded-md border bg-white px-3 py-2 text-sm">
              <option value="viewer">Viewer</option>
              <option value="editor">Editor</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="rounded-md border px-4 py-2 text-sm hover:bg-accent">
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:opacity-90 disabled:opacity-50">
              {loading ? 'Inviting...' : 'Invite'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
