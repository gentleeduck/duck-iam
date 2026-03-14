'use client'

import { FileTextIcon, GlobeIcon, LockIcon, PlusIcon, TrashIcon } from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'
import { Can, Cannot } from '@/lib/access-client'
import { createDocument, deleteDocument, toggleDocumentPublic } from '@/server/actions/document'

interface Document {
  id: string
  title: string
  workspaceId: string
  ownerId: string
  isPublic: boolean
  createdAt: string
  updatedAt: string
}

interface Props {
  documents: Document[]
  workspaceId: string
  workspaceSlug: string
}

export function DocumentList({ documents, workspaceId, workspaceSlug }: Props) {
  const router = useRouter()
  const [creating, setCreating] = useState(false)

  async function handleCreate() {
    setCreating(true)
    try {
      const result = await createDocument(workspaceId, 'Untitled')
      router.push(`/workspaces/${workspaceSlug}/documents/${result.id}`)
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(docId: string) {
    if (!confirm('Delete this document?')) return
    try {
      await deleteDocument(docId)
      toast.success('Document deleted')
      router.refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  async function handleTogglePublic(docId: string) {
    try {
      await toggleDocumentPublic(docId)
      router.refresh()
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : 'An error occurred')
    }
  }

  return (
    <div>
      <Can action="create" resource="document">
        <button
          type="button"
          onClick={handleCreate}
          disabled={creating}
          className="mb-4 flex items-center gap-2 rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:opacity-90 disabled:opacity-50">
          <PlusIcon className="h-4 w-4" />
          {creating ? 'Creating...' : 'New Document'}
        </button>
      </Can>

      <Cannot action="create" resource="document">
        <p className="mb-4 text-muted-foreground text-sm">
          You don&apos;t have permission to create documents in this workspace.
        </p>
      </Cannot>

      {documents.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <FileTextIcon className="mx-auto h-10 w-10 text-muted-foreground" />
          <p className="mt-2 text-muted-foreground text-sm">No documents yet</p>
        </div>
      ) : (
        <div className="space-y-2">
          {documents.map((doc) => (
            <div
              key={doc.id}
              className="group flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-accent">
              <Link
                href={`/workspaces/${workspaceSlug}/documents/${doc.id}`}
                className="flex flex-1 items-center gap-3">
                <FileTextIcon className="h-5 w-5 text-muted-foreground" />
                <div>
                  <h3 className="font-medium">{doc.title}</h3>
                  <p className="text-muted-foreground text-xs">
                    Updated {new Date(doc.updatedAt).toLocaleDateString()}
                  </p>
                </div>
              </Link>

              <div className="flex items-center gap-2">
                {doc.isPublic ? (
                  <span className="flex items-center gap-1 text-muted-foreground text-xs">
                    <GlobeIcon className="h-3 w-3" /> Public
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-muted-foreground text-xs">
                    <LockIcon className="h-3 w-3" /> Private
                  </span>
                )}

                <Can action="share" resource="document">
                  <button
                    type="button"
                    onClick={() => handleTogglePublic(doc.id)}
                    className="rounded p-1 text-muted-foreground opacity-0 hover:bg-muted group-hover:opacity-100"
                    title={doc.isPublic ? 'Make private' : 'Make public'}>
                    {doc.isPublic ? <LockIcon className="h-4 w-4" /> : <GlobeIcon className="h-4 w-4" />}
                  </button>
                </Can>

                <Can action="delete" resource="document">
                  <button
                    type="button"
                    onClick={() => handleDelete(doc.id)}
                    className="rounded p-1 text-destructive opacity-0 hover:bg-destructive/10 group-hover:opacity-100"
                    title="Delete">
                    <TrashIcon className="h-4 w-4" />
                  </button>
                </Can>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
