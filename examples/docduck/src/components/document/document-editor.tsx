'use client'

import { ArrowLeftIcon, LockIcon, PenIcon } from 'lucide-react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useCallback, useState } from 'react'
import { toast } from 'sonner'
import { updateDocumentTitle } from '@/server/actions/document'
import { PresenceAvatars } from './presence-avatars'

const CollaborativeEditor = dynamic(
  () => import('./collaborative-editor').then((m) => ({ default: m.CollaborativeEditor })),
  {
    ssr: false,
    loading: () => (
      <div className="flex min-h-[500px] items-center justify-center text-muted-foreground text-sm">
        Loading editor...
      </div>
    ),
  },
)

interface Document {
  id: string
  title: string
  workspaceId: string
  ownerId: string
  isPublic: boolean
}

interface Workspace {
  id: string
  name: string
  slug: string
}

interface User {
  id: string
  name: string
  email: string
}

interface Props {
  document: Document
  workspace: Workspace
  user: User
  canEdit: boolean
}

export function DocumentEditor({ document: doc, workspace, user, canEdit }: Props) {
  const [title, setTitle] = useState(doc.title)
  const [titleSaving, setTitleSaving] = useState(false)

  const saveTitle = useCallback(
    async (newTitle: string) => {
      if (newTitle === doc.title || !canEdit) return
      setTitleSaving(true)
      try {
        await updateDocumentTitle(doc.id, newTitle)
      } catch (err: unknown) {
        toast.error(err instanceof Error ? err.message : 'An error occurred')
      } finally {
        setTitleSaving(false)
      }
    },
    [doc.id, doc.title, canEdit],
  )

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href={`/workspaces/${workspace.slug}`} className="rounded-md p-1.5 hover:bg-accent">
            <ArrowLeftIcon className="h-4 w-4" />
          </Link>
          {canEdit ? (
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onBlur={(e) => saveTitle(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') saveTitle(title)
              }}
              className="border-none bg-transparent font-bold text-xl outline-none focus:ring-0"
              placeholder="Untitled"
            />
          ) : (
            <h1 className="font-bold text-xl">{doc.title}</h1>
          )}
          {titleSaving && <span className="text-muted-foreground text-xs">Saving...</span>}
        </div>
        <div className="flex items-center gap-3">
          <PresenceAvatars />
          {!canEdit && (
            <span className="flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 font-medium text-muted-foreground text-xs">
              <LockIcon className="h-3 w-3" /> Read-only
            </span>
          )}
          {canEdit && (
            <span className="flex items-center gap-1 rounded-full bg-green-50 px-2.5 py-1 font-medium text-green-700 text-xs">
              <PenIcon className="h-3 w-3" /> Editing
            </span>
          )}
        </div>
      </div>

      <div className="rounded-lg border bg-white p-1">
        <CollaborativeEditor docId={doc.id} workspaceId={workspace.id} user={user} editable={canEdit} />
      </div>
    </div>
  )
}
