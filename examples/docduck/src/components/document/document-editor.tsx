'use client'

import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Separator } from '@gentleduck/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/ui/tooltip'
import { ArrowLeftIcon, LockIcon, PenIcon } from 'lucide-react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useCallback, useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { updateDocumentTitle } from '@/server/actions/document'

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

function formatRelativeTime(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000)
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

export function DocumentEditor({ document: doc, workspace, user, canEdit }: Props) {
  const [title, setTitle] = useState(doc.title)
  const [titleSaving, setTitleSaving] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)
  const [lastSavedDisplay, setLastSavedDisplay] = useState<string>('')
  const [wordCount, setWordCount] = useState(0)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!lastSaved) return
    setLastSavedDisplay(formatRelativeTime(lastSaved))

    intervalRef.current = setInterval(() => {
      setLastSavedDisplay(formatRelativeTime(lastSaved))
    }, 10_000)

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [lastSaved])

  const saveTitleTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const saveTitle = useCallback(
    async (newTitle: string) => {
      if (newTitle === doc.title || !canEdit) return
      setTitleSaving(true)
      try {
        await updateDocumentTitle(doc.id, newTitle)
        setLastSaved(new Date())
      } catch (err: unknown) {
        toast.error(err instanceof Error ? err.message : 'An error occurred')
      } finally {
        setTitleSaving(false)
      }
    },
    [doc.id, doc.title, canEdit],
  )

  // Debounce title saves - only save after 500ms of no typing
  useEffect(() => {
    if (title === doc.title) return

    saveTitleTimeoutRef.current = setTimeout(() => {
      saveTitle(title)
    }, 500)

    return () => {
      if (saveTitleTimeoutRef.current) clearTimeout(saveTitleTimeoutRef.current)
    }
  }, [title, doc.title, saveTitle])

  const handleWordCountChange = useCallback((count: number) => {
    setWordCount(count)
  }, [])

  const handleSynced = useCallback(() => {
    setLastSaved(new Date())
  }, [])

  return (
    <div className="mx-auto max-w-4xl">
      <TooltipProvider>
        {/* Header / Toolbar */}
        <div className="mb-4 flex items-center justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button type="button" variant="ghost" size="icon" className="shrink-0" asChild>
                  <Link href={`/workspaces/${workspace.slug}`}>
                    <ArrowLeftIcon className="h-4 w-4" />
                  </Link>
                </Button>
              </TooltipTrigger>
              <TooltipContent>Back to workspace</TooltipContent>
            </Tooltip>

            {canEdit ? (
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') e.currentTarget.blur()
                }}
                className="min-w-0 border-transparent border-b-2 bg-transparent font-bold text-xl outline-none transition-colors focus:border-primary focus:ring-0"
                placeholder="Untitled"
              />
            ) : (
              <h1 className="truncate font-bold text-xl">{doc.title}</h1>
            )}
            {titleSaving && <span className="text-muted-foreground text-xs">Saving...</span>}
          </div>

          <div className="flex items-center gap-2">
            {canEdit ? (
              <Badge variant="secondary" className="bg-green-50 text-green-700">
                <PenIcon className="mr-1 h-3 w-3" /> Editing
              </Badge>
            ) : (
              <Badge variant="outline">
                <LockIcon className="mr-1 h-3 w-3" /> Read-only
              </Badge>
            )}
          </div>
        </div>

        <div className="rounded-lg border bg-white">
          <CollaborativeEditor
            docId={doc.id}
            workspaceId={workspace.id}
            user={user}
            editable={canEdit}
            onWordCountChange={handleWordCountChange}
            onSynced={handleSynced}
          />
        </div>

        {/* Status bar */}
        <div className="mt-2 flex items-center gap-3 px-1 text-muted-foreground text-xs">
          <span>
            {wordCount} {wordCount === 1 ? 'word' : 'words'}
          </span>
          <Separator orientation="vertical" className="h-3" />
          {lastSaved ? <span>Last saved {lastSavedDisplay}</span> : <span>Not yet saved</span>}
        </div>
      </TooltipProvider>
    </div>
  )
}
