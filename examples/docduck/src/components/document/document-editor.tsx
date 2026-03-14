'use client'

import { ArrowLeftIcon, CircleIcon, Loader2Icon, LockIcon, PenIcon, WifiIcon, WifiOffIcon } from 'lucide-react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useCallback, useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { updateDocumentTitle } from '@/server/actions/document'
import type { ConnectionStatus } from './collaborative-editor'

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

const CONNECTION_CONFIG: Record<ConnectionStatus, { icon: React.ReactNode; label: string; dotClass: string }> = {
  connected: {
    icon: <WifiIcon className="h-3 w-3" />,
    label: 'Connected',
    dotClass: 'bg-green-500',
  },
  syncing: {
    icon: <Loader2Icon className="h-3 w-3 animate-spin" />,
    label: 'Syncing...',
    dotClass: 'bg-yellow-500',
  },
  disconnected: {
    icon: <WifiOffIcon className="h-3 w-3" />,
    label: 'Disconnected',
    dotClass: 'bg-red-500',
  },
  connecting: {
    icon: <CircleIcon className="h-3 w-3" />,
    label: 'Connecting...',
    dotClass: 'bg-yellow-500',
  },
}

export function DocumentEditor({ document: doc, workspace, user, canEdit }: Props) {
  const [title, setTitle] = useState(doc.title)
  const [titleSaving, setTitleSaving] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)
  const [lastSavedDisplay, setLastSavedDisplay] = useState<string>('')
  const [wordCount, setWordCount] = useState(0)
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting')
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

  const handleConnectionChange = useCallback((status: ConnectionStatus) => {
    setConnectionStatus(status)
  }, [])

  const currentConnection = CONNECTION_CONFIG[connectionStatus]

  return (
    <div className="mx-auto max-w-4xl space-y-3">
      <TooltipProvider>
        {/* Header row: back button, title, badges */}
        <div className="flex items-center gap-3">
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

          <div className="flex min-w-0 flex-1 items-center gap-3">
            {canEdit ? (
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') e.currentTarget.blur()
                }}
                className="min-w-0 flex-1 border-transparent border-b-2 bg-transparent font-semibold text-lg outline-none transition-colors focus:border-primary focus:ring-0"
                placeholder="Untitled"
              />
            ) : (
              <h1 className="min-w-0 truncate font-bold text-xl">{doc.title}</h1>
            )}

            {titleSaving && <span className="shrink-0 text-muted-foreground text-xs">Saving...</span>}
          </div>

          {canEdit ? (
            <Badge variant="secondary" className="shrink-0 bg-green-50 text-green-700">
              <PenIcon className="mr-1 h-3 w-3" /> Editing
            </Badge>
          ) : (
            <Badge variant="outline" className="shrink-0">
              <LockIcon className="mr-1 h-3 w-3" /> Read-only
            </Badge>
          )}
        </div>

        {/* Toolbar bar */}
        <div className="flex items-center gap-3 rounded-md border bg-muted/40 px-3 py-1.5 text-muted-foreground text-xs">
          <span>
            {wordCount} {wordCount === 1 ? 'word' : 'words'}
          </span>

          <Separator orientation="vertical" className="h-3" />

          <Tooltip>
            <TooltipTrigger asChild>
              <span className="flex cursor-default items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${currentConnection.dotClass}`} />
                {currentConnection.icon}
                {currentConnection.label}
              </span>
            </TooltipTrigger>
            <TooltipContent>
              {connectionStatus === 'connected' && 'Real-time sync is active'}
              {connectionStatus === 'syncing' && 'Synchronizing changes with server'}
              {connectionStatus === 'disconnected' && 'Connection lost. Attempting to reconnect...'}
              {connectionStatus === 'connecting' && 'Establishing connection...'}
            </TooltipContent>
          </Tooltip>

          <Separator orientation="vertical" className="h-3" />

          {lastSaved ? <span>Saved {lastSavedDisplay}</span> : <span>Not yet saved</span>}

          <Separator orientation="vertical" className="h-3" />

          {canEdit ? (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              Edit
            </Badge>
          ) : (
            <Badge variant="outline" className="h-5 px-1.5 text-[10px]">
              Read-only
            </Badge>
          )}
        </div>

        {/* Editor area */}
        <Card>
          <CardContent className="p-0">
            <CollaborativeEditor
              docId={doc.id}
              workspaceId={workspace.id}
              user={user}
              editable={canEdit}
              onWordCountChange={handleWordCountChange}
              onSynced={handleSynced}
              onConnectionChange={handleConnectionChange}
            />
          </CardContent>
        </Card>
      </TooltipProvider>
    </div>
  )
}
