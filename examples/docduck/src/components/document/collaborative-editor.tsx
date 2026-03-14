'use client'

import { BlockNoteView } from '@blocknote/mantine'
import { useCreateBlockNote } from '@blocknote/react'
import { Badge } from '@gentleduck/ui/badge'
import { Separator } from '@gentleduck/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/ui/tooltip'
import { HocuspocusProvider } from '@hocuspocus/provider'
import { CircleIcon, Loader2Icon, WifiIcon, WifiOffIcon } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import * as Y from 'yjs'
import { PresenceAvatars } from './presence-avatars'
import '@blocknote/core/fonts/inter.css'
import '@blocknote/mantine/style.css'

interface Props {
  docId: string
  workspaceId: string
  user: { id: string; name: string; email: string }
  editable: boolean
  onWordCountChange?: (count: number) => void
  onSynced?: () => void
}

type ConnectionStatus = 'connecting' | 'connected' | 'syncing' | 'disconnected'

const COLORS = ['#958DF1', '#F98181', '#FBBC88', '#FAF594', '#70CFF8', '#94FADB', '#B9F18D', '#C3E2C2']

export function CollaborativeEditor({ docId, workspaceId, user, editable, onWordCountChange, onSynced }: Props) {
  const [status, setStatus] = useState<ConnectionStatus>('connecting')
  const [ready, setReady] = useState(false)
  const ydocRef = useRef<Y.Doc | null>(null)
  const providerRef = useRef<HocuspocusProvider | null>(null)
  const disconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const setStatusDebounced = useCallback((newStatus: ConnectionStatus) => {
    if (disconnectTimeoutRef.current) {
      clearTimeout(disconnectTimeoutRef.current)
      disconnectTimeoutRef.current = null
    }

    // Delay showing "disconnected" by 1 second to avoid flicker on brief hiccups
    if (newStatus === 'disconnected') {
      disconnectTimeoutRef.current = setTimeout(() => {
        setStatus('disconnected')
      }, 1000)
    } else {
      setStatus(newStatus)
    }
  }, [])

  useEffect(() => {
    const ydoc = new Y.Doc()
    const provider = new HocuspocusProvider({
      url: process.env.NEXT_PUBLIC_HOCUSPOCUS_URL ?? 'ws://localhost:8888',
      name: docId,
      document: ydoc,
      token: JSON.stringify({ userId: user.id, workspaceId }),
      onConnect: () => setStatusDebounced('connected'),
      onDisconnect: () => setStatusDebounced('disconnected'),
      onSynced: () => {
        setStatusDebounced('connected')
        setReady(true)
        onSynced?.()
      },
      onStatus: ({ status: s }) => {
        if (s === 'connecting') setStatusDebounced('syncing')
      },
    })

    ydocRef.current = ydoc
    providerRef.current = provider

    return () => {
      if (disconnectTimeoutRef.current) clearTimeout(disconnectTimeoutRef.current)
      provider.destroy()
      ydoc.destroy()
      ydocRef.current = null
      providerRef.current = null
      setReady(false)
      setStatus('connecting')
    }
  }, [docId, workspaceId, user.id, onSynced, setStatusDebounced])

  if (!ready || !ydocRef.current || !providerRef.current) {
    return (
      <div className="flex min-h-[500px] items-center justify-center">
        <div className="flex items-center gap-2 text-muted-foreground text-sm">
          <Loader2Icon className="h-4 w-4 animate-spin" />
          Connecting to document...
        </div>
      </div>
    )
  }

  return (
    <EditorContent
      ydoc={ydocRef.current}
      provider={providerRef.current}
      user={user}
      editable={editable}
      status={status}
      onWordCountChange={onWordCountChange}
    />
  )
}

function EditorContent({
  ydoc,
  provider,
  user,
  editable,
  status,
  onWordCountChange,
}: {
  ydoc: Y.Doc
  provider: HocuspocusProvider
  user: { name: string }
  editable: boolean
  status: ConnectionStatus
  onWordCountChange?: (count: number) => void
}) {
  const color = useRef(COLORS[Math.floor(Math.random() * COLORS.length)] ?? '#958DF1').current

  const editor = useCreateBlockNote({
    collaboration: {
      provider,
      fragment: ydoc.getXmlFragment('document-store'),
      user: {
        name: user.name,
        color,
      },
    },
  })

  useEffect(() => {
    if (!onWordCountChange) return

    const fragment = ydoc.getXmlFragment('document-store')

    function countWords() {
      const text = fragment.toDOM().textContent ?? ''
      const words = text.trim().split(/\s+/).filter(Boolean)
      onWordCountChange(words.length)
    }

    countWords()
    fragment.observeDeep(countWords)

    return () => {
      fragment.unobserveDeep(countWords)
    }
  }, [ydoc, onWordCountChange])

  const statusConfig: Record<ConnectionStatus, { icon: React.ReactNode; label: string; dotClass: string }> = {
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
      label: 'Disconnected - Reconnecting...',
      dotClass: 'bg-red-500',
    },
    connecting: {
      icon: <CircleIcon className="h-3 w-3" />,
      label: 'Connecting...',
      dotClass: 'bg-yellow-500',
    },
  }

  const currentStatus = statusConfig[status]

  return (
    <div className="min-h-[500px]">
      <div className="flex items-center justify-between px-3 pt-2">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge
                variant={status === 'connected' ? 'secondary' : status === 'disconnected' ? 'destructive' : 'outline'}
                className="cursor-default gap-1.5 text-xs">
                <span className={`h-1.5 w-1.5 rounded-full ${currentStatus.dotClass}`} />
                {currentStatus.icon}
                {currentStatus.label}
              </Badge>
            </TooltipTrigger>
            <TooltipContent>
              {status === 'connected' && 'Real-time sync is active'}
              {status === 'syncing' && 'Synchronizing changes with server'}
              {status === 'disconnected' && 'Connection lost. Attempting to reconnect...'}
              {status === 'connecting' && 'Establishing connection...'}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        <PresenceAvatars provider={provider} />
      </div>

      <Separator className="my-2" />

      <BlockNoteView editor={editor} editable={editable} theme="light" />
    </div>
  )
}
