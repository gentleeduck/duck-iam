'use client'

import { BlockNoteView } from '@blocknote/mantine'
import { useCreateBlockNote } from '@blocknote/react'
import { HocuspocusProvider } from '@hocuspocus/provider'
import { useEffect, useRef, useState } from 'react'
import * as Y from 'yjs'
import '@blocknote/core/fonts/inter.css'
import '@blocknote/mantine/style.css'

interface Props {
  docId: string
  workspaceId: string
  user: { id: string; name: string; email: string }
  editable: boolean
}

const COLORS = ['#958DF1', '#F98181', '#FBBC88', '#FAF594', '#70CFF8', '#94FADB', '#B9F18D', '#C3E2C2']

export function CollaborativeEditor({ docId, workspaceId, user, editable }: Props) {
  const [connected, setConnected] = useState(false)
  const [ready, setReady] = useState(false)
  const ydocRef = useRef<Y.Doc | null>(null)
  const providerRef = useRef<HocuspocusProvider | null>(null)

  useEffect(() => {
    const ydoc = new Y.Doc()
    const provider = new HocuspocusProvider({
      url: process.env.NEXT_PUBLIC_HOCUSPOCUS_URL ?? 'ws://localhost:8888',
      name: docId,
      document: ydoc,
      token: JSON.stringify({ userId: user.id, workspaceId }),
      onConnect: () => setConnected(true),
      onDisconnect: () => setConnected(false),
      onSynced: () => setReady(true),
    })

    ydocRef.current = ydoc
    providerRef.current = provider

    return () => {
      provider.destroy()
      ydoc.destroy()
      ydocRef.current = null
      providerRef.current = null
      setReady(false)
      setConnected(false)
    }
  }, [docId, workspaceId, user.id])

  if (!ready || !ydocRef.current || !providerRef.current) {
    return (
      <div className="flex min-h-[500px] items-center justify-center">
        <div className="flex items-center gap-2 text-muted-foreground text-sm">
          <span className="h-2 w-2 animate-pulse rounded-full bg-yellow-500" />
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
      connected={connected}
    />
  )
}

function EditorContent({
  ydoc,
  provider,
  user,
  editable,
  connected,
}: {
  ydoc: Y.Doc
  provider: HocuspocusProvider
  user: { name: string }
  editable: boolean
  connected: boolean
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

  return (
    <div className="min-h-[500px]">
      <div className="mb-2 flex items-center gap-2 px-3 pt-2">
        <span className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
        <span className="text-muted-foreground text-xs">{connected ? 'Connected' : 'Reconnecting...'}</span>
      </div>
      <BlockNoteView editor={editor} editable={editable} theme="light" />
    </div>
  )
}
