'use client'

import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Card, CardContent } from '@gentleduck/ui/card'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@gentleduck/ui/context-menu'
import { Input } from '@gentleduck/ui/input'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/ui/tooltip'
import { EditIcon, FileTextIcon, GlobeIcon, LockIcon, PlusIcon, SearchIcon, TrashIcon } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useMemo, useState } from 'react'
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
  const [search, setSearch] = useState('')

  const filteredDocuments = useMemo(() => {
    const query = search.toLowerCase().trim()
    const filtered = query ? documents.filter((doc) => doc.title.toLowerCase().includes(query)) : documents

    return [...filtered].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
  }, [documents, search])

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

  function formatDate(dateString: string): string {
    const date = new Date(dateString)
    return date.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  function formatTime(dateString: string): string {
    const date = new Date(dateString)
    return date.toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Sticky header with search and create */}
      <div className="sticky top-0 z-10 -mx-1 bg-background/95 px-1 pb-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <SearchIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search documents..."
              className="pl-9"
            />
          </div>

          <Can action="create" resource="document">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button type="button" onClick={handleCreate} loading={creating}>
                    <PlusIcon className="h-4 w-4" />
                    {creating ? 'Creating...' : 'New Document'}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Create a new document in this workspace</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </Can>
        </div>

        <Cannot action="create" resource="document">
          <p className="mt-2 text-muted-foreground text-sm">
            You don&apos;t have permission to create documents in this workspace.
          </p>
        </Cannot>
      </div>

      {/* Document grid or empty state */}
      {filteredDocuments.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-muted-foreground/25 border-dashed py-20">
          <div className="relative mb-4">
            <FileTextIcon className="h-16 w-16 text-muted-foreground/30" />
            <SearchIcon className="absolute -right-1 -bottom-1 h-6 w-6 text-muted-foreground/50" />
          </div>
          <p className="font-medium text-muted-foreground">
            {search ? 'No documents match your search' : 'No documents yet'}
          </p>
          <p className="mt-1 max-w-sm text-center text-muted-foreground/70 text-xs">
            {search
              ? 'Try adjusting your search terms or clearing the filter.'
              : 'Create your first document to get started. Documents can be public or private.'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))' }}>
          {filteredDocuments.map((doc) => (
            <ContextMenu key={doc.id}>
              <ContextMenuTrigger asChild>
                <Card
                  className={`group relative cursor-pointer overflow-hidden transition-all duration-200 hover:scale-[1.02] hover:shadow-lg ${
                    doc.isPublic
                      ? 'border-l-4 border-l-pink-400/80 hover:border-l-pink-500'
                      : 'border-l-4 border-l-muted-foreground/20 hover:border-l-muted-foreground/40'
                  } hover:bg-accent/30`}
                  onClick={() => router.push(`/workspaces/${workspaceSlug}/documents/${doc.id}`)}>
                  {/* Watermark file icon */}
                  <FileTextIcon className="pointer-events-none absolute -right-3 -bottom-3 h-24 w-24 rotate-12 text-muted-foreground/[0.04] transition-all duration-300 group-hover:text-muted-foreground/[0.08]" />

                  <CardContent className="relative z-[1] flex flex-col gap-3 p-4">
                    {/* Title row */}
                    <div className="flex items-start gap-2.5">
                      <FileTextIcon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground/60" />
                      <span className="truncate font-semibold text-sm leading-tight">{doc.title}</span>
                    </div>

                    {/* Meta row */}
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant={doc.isPublic ? 'secondary' : 'outline'} className="shrink-0 gap-1 text-[10px]">
                        {doc.isPublic ? (
                          <>
                            <GlobeIcon className="h-3 w-3" />
                            Public
                          </>
                        ) : (
                          <>
                            <LockIcon className="h-3 w-3" />
                            Private
                          </>
                        )}
                      </Badge>

                      <span className="truncate text-muted-foreground/70 text-xs">
                        {formatDate(doc.updatedAt)}
                        <span className="hidden sm:inline"> {formatTime(doc.updatedAt)}</span>
                      </span>
                    </div>
                  </CardContent>
                </Card>
              </ContextMenuTrigger>

              <ContextMenuContent className="w-48">
                <ContextMenuItem onClick={() => router.push(`/workspaces/${workspaceSlug}/documents/${doc.id}`)}>
                  <FileTextIcon className="mr-2 h-4 w-4" />
                  Open
                </ContextMenuItem>

                <ContextMenuItem disabled>
                  <EditIcon className="mr-2 h-4 w-4" />
                  Rename
                </ContextMenuItem>

                <Can action="share" resource="document">
                  <ContextMenuItem onClick={() => handleTogglePublic(doc.id)}>
                    {doc.isPublic ? (
                      <>
                        <LockIcon className="mr-2 h-4 w-4" />
                        Make Private
                      </>
                    ) : (
                      <>
                        <GlobeIcon className="mr-2 h-4 w-4" />
                        Make Public
                      </>
                    )}
                  </ContextMenuItem>
                </Can>

                <Can action="delete" resource="document">
                  <ContextMenuSeparator />
                  <ContextMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={() => handleDelete(doc.id)}>
                    <TrashIcon className="mr-2 h-4 w-4" />
                    Delete
                  </ContextMenuItem>
                </Can>
              </ContextMenuContent>
            </ContextMenu>
          ))}
        </div>
      )}
    </div>
  )
}
