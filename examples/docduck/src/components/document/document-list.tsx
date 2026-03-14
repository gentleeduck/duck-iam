'use client'

import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@gentleduck/ui/card'
import { Input } from '@gentleduck/ui/input'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/ui/tooltip'
import { FileTextIcon, GlobeIcon, LockIcon, PlusIcon, SearchIcon, TrashIcon } from 'lucide-react'
import Link from 'next/link'
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

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <SearchIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter documents by title..."
            className="pl-9"
          />
        </div>

        <Can action="create" resource="document">
          <Button type="button" onClick={handleCreate} loading={creating}>
            <PlusIcon className="h-4 w-4" />
            {creating ? 'Creating...' : 'New Document'}
          </Button>
        </Can>
      </div>

      <Cannot action="create" resource="document">
        <p className="text-muted-foreground text-sm">
          You don&apos;t have permission to create documents in this workspace.
        </p>
      </Cannot>

      {filteredDocuments.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <FileTextIcon className="mx-auto h-10 w-10 text-muted-foreground" />
          <p className="mt-2 text-muted-foreground text-sm">
            {search ? 'No documents match your search' : 'No documents yet'}
          </p>
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {filteredDocuments.map((doc) => (
            <Card key={doc.id} className="group transition-colors hover:bg-accent/50">
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between gap-2">
                  <Link href={`/workspaces/${workspaceSlug}/documents/${doc.id}`} className="min-w-0 flex-1">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <FileTextIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <span className="truncate">{doc.title}</span>
                    </CardTitle>
                  </Link>
                  <Badge variant={doc.isPublic ? 'secondary' : 'outline'}>
                    {doc.isPublic ? (
                      <span className="flex items-center gap-1">
                        <GlobeIcon className="h-3 w-3" /> Public
                      </span>
                    ) : (
                      <span className="flex items-center gap-1">
                        <LockIcon className="h-3 w-3" /> Private
                      </span>
                    )}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <p className="mb-3 text-muted-foreground text-xs">
                  Updated{' '}
                  <span>
                    {new Date(doc.updatedAt).toLocaleDateString(undefined, {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                    })}
                  </span>
                  <span className="hidden sm:inline">
                    {' '}
                    {new Date(doc.updatedAt).toLocaleTimeString(undefined, {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </span>
                </p>
                <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                  <TooltipProvider>
                    <Can action="share" resource="document">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button type="button" variant="ghost" size="icon" onClick={() => handleTogglePublic(doc.id)}>
                            {doc.isPublic ? <LockIcon className="h-4 w-4" /> : <GlobeIcon className="h-4 w-4" />}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>{doc.isPublic ? 'Make private' : 'Make public'}</TooltipContent>
                      </Tooltip>
                    </Can>

                    <Can action="delete" resource="document">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button type="button" variant="ghost" size="icon" onClick={() => handleDelete(doc.id)}>
                            <TrashIcon className="h-4 w-4 text-destructive" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Delete document</TooltipContent>
                      </Tooltip>
                    </Can>
                  </TooltipProvider>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
