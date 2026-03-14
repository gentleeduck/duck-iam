import { Avatar, AvatarFallback } from '@gentleduck/ui/avatar'
import { Badge } from '@gentleduck/ui/badge'
import { redirect } from 'next/navigation'
import { DocumentList } from '@/components/document/document-list'
import { getDocuments } from '@/server/actions/document'
import { getWorkspaceBySlug } from '@/server/actions/workspace'

interface Props {
  params: Promise<{ slug: string }>
}

export default async function WorkspaceDocumentsPage({ params }: Props) {
  const { slug } = await params
  const workspace = await getWorkspaceBySlug(slug)
  if (!workspace) redirect('/workspaces')

  const docs = await getDocuments(workspace.id)

  const serializedDocs = docs.map((d) => ({
    ...d,
    createdAt: d.createdAt.toISOString(),
    updatedAt: d.updatedAt.toISOString(),
  }))

  return (
    <div>
      <div className="mb-8 flex items-start gap-4">
        <Avatar className="h-14 w-14 shrink-0 rounded-xl shadow-sm">
          <AvatarFallback className="rounded-xl bg-gradient-to-br from-primary to-primary/70 font-bold text-lg text-primary-foreground">
            {workspace.name.charAt(0).toUpperCase()}
          </AvatarFallback>
        </Avatar>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <h1 className="truncate font-bold text-2xl leading-tight">{workspace.name}</h1>
            <Badge variant="secondary" className="shrink-0 font-medium">
              {docs.length} {docs.length === 1 ? 'document' : 'documents'}
            </Badge>
          </div>
          <p className="mt-1 text-muted-foreground text-sm">Manage and organize documents in this workspace</p>
        </div>
      </div>
      <DocumentList documents={serializedDocs} workspaceId={workspace.id} workspaceSlug={slug} />
    </div>
  )
}
