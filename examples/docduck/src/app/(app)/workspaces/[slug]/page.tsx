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

  // Serialize dates for client component
  const serializedDocs = docs.map((d) => ({
    ...d,
    createdAt: d.createdAt.toISOString(),
    updatedAt: d.updatedAt.toISOString(),
  }))

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="font-bold text-2xl">{workspace.name}</h1>
          <p className="mt-1 text-muted-foreground text-sm">Documents in this workspace</p>
        </div>
      </div>
      <DocumentList documents={serializedDocs} workspaceId={workspace.id} workspaceSlug={slug} />
    </div>
  )
}
