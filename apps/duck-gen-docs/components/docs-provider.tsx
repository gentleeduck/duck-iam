'use client'

import type { DocsConfig, DocsEntry, DocsSiteConfig } from '@gentleduck/docs'
import { DocsProvider } from '@gentleduck/docs/client'
import type React from 'react'

type DocsProviderProps = {
  children: React.ReactNode
  docs?: DocsEntry[]
  docsConfig: DocsConfig
  siteConfig: DocsSiteConfig
}

export function DocsAppProvider({ children, docs, docsConfig, siteConfig }: DocsProviderProps) {
  return (
    <DocsProvider docs={docs} docsConfig={docsConfig} siteConfig={siteConfig}>
      {children}
    </DocsProvider>
  )
}
