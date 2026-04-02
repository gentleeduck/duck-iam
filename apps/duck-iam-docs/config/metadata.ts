import { absoluteUrl } from '@gentleduck/docs/lib'
import type { Metadata, Viewport } from 'next'
import { siteConfig } from './site'

export const VIEWPORT: Viewport = {
  themeColor: [
    { color: 'white', media: '(prefers-color-scheme: light)' },
    { color: 'black', media: '(prefers-color-scheme: dark)' },
  ],
}

export const METADATA: Metadata = {
  alternates: {
    canonical: siteConfig.url,
  },
  authors: [
    {
      name: 'wildduck2',
      url: 'https://github.com/wildduck2',
    },
  ],
  creator: 'wildduck2',
  description: siteConfig.description,
  icons: {
    apple: '/apple-touch-icon.png',
    icon: '/favicon.ico',
    shortcut: '/favicon-96x96.png',
  },
  keywords: [
    'duck-iam',
    'access control',
    'rbac',
    'abac',
    'authorization',
    'permissions',
    'typescript access control',
    'role based access control',
    'attribute based access control',
    'policy engine',
    'express middleware',
    'nestjs guard',
    'hono middleware',
    'nextjs authorization',
    'react permissions',
    'vue permissions',
    'type-safe permissions',
  ],
  manifest: `${siteConfig.url}/site.webmanifest`,
  metadataBase: new URL(
    process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL}`
      : siteConfig.url.startsWith('http')
        ? siteConfig.url
        : 'http://localhost:3000',
  ),
  openGraph: {
    description: siteConfig.description,
    images: [
      {
        url: `/og?title=${encodeURIComponent(siteConfig.name)}&description=${encodeURIComponent(siteConfig.title)}`,
      },
    ],
    locale: 'en_US',
    siteName: siteConfig.name,
    title: siteConfig.name,
    type: 'website',
    url: siteConfig.url,
  },
  title: {
    default: siteConfig.name,
    template: `%s - ${siteConfig.name}`,
  },
  twitter: {
    card: 'summary_large_image',
    creator: '@gentleduck',
    description: siteConfig.description,
    images: [
      {
        url: `/og?title=${encodeURIComponent(siteConfig.name)}&description=${encodeURIComponent(siteConfig.title)}`,
      },
    ],
    title: siteConfig.name,
  },
}

export const SLUG_METADATA = (doc: { title: string; description: string; slug: string }): Metadata => {
  const ogUrl = `/og?title=${encodeURIComponent(doc.title)}&description=${encodeURIComponent(doc.description)}`
  return {
    ...METADATA,
    alternates: {
      canonical: absoluteUrl(doc.slug),
    },
    description: doc.description,
    openGraph: {
      ...METADATA.openGraph,
      description: doc.description,
      images: [{ url: ogUrl }],
      title: doc.title,
      type: 'article',
      url: absoluteUrl(doc.slug),
    },
    title: doc.title,
    twitter: {
      ...METADATA.twitter,
      description: doc.description,
      images: [{ url: ogUrl }],
      title: doc.title,
    },
  }
}
