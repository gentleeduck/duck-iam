import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import { AuthProvider } from './provider'
import './globals.css'

export const metadata: Metadata = {
  title: 'DuckMarket — duck-iam Next.js example',
  description: 'duck-iam authorization wired through Next.js Route Handlers and React UI gating.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  )
}
