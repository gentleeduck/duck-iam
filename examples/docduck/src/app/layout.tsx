import type { Metadata } from 'next'
import { Toaster } from 'sonner'
import './globals.css'
import '@gentleduck/ui/styles.css'

export const metadata: Metadata = {
  title: 'DocDuck — Collaborative Document Editor',
  description: 'A collaborative document editor showcasing @gentleduck/iam',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Toaster position="bottom-right" />
      </body>
    </html>
  )
}
