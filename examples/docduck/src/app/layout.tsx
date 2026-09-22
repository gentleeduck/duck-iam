import type { Metadata } from 'next'
import { Inria_Serif, JetBrains_Mono } from 'next/font/google'
import { Toaster } from 'sonner'
import { IamDevtools } from '@/components/devtools/iam-devtools'
import './globals.css'

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
})

const inriaSerif = Inria_Serif({
  subsets: ['latin'],
  weight: ['300', '400', '700'],
  style: ['normal', 'italic'],
  variable: '--font-inria-serif',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'DocDuck — Collaborative Document Editor',
  description: 'A collaborative document editor showcasing @gentleduck/iam',
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/favicon-32.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon-16.png', sizes: '16x16', type: 'image/png' },
    ],
    apple: '/apple-touch-icon.png',
  },
  manifest: '/manifest.json',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="bun" className={`${jetbrainsMono.variable} ${inriaSerif.variable}`}>
      <body className={jetbrainsMono.className}>
        {children}
        <Toaster position="top-center" closeButton />
        {/* Written against `process.env.NODE_ENV` literally rather than
            through the `IAM_DEVTOOLS_ENABLED` constant the routes share:
            the bundler inlines this one and drops the panel from the
            production build, where an imported flag would keep it. The
            `/api/iam` routes refuse in production either way, and that is
            the check that actually protects anything. */}
        {process.env.NODE_ENV !== 'production' && <IamDevtools />}
      </body>
    </html>
  )
}
