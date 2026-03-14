import type { Metadata } from 'next'
import { Inria_Serif, JetBrains_Mono } from 'next/font/google'
import { Toaster } from 'sonner'
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
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${jetbrainsMono.variable} ${inriaSerif.variable}`}>
      <body className={jetbrainsMono.className}>
        {children}
        <Toaster position="bottom-right" richColors closeButton />
      </body>
    </html>
  )
}
