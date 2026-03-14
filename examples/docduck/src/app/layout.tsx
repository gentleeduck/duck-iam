import type { Metadata } from 'next'
import { Inria_Serif, JetBrains_Mono } from 'next/font/google'
import { Toaster } from 'sonner'
import './globals.css'
import '@gentleduck/ui/styles.css'

const inriaSerif = Inria_Serif({
  subsets: ['latin'],
  weight: ['300', '400', '700'],
  style: ['normal', 'italic'],
  variable: '--font-serif',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'DocDuck — Collaborative Document Editor',
  description: 'A collaborative document editor showcasing @gentleduck/iam',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inriaSerif.variable} ${jetbrainsMono.variable}`}>
      <body className={inriaSerif.className}>
        {children}
        <Toaster position="bottom-right" richColors closeButton />
      </body>
    </html>
  )
}
