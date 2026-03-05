import type { Metadata } from 'next'
import './globals.css'
import '@gentleduck/motion/css'
import { TailwindIndicator, ThemeProvider } from '@gentleduck/docs/client'
import { cn } from '@gentleduck/libs/cn'
<<<<<<< HEAD:apps/duck-iam-docs/app/layout.tsx
import { KeyProvider } from '@gentleduck/vim/react'
import { Geist_Mono, Montserrat } from 'next/font/google'
=======
import { DirectionProvider } from '@gentleduck/registry-ui/direction'
import { GeistMono } from 'geist/font/mono'
import { GeistSans } from 'geist/font/sans'
import { AppClientProviders } from '~/components/app-client-providers'
import { DocsAppProvider } from '~/components/docs-provider'
import { ThemeWrapper } from '~/components/themes'
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/app/layout.tsx
import { docsConfig } from '~/config/docs'
import { METADATA } from '~/config/metadata'
import { META_THEME_COLORS, siteConfig } from '~/config/site'
import { docs } from '../.velite'

const docsEntries = docs.map((doc) => {
  const slug = doc.slug.startsWith('/') ? doc.slug : `/${doc.slug}`
  return {
    component: doc.component,
    permalink: slug,
    slug,
    title: doc.title,
    toc: doc.toc,
  }
})

const docsSiteConfig = {
  ...siteConfig,
  metaThemeColors: META_THEME_COLORS,
}

export const metadata: Metadata = {
  ...METADATA,
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html className={`${GeistSans.variable} ${GeistMono.variable}`} dir="ltr" lang="en" suppressHydrationWarning>
      <head>
        {process.env.NODE_ENV === 'development' && (
          <script crossOrigin="anonymous" src="//unpkg.com/react-scan/dist/auto.global.js" />
        )}

        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var raw = localStorage.getItem('fontType');
                  var fontType = raw ? JSON.parse(raw) : 'mono';
                  var family = fontType === 'sans'
                    ? 'var(--font-geist-sans, "Geist"), sans-serif'
                    : 'var(--font-geist-mono, "Geist Mono"), monospace';
                  document.documentElement.style.setProperty('font-family', family, 'important');
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body className={cn('duck min-h-svh bg-background antialiased')}>
<<<<<<< HEAD:apps/duck-iam-docs/app/layout.tsx
        <KeyProvider timeoutMs={100}>
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            disableTransitionOnChange
            enableColorScheme
            enableSystem>
            <DocsProvider docs={docsEntries} docsConfig={docsConfig} siteConfig={docsSiteConfig}>
              <div vaul-drawer-wrapper="">
                <div className="relative flex min-h-svh flex-col bg-background">{children}</div>
              </div>
            </DocsProvider>
            {process.env.NODE_ENV === 'development' && <TailwindIndicator />}
          </ThemeProvider>
        </KeyProvider>
=======
        <ThemeProvider attribute="class" defaultTheme="system" disableTransitionOnChange enableColorScheme enableSystem>
          <AppClientProviders>
            <DirectionProvider dir="ltr">
              <DocsAppProvider docs={docsEntries} docsConfig={docsConfig} siteConfig={docsSiteConfig}>
                <ThemeWrapper>
                  <div vaul-drawer-wrapper="">
                    <div className="relative flex min-h-svh flex-col bg-background">{children}</div>
                  </div>

                  {process.env.NODE_ENV === 'development' && <TailwindIndicator />}
                </ThemeWrapper>
              </DocsAppProvider>
            </DirectionProvider>
          </AppClientProviders>
        </ThemeProvider>
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/app/layout.tsx
      </body>
    </html>
  )
}
