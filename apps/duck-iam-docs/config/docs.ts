import type { DocsConfig } from '@gentleduck/docs/context'

export const docsConfig = {
  chartsNav: [],
  mainNav: [
    {
      href: '/docs',
      title: 'Documentation',
    },
  ],
  sidebarNav: [
    {
      collapsible: false,
      items: [
        {
          href: '/docs',
          title: 'Introduction',
        },
        {
          href: '/docs/installation',
          title: 'Installation',
        },
        {
          href: '/docs/guides',
          title: 'Quick Start',
        },
        {
          href: '/docs/faqs',
          title: 'FAQs',
        },
      ],
      title: 'Getting Started',
    },
    {
      collapsible: false,
      items: [
        {
          href: '/docs/core',
          title: 'Overview',
        },
        {
          href: '/docs/core/roles',
          title: 'Roles & Permissions',
        },
        {
          href: '/docs/core/policies',
          title: 'Policies & Rules',
        },
      ],
      title: 'Core Concepts',
    },
    {
      collapsible: false,
      items: [
        {
          href: '/docs/integrations/server',
          title: 'Server Middleware',
        },
        {
          href: '/docs/integrations/client',
          title: 'Client Libraries',
        },
        {
          href: '/docs/integrations/adapters',
          title: 'Database Adapters',
        },
      ],
      title: 'Integrations',
    },
    {
      collapsible: false,
      items: [
        {
          href: '/docs/advanced/engine',
          title: 'Engine API',
        },
        {
          href: '/docs/advanced/explain',
          title: 'Explain & Debug',
        },
        {
          href: '/docs/advanced/config',
          title: 'Type-Safe Config',
        },
        {
          href: '/docs/advanced/utilities',
          title: 'Utilities',
        },
        {
          href: '/docs/benchmarks',
          title: 'Benchmarks',
        },
      ],
      title: 'Advanced',
    },
    {
      collapsible: false,
      items: [
        {
          href: '/docs/course',
          title: 'Course Overview',
        },
        {
          href: '/docs/course/chapter-1',
          title: '1. First Permission Check',
        },
        {
          href: '/docs/course/chapter-2',
          title: '2. Role Hierarchies',
        },
        {
          href: '/docs/course/chapter-3',
          title: '3. Policies & Conditions',
        },
        {
          href: '/docs/course/chapter-4',
          title: '4. Engine In Depth',
        },
        {
          href: '/docs/course/chapter-5',
          title: '5. Multi-Tenant Scoping',
        },
        {
          href: '/docs/course/chapter-6',
          title: '6. Server Integration',
        },
        {
          href: '/docs/course/chapter-7',
          title: '7. Client Libraries',
        },
        {
          href: '/docs/course/chapter-8',
          title: '8. Production Readiness',
        },
      ],
      title: 'Course',
    },
    {
      collapsible: false,
      items: [
        {
          href: '/docs/skills',
          title: 'Agent Skills',
        },
      ],
      title: 'AI & Agents',
    },
  ],
} satisfies DocsConfig

type NavItem = {
  title: string
  href?: string
  label?: string
  items?: NavItem[]
}

function extractTitles(navItems: NavItem[]): string[] {
  const titles: string[] = []

  for (const item of navItems) {
    if (item.title) {
      titles.push(item.title)
    }

    if (item.items && item.items.length > 0) {
      titles.push(...extractTitles(item.items))
    }
  }

  return titles
}

export const allTitles = [
  ...extractTitles(docsConfig.mainNav),
  ...extractTitles(docsConfig.sidebarNav),
  ...extractTitles(docsConfig.chartsNav),
]
