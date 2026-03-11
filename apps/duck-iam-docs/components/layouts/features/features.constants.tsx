import { Layers, Puzzle, Server, Shield, Terminal, Zap } from 'lucide-react'
export const features = [
  {
    bgColor: 'rgba(59, 130, 246, 0.1)',
    description:
      'Combine role-based and attribute-based access control in one engine. Define roles with inheritance, then layer on fine-grained ABAC policies.',
    icon: <Shield aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(59, 130, 246)',
    title: 'RBAC + ABAC',
  },
  {
    bgColor: 'rgba(234, 179, 8, 0.1)',
    description:
      'Define actions, resources, and scopes with const assertions. Typos become compile errors, not runtime bugs.',
    icon: <Zap aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(234, 179, 8)',
    title: 'Type-Safe Permissions',
  },
  {
    bgColor: 'rgba(168, 85, 247, 0.1)',
    description:
      'Built-in support for multi-tenant scoped roles. A user can be an editor in org-1 and a viewer in org-2.',
    icon: <Layers aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(168, 85, 247)',
    title: 'Multi-Tenant Scopes',
  },
  {
    bgColor: 'rgba(34, 197, 94, 0.1)',
    description:
      'Ready-made middleware for Express, Hono, NestJS, and Next.js. Client providers for React, Vue, and vanilla JS.',
    icon: <Server aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(34, 197, 94)',
    title: 'Framework Integrations',
  },
  {
    bgColor: 'rgba(249, 115, 22, 0.1)',
    description:
      'Call engine.explain() to get a full trace of every policy, rule, and condition with actual vs expected values.',
    icon: <Terminal aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(249, 115, 22)',
    title: 'Explain & Debug',
  },
  {
    bgColor: 'rgba(14, 165, 233, 0.1)',
    description:
      'Store policies and roles anywhere. Ship with Memory, Prisma, Drizzle, and HTTP adapters out of the box.',
    icon: <Puzzle aria-hidden="true" className="h-7 w-7" />,
    textColor: 'rgb(14, 165, 233)',
    title: 'Pluggable Adapters',
  },
]
