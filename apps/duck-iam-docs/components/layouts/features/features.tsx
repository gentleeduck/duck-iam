'use client'

<<<<<<< HEAD:apps/duck-iam-docs/components/layouts/features/features.tsx
import { features } from './features.constants'
import type React from 'react'

function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={className} {...props} />
}

function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={className} {...props} />
}
=======
import { Card, CardTitle } from '@gentleduck/registry-ui/card'
import { FileText, Layers, Puzzle, Server, Terminal, Zap } from 'lucide-react'
>>>>>>> 68028f2b8f071c10853ff31e15c817d8fd06f964:apps/duck-gen-docs/components/layouts/features/features.tsx

export function SectionTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mx-auto mb-12 max-w-2xl text-center md:mb-16">
      <h2 className="font-medium text-5xl uppercase sm:text-4xl">{title}</h2>
      <p className="mt-4 max-w-2xl text-center text-lg text-muted-foreground">{subtitle}</p>
    </div>
  )
}

function FeatureCard({
  feature,
}: {
  feature: { bgColor: string; description: string; icon: React.ReactNode; textColor: string; title: string }
}) {
  return (
    <Card className="group overflow-hidden rounded-xl border border-border/60 bg-background/60 p-1 shadow-sm transition-all duration-300 hover:border-border hover:shadow-md">
      <div className="relative p-5">
        <div
          aria-hidden="true"
          className={`mb-3 flex h-14 w-14 items-center justify-center rounded-lg ${feature.bgColor} ${feature.textColor} transition-all duration-300 group-hover:scale-105`}>
          {feature.icon}
        </div>
        <CardTitle className="mb-1 font-semibold text-xl tracking-tight">{feature.title}</CardTitle>
        <p className="text-muted-foreground">{feature.description}</p>
      </div>
    </Card>
  )
}

const features = [
  {
    bgColor: 'bg-blue-500/10',
    description: 'Generate API contracts from framework controllers so clients stay aligned -- tested with NestJS.',
    icon: <Zap aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-blue-500',
    title: 'Contract-First Generation',
  },
  {
    bgColor: 'bg-yellow-500/10',
    description: 'Create request and response types for every route without manual duplication.',
    icon: <Server aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-yellow-500',
    title: 'Typed Routes & DTOs',
  },
  {
    bgColor: 'bg-purple-500/10',
    description: 'Extract message tags into typed keys for predictable i18n workflows.',
    icon: <FileText aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-purple-500',
    title: 'Message Tag Safety',
  },
  {
    bgColor: 'bg-green-500/10',
    description: 'Produce structured outputs that plug into clients, SDKs, and docs.',
    icon: <Layers aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-green-500',
    title: 'Composable Output',
  },
  {
    bgColor: 'bg-orange-500/10',
    description: 'Generate once or stay in sync during development with watch mode.',
    icon: <Terminal aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-orange-500',
    title: 'CLI + Watch Mode',
  },
  {
    bgColor: 'bg-sky-500/10',
    description: 'Built for multiple frameworks, currently being tested with NestJS.',
    icon: <Puzzle aria-hidden="true" className="h-7 w-7" />,
    textColor: 'text-sky-500',
    title: 'Framework Friendly',
  },
]

export function FeaturesSection() {
  return (
    <section aria-labelledby="features-heading" className="relative" id="features">
      <div
        aria-hidden="true"
        className="absolute top-1/4 left-1/4 z-0 h-64 w-64 rounded-full bg-purple-500/20 blur-3xl"></div>
      <div
        aria-hidden="true"
        className="absolute right-1/4 bottom-1/4 z-0 h-72 w-72 rounded-full bg-blue-500/20 blur-3xl"></div>

      <div className="container relative mx-auto py-24 sm:py-32 lg:py-40">
        <SectionTitle
          subtitle="Type-safe RBAC + ABAC access control engine for TypeScript with framework integrations for Express, NestJS, Hono, Next.js, React, and Vue."
          title="Built for duck-iam"
        />

        <div className="mt-16 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, i) => (
            <FeatureCard feature={feature} key={i} />
          ))}
        </div>
      </div>
    </section>
  )
}
