'use client'

import { features } from './features.constants'

function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={className} {...props} />
}

function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={className} {...props} />
}

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
          className="mb-3 flex h-14 w-14 items-center justify-center rounded-lg transition-all duration-300 group-hover:scale-105"
          style={{ backgroundColor: feature.bgColor, color: feature.textColor }}>
          {feature.icon}
        </div>
        <CardTitle className="mb-1 font-semibold text-xl tracking-tight">{feature.title}</CardTitle>
        <p className="text-muted-foreground">{feature.description}</p>
      </div>
    </Card>
  )
}

export function FeaturesSection() {
  return (
    <section aria-labelledby="features-heading" className="relative" id="features">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-32 -left-20 z-0 h-[12rem] w-[12rem] rounded-full bg-gradient-to-br from-purple-500/12 to-indigo-400/8 blur-[90px] md:h-[18rem] md:w-[18rem]"></div>
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-20 -bottom-32 z-0 h-[10rem] w-[10rem] rounded-full bg-gradient-to-tl from-blue-500/10 to-cyan-400/6 blur-[100px] md:h-[16rem] md:w-[16rem]"></div>
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-40 right-1/3 z-0 h-[8rem] w-[8rem] rounded-full bg-gradient-to-r from-emerald-400/5 to-teal-400/4 blur-[80px] md:h-[14rem] md:w-[14rem]"></div>

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
