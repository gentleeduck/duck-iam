import Link from 'next/link'
import { SectionTitle } from '../features'
import { packages } from './core-packages.constants'

function EcosystemCard({ pkg, index }: { pkg: (typeof packages)[number]; index: number }) {
  const Icon = pkg.icon
  const statusStyles: Record<string, string> = {
    new: 'border border-green-500/20 bg-green-500/10 text-green-600',
    planned: 'border border-orange-500/20 bg-orange-500/10 text-orange-600',
    'under development': 'border border-zinc-400/20 bg-zinc-500/5 text-zinc-500',
    'waiting for docs': 'border border-orange-500/20 bg-orange-500/10 text-orange-600',
  }
  const Content = () => (
    <>
      <div className="flex items-center gap-4">
        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
          <Icon className="h-6 w-6 text-primary" />
        </div>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold text-lg">{pkg.name}</h3>
            <span
              className={`rounded-full px-2 py-0.5 font-medium text-xs ${
                statusStyles[pkg.status] ?? 'border border-slate-500/20 bg-slate-500/10 text-slate-600'
              }`}>
              {pkg.status}
            </span>
          </div>
        </div>
      </div>
      <p className="mt-4 text-muted-foreground text-sm leading-relaxed">{pkg.description}</p>
    </>
  )
  return pkg.href.length > 0 ? (
    <Link
      className="rounded-xl border border-border/50 bg-background/60 p-6 shadow-sm transition-colors hover:bg-background/80"
      href={pkg.href}>
      <Content />
    </Link>
  ) : (
    <div className="rounded-xl border border-border/50 bg-background/60 p-6 shadow-sm transition-colors hover:bg-background/80">
      <Content />
    </div>
  )
}

export function EcosystemSection() {
  return (
    <section aria-labelledby="ecosystem-heading" className="relative" id="ecosystem">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-32 -left-20 z-0 h-[12rem] w-[12rem] rounded-full bg-gradient-to-br from-orange-500/12 to-amber-400/8 blur-[90px] md:h-[18rem] md:w-[18rem]"></div>
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -right-20 -bottom-32 z-0 h-[10rem] w-[10rem] rounded-full bg-gradient-to-tl from-rose-500/10 to-pink-400/6 blur-[100px] md:h-[16rem] md:w-[16rem]"></div>
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-40 right-1/3 z-0 h-[8rem] w-[8rem] rounded-full bg-gradient-to-r from-red-400/5 to-orange-300/4 blur-[80px] md:h-[14rem] md:w-[14rem]"></div>

      <div className="container relative mx-auto pb-24 sm:pb-32 lg:pb-40">
        <SectionTitle
          subtitle="A growing ecosystem of tools, primitives, and utilities for modern development."
          title="The Gentleduck Ecosystem"
        />

        <div className="mt-16 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {packages.map((pkg, i) => (
            <EcosystemCard index={i} key={i} pkg={pkg} />
          ))}
        </div>
      </div>
    </section>
  )
}
