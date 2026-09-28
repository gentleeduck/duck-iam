import { cva } from '@gentleduck/variants'

// duck-ui's recipes from `@gentleduck/registry-ui`, for the clients that cannot render its React components.

export const button = cva(
  'relative inline-flex shrink-0 cursor-pointer select-none items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium text-sm outline-none transition-all focus-visible:border-ring focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50',
  {
    defaultVariants: { size: 'default', variant: 'default' },
    variants: {
      size: {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 gap-1.5 px-3',
      },
      variant: {
        default: 'bg-primary text-primary-foreground shadow-sm hover:bg-primary/90',
        destructive: 'bg-destructive/90 text-destructive-foreground shadow-xs hover:bg-destructive/70',
        ghost: 'text-accent-foreground hover:bg-accent hover:text-accent-foreground',
        link: 'text-primary underline-offset-4 hover:underline',
        outline:
          'border border-input bg-background text-accent-foreground shadow-xs hover:bg-accent hover:text-accent-foreground',
      },
    },
  },
)

export const badge = cva(
  'inline-flex w-fit shrink-0 items-center justify-center gap-1 whitespace-nowrap rounded-md px-2.5 py-0.5 font-medium text-sm',
  {
    defaultVariants: { variant: 'default' },
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        outline: 'border text-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        warning: 'border-transparent bg-warning text-warning-foreground',
      },
    },
  },
)

export const alert = cva(
  'relative grid w-full grid-cols-[0_1fr] items-start gap-y-0.5 rounded-lg border px-4 py-3 text-sm',
  {
    defaultVariants: { variant: 'default' },
    variants: {
      variant: {
        default: 'bg-card text-card-foreground',
        destructive: 'bg-card text-destructive',
      },
    },
  },
)

export const alertDescription = 'col-start-2 text-sm [&_p]:leading-relaxed'

export const input =
  'h-8 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1 text-base outline-none transition-colors placeholder:text-muted-foreground focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm'

export const label = 'text-balance font-medium text-sm leading-none'

export const card = {
  root: 'flex flex-col gap-6 rounded-xl border bg-card py-6 text-card-foreground shadow-sm',
  header: 'grid auto-rows-min items-start gap-1.5 px-6',
  title: 'font-semibold leading-none',
  description: 'text-muted-foreground text-sm',
  content: 'px-6',
  footer: 'flex items-center gap-2 px-6',
}

export const separator = 'h-px w-full shrink-0 bg-border'

export const select =
  'h-8 w-32 rounded-md border border-input bg-transparent px-2 text-sm outline-none focus-visible:ring-1 focus-visible:ring-ring'
