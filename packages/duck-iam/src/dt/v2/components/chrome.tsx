'use client'

import { cn } from '@gentleduck/libs/cn'
import { Alert, AlertDescription, AlertTitle } from '@gentleduck/registry-ui/alert'
import { Avatar, AvatarFallback } from '@gentleduck/registry-ui/avatar'
import { Badge } from '@gentleduck/registry-ui/badge'
import { Button } from '@gentleduck/registry-ui/button'
import { ButtonGroup } from '@gentleduck/registry-ui/button-group'
import { Card, CardContent, CardHeader, CardTitle } from '@gentleduck/registry-ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@gentleduck/registry-ui/empty'
import { InputGroup, InputGroupAddon, InputGroupInput } from '@gentleduck/registry-ui/input-group'
import { Item, ItemContent, ItemDescription, ItemTitle } from '@gentleduck/registry-ui/item'
import { Kbd, KbdGroup } from '@gentleduck/registry-ui/kbd'
import { Label } from '@gentleduck/registry-ui/label'
import { Progress } from '@gentleduck/registry-ui/progress'
import { ScrollArea } from '@gentleduck/registry-ui/scroll-area'
import { Separator } from '@gentleduck/registry-ui/separator'
import { Skeleton } from '@gentleduck/registry-ui/skeleton'
import { Switch } from '@gentleduck/registry-ui/switch'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/registry-ui/tooltip'
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, CircleAlert, Inbox, Search } from 'lucide-react'
import React from 'react'
import { IAM_V2_MONO, type IamV2Tone, iamV2Chip, iamV2Dot, iamV2Track } from '../lib/tone'

// Layout building blocks for the v2 panels: duck-ui components plus Tailwind, no stylesheet of their own.
// NOTE: if duck-ui ships a component, use it with a density class so the host theme can still restyle it.

/**
 * Outermost element of anything mountable on its own; `data-iam-dt-v2` lets hosts and tests find it.
 * NOTE: every panel is exported alone, so each root mounts its own `TooltipProvider`.
 */
export function IamV2Root({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <TooltipProvider delayDuration={300}>
      <div
        className={cn('flex min-h-0 flex-col bg-background text-foreground text-sm antialiased', className)}
        data-iam-dt-v2="">
        {children}
      </div>
    </TooltipProvider>
  )
}

/**
 * Master/detail layout that stacks on narrow viewports (the panel is often docked to a 320px edge).
 * `side` picks the fixed-width column; Flow uses `end` so its data table gets the flexible one.
 */
export function IamV2Split({
  detail,
  list,
  side = 'start',
}: {
  detail: React.ReactNode
  list: React.ReactNode
  side?: 'start' | 'end'
}) {
  const fixed = 'flex min-h-0 shrink-0 flex-col lg:h-full lg:w-[22rem]'
  const flex = 'flex min-h-0 flex-1 flex-col'
  return (
    <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
      {side === 'start' ? (
        <>
          <div className={fixed}>{list}</div>
          <Separator className="lg:hidden" />
          <Separator className="hidden lg:block" orientation="vertical" />
          <div className={flex}>{detail}</div>
        </>
      ) : (
        <>
          <div className={flex}>{list}</div>
          <Separator className="lg:hidden" />
          <Separator className="hidden lg:block" orientation="vertical" />
          <div className={fixed}>{detail}</div>
        </>
      )}
    </div>
  )
}

/** A pane's sticky title bar: name, live count, and whatever controls it owns. */
export function IamV2PaneHeader({
  actions,
  count,
  title,
}: {
  actions?: React.ReactNode
  count?: number
  title: string
}) {
  return (
    <div className="flex h-11 shrink-0 items-center gap-2 border-border border-b bg-card px-3">
      <h3 className="font-medium text-foreground text-xs uppercase tracking-wider">{title}</h3>
      {count !== undefined && (
        <Badge className="tabular-nums" size="sm" variant="secondary">
          {count}
        </Badge>
      )}
      {actions && <div className="ms-auto flex items-center gap-1">{actions}</div>}
    </div>
  )
}

/** The scrolling body of a pane. Separate from the header so the header stays put. */
export function IamV2PaneBody({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <ScrollArea className="min-h-0 flex-1" viewportClassName="scrollbar-thin">
      <div className={cn('flex flex-col gap-2 p-3', className)}>{children}</div>
    </ScrollArea>
  )
}

/** The filter box every list pane opens with. */
export function IamV2Search({
  onChange,
  placeholder,
  value,
}: {
  onChange: (value: string) => void
  placeholder: string
  value: string
}) {
  return (
    <InputGroup className="h-8">
      <InputGroupAddon>
        <Search />
      </InputGroupAddon>
      <InputGroupInput
        aria-label={placeholder}
        className="h-8 text-xs"
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        type="search"
        value={value}
      />
    </InputGroup>
  )
}

/** One selectable row, on duck-ui's `Item`. `aria-current` makes the selection audible to screen readers. */
export function IamV2ListRow({
  active,
  description,
  onSelect,
  title,
  tone = 'neutral',
  trailing,
}: {
  active: boolean
  description?: React.ReactNode
  onSelect: () => void
  title: React.ReactNode
  tone?: IamV2Tone
  trailing?: React.ReactNode
}) {
  return (
    <Item
      aria-current={active ? 'true' : undefined}
      asChild
      className={cn(
        'w-full cursor-pointer gap-2.5 rounded-md border border-transparent px-2.5 py-2 text-start transition-colors',
        'hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        active && 'border-border bg-accent',
      )}
      size="sm"
      variant="default">
      <button onClick={onSelect} type="button">
        <span aria-hidden className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', iamV2Dot(tone))} />
        <ItemContent className="min-w-0 gap-0.5">
          <ItemTitle className="truncate font-normal">{title}</ItemTitle>
          {description && <ItemDescription className="truncate text-[0.6875rem]">{description}</ItemDescription>}
        </ItemContent>
        {trailing}
      </button>
    </Item>
  )
}

/**
 * A collapsible titled block in a detail pane, on duck-ui's `Card`.
 * NOTE: not duck-ui's `Collapsible`, whose DOM-attribute state fights a prop default and renders closed on SSR.
 */
export function IamV2Section({
  children,
  defaultOpen = true,
  title,
  trailing,
}: {
  children: React.ReactNode
  defaultOpen?: boolean
  title: string
  trailing?: React.ReactNode
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  const bodyId = React.useId()
  return (
    <Card className="gap-0 overflow-hidden rounded-lg py-0">
      <CardHeader className="grid-cols-[1fr_auto] items-center gap-0 px-0 pe-2">
        {/* `CardTitle` wraps the button: a `div` inside a `button` is invalid and `CardTitle` has no `asChild`. */}
        <CardTitle className="font-medium text-muted-foreground text-xs uppercase tracking-wider">
          <button
            aria-controls={bodyId}
            aria-expanded={open}
            className="flex w-full items-center gap-1.5 px-2.5 py-2 text-start uppercase tracking-wider hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => setOpen((o) => !o)}
            type="button">
            <span aria-hidden className="text-muted-foreground/70">
              {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            </span>
            {title}
          </button>
        </CardTitle>
        {trailing}
      </CardHeader>
      {open && (
        <>
          <Separator />
          <CardContent className="p-2.5" id={bodyId}>
            {children}
          </CardContent>
        </>
      )}
    </Card>
  )
}

/** A disclosure row inside a section - a rule, a permission, a trace group. */
export function IamV2Disclosure({
  children,
  defaultOpen = false,
  disabled = false,
  summary,
}: {
  children?: React.ReactNode
  defaultOpen?: boolean
  disabled?: boolean
  summary: React.ReactNode
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  const bodyId = React.useId()
  const isOpen = open && !disabled
  return (
    <div className="overflow-hidden rounded-md border border-border bg-background">
      <button
        aria-controls={bodyId}
        aria-expanded={disabled ? undefined : isOpen}
        className="flex w-full flex-wrap items-center gap-1.5 px-2 py-1.5 text-start hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-default disabled:hover:bg-transparent"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        type="button">
        <span aria-hidden className="shrink-0 text-muted-foreground/70">
          {disabled ? (
            <span className="inline-block size-3" />
          ) : isOpen ? (
            <ChevronDown size={12} />
          ) : (
            <ChevronRight size={12} />
          )}
        </span>
        {summary}
      </button>
      {isOpen && children && (
        <>
          <Separator />
          <div className="flex flex-col gap-1.5 p-2" id={bodyId}>
            {children}
          </div>
        </>
      )}
    </div>
  )
}

/** A tone-coloured inline chip. The devtool's whole vocabulary of verdicts. */
export function IamV2Chip({
  children,
  className,
  mono = true,
  tone = 'neutral',
}: {
  children: React.ReactNode
  className?: string
  mono?: boolean
  tone?: IamV2Tone
}) {
  return (
    <Badge
      className={cn(
        'gap-1 rounded border px-1.5 py-px text-[0.6875rem] leading-4',
        mono && 'font-mono',
        iamV2Chip(tone),
        className,
      )}
      size="sm"
      variant="outline">
      {children}
    </Badge>
  )
}

/** A label/value pair, for a deciding policy or a rule id. */
export function IamV2Kv({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/40 py-0.5 ps-1.5 pe-2">
      <span className="text-[0.625rem] text-muted-foreground uppercase tracking-wider">{label}</span>
      <code className={IAM_V2_MONO}>{value}</code>
    </div>
  )
}

/** One number in the telemetry grid, on `Card` at devtools density. */
export function IamV2Stat({ hint, label, value }: { hint?: string; label: string; value: React.ReactNode }) {
  return (
    <Card className="gap-0.5 rounded-lg px-3 py-2">
      <span className="text-[0.625rem] text-muted-foreground uppercase tracking-wider">{label}</span>
      <span className="font-semibold text-base text-foreground tabular-nums">{value}</span>
      {hint && <span className="text-[0.6875rem] text-muted-foreground">{hint}</span>}
    </Card>
  )
}

/**
 * A labelled percentage bar, on duck-ui's `Progress`.
 * `Progress` already announces the value, so the caption stays plain text.
 */
export function IamV2Meter({
  caption,
  label,
  name,
  percent,
  tone,
}: {
  caption?: React.ReactNode
  label?: React.ReactNode
  /** What the bar is measuring. Its accessible name - several sit side by side. */
  name: string
  percent: number
  tone: IamV2Tone
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(percent)))
  return (
    <Card className="gap-1.5 rounded-lg px-3 py-2">
      <div className="flex items-center gap-2">
        {label ?? <span className="truncate text-foreground text-xs">{name}</span>}
        <IamV2Chip className="ms-auto tabular-nums" tone={tone}>
          {clamped}%
        </IamV2Chip>
      </div>
      <Progress aria-label={name} className={cn('h-1.5', iamV2Track(tone))} value={clamped} />
      {caption && <span className="text-[0.6875rem] text-muted-foreground tabular-nums">{caption}</span>}
    </Card>
  )
}

/** A subject's initial in a duck-ui `Avatar`. Decorative - the id is beside it. */
export function IamV2Avatar({ id }: { id: string }) {
  const initial = id.replace(/^[a-z]+[-_]/i, '').charAt(0) || id.charAt(0) || '?'
  return (
    <Avatar aria-hidden className="size-5 rounded">
      <AvatarFallback className="rounded bg-primary/10 font-medium text-[0.625rem] text-primary uppercase">
        {initial}
      </AvatarFallback>
    </Avatar>
  )
}

/** Placeholder rows for a pane that has asked the adapter and not heard back. */
export function IamV2SkeletonRows({ rows = 4 }: { rows?: number }) {
  return (
    <div aria-hidden className="flex flex-col gap-1.5">
      {Array.from({ length: rows }, (_, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: placeholders have no identity beyond their position
        <div className="flex items-center gap-2 px-2.5 py-2" key={index}>
          <Skeleton className="size-1.5 rounded-full" />
          <Skeleton className="h-3 flex-1" />
          <Skeleton className="h-3 w-8" />
        </div>
      ))}
    </div>
  )
}

/** The nothing-here state, on duck-ui's `Empty`. */
export function IamV2Empty({
  description,
  icon,
  title,
}: {
  description?: React.ReactNode
  icon?: React.ReactNode
  title: string
}) {
  return (
    <Empty className="border border-border border-dashed p-8">
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon ?? <Inbox />}</EmptyMedia>
        <EmptyTitle className="text-sm">{title}</EmptyTitle>
        {description && <EmptyDescription className="text-xs">{description}</EmptyDescription>}
      </EmptyHeader>
    </Empty>
  )
}

/**
 * An inline message, on duck-ui's `Alert`.
 * NOTE: duck-ui hard-codes `role="alert"`; the passed `role` overrides it so only errors are announced assertively.
 */
export function IamV2Alert({ children, tone }: { children: React.ReactNode; tone: 'error' | 'success' | 'info' }) {
  const mapped: IamV2Tone = tone === 'error' ? 'deny' : tone === 'success' ? 'allow' : 'info'
  const Icon = tone === 'error' ? CircleAlert : tone === 'success' ? CheckCircle2 : AlertTriangle
  return (
    <Alert
      className={cn('items-center gap-x-2 px-2.5 py-1.5 text-xs', iamV2Chip(mapped))}
      role={tone === 'error' ? 'alert' : 'status'}
      variant="default">
      <Icon />
      <AlertTitle className="text-xs">{children}</AlertTitle>
    </Alert>
  )
}

/** The wordier form of {@link IamV2Alert}, when the fix needs a sentence. */
export function IamV2Notice({
  children,
  title,
  tone,
}: {
  children: React.ReactNode
  title: string
  tone: 'error' | 'info'
}) {
  const Icon = tone === 'error' ? CircleAlert : AlertTriangle
  return (
    <Alert
      className={cn('gap-x-2 px-3 py-2', iamV2Chip(tone === 'error' ? 'deny' : 'info'))}
      role={tone === 'error' ? 'alert' : 'status'}
      variant="default">
      <Icon />
      <AlertTitle className="text-xs">{title}</AlertTitle>
      <AlertDescription className="text-[0.6875rem]">{children}</AlertDescription>
    </Alert>
  )
}

/** A fixed-size toolbar button; `label` is both its tooltip and its accessible name. */
export function IamV2Action({
  children,
  disabled,
  label,
  onClick,
}: {
  children: React.ReactNode
  disabled?: boolean
  label: string
  onClick: () => void
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          aria-label={label}
          className="h-7 gap-1 px-2 text-xs"
          disabled={disabled}
          onClick={onClick}
          size="sm"
          variant="ghost">
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent className="px-2 py-1 text-xs">{label}</TooltipContent>
    </Tooltip>
  )
}

/** A segmented row of related controls, on duck-ui's `ButtonGroup`. */
export function IamV2Toolbar({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <ButtonGroup aria-label={label} className="h-7">
      {children}
    </ButtonGroup>
  )
}

/** A boolean filter, on duck-ui's `Switch` (accessible `role="switch"` out of the box). */
export function IamV2Toggle({
  checked,
  count,
  label,
  onChange,
  tone = 'neutral',
}: {
  checked: boolean
  count?: number
  label: string
  onChange: (checked: boolean) => void
  tone?: IamV2Tone
}) {
  const id = React.useId()
  return (
    <div className="inline-flex items-center gap-1.5">
      <Switch checked={checked} className="scale-90" id={id} onCheckedChange={onChange} />
      <Label className="cursor-pointer gap-1.5 font-normal text-xs" htmlFor={id}>
        <span aria-hidden className={cn('size-1.5 rounded-full', iamV2Dot(tone))} />
        {label}
        {count !== undefined && (
          <Badge className="tabular-nums" size="sm" variant="secondary">
            {count}
          </Badge>
        )}
      </Label>
    </div>
  )
}

/** A keyboard hint, on duck-ui's `Kbd`. `aria-hidden` because every shortcut also has a labelled control. */
export function IamV2Hint({ children, keys }: { children?: React.ReactNode; keys: readonly string[] }) {
  return (
    <span aria-hidden className="inline-flex items-center gap-1 text-[0.6875rem] text-muted-foreground">
      <KbdGroup>
        {keys.map((key) => (
          <Kbd className="h-4 min-w-4 px-1 text-[0.625rem]" key={key}>
            {key}
          </Kbd>
        ))}
      </KbdGroup>
      {children}
    </span>
  )
}
