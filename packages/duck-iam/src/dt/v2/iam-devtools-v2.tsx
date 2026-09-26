'use client'

import { cn } from '@gentleduck/libs/cn'
import { Badge } from '@gentleduck/registry-ui/badge'
import { Button } from '@gentleduck/registry-ui/button'
import { Kbd } from '@gentleduck/registry-ui/kbd'
import { Separator } from '@gentleduck/registry-ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/registry-ui/tooltip'
import { LayoutPanelLeft, ShieldCheck, X } from 'lucide-react'
import React from 'react'
import { type IamDockPosition, useIamDockablePanel } from '../lib/dockable-panel'
import { isDevtoolsAllowed } from '../lib/guard'
import { IamV2Chip } from './components/chrome'
import { IamDevtoolsInnerV2, type IIamDevtoolsInnerV2Props } from './iam-devtools-inner-v2'

/** Where the floating launcher sits. `'relative'` drops it into normal flow, for a toolbar of your own. */
export type IamV2ButtonPosition = 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left' | 'relative'
/** Which edge the panel docks to. Cycled through in dock order. */
export type IamV2PanelPosition = IamDockPosition

/** Props for `IamDevtoolsV2`, the launcher and dockable panel; inner props pass to {@link IamDevtoolsInnerV2}. */
export interface IIamDevtoolsV2Props extends IIamDevtoolsInnerV2Props {
  buttonPosition?: IamV2ButtonPosition
  hideButton?: boolean
  initialIsOpen?: boolean
  position?: IamV2PanelPosition
  /** `localStorage` key prefix for the persisted open/dock/size state. Set it when two devtools share a page. */
  storagePrefix?: string
}

const DEFAULT_SIZE = 520
const MIN_SIZE = 260
const MAX_SIZE_FRACTION = 0.9
/** How far one arrow key nudges the resize edge; Page Up/Down move ten times that. */
const KEY_RESIZE_STEP = 16

/** Fixed placement for a dock edge. */
const DOCK_CLASS: Record<IamV2PanelPosition, string> = {
  bottom: 'inset-x-0 bottom-0 border-t',
  left: 'inset-y-0 left-0 border-r',
  right: 'inset-y-0 right-0 border-l',
  top: 'inset-x-0 top-0 border-b',
}

/** Where the resize handle sits, and which cursor it takes. */
const HANDLE_CLASS: Record<IamV2PanelPosition, string> = {
  bottom: 'inset-x-0 top-0 h-1.5 cursor-ns-resize',
  left: 'inset-y-0 right-0 w-1.5 cursor-ew-resize',
  right: 'inset-y-0 left-0 w-1.5 cursor-ew-resize',
  top: 'inset-x-0 bottom-0 h-1.5 cursor-ns-resize',
}

const LAUNCHER_CLASS: Record<Exclude<IamV2ButtonPosition, 'relative'>, string> = {
  'bottom-left': 'fixed bottom-4 left-4',
  'bottom-right': 'fixed right-4 bottom-4',
  'top-left': 'fixed top-4 left-4',
  'top-right': 'fixed top-4 right-4',
}

/**
 * SECURITY: renders nothing in production, with no escape hatch (see `lib/guard.ts`).
 * The guard sits in a wrapper so `Impl`'s hook order stays unconditional.
 */
export function IamDevtoolsV2(props: IIamDevtoolsV2Props) {
  if (!isDevtoolsAllowed(props.engine)) return null
  return <Impl {...props} />
}

function Impl({
  buttonPosition = 'bottom-right',
  hideButton = false,
  initialIsOpen = false,
  position: positionProp,
  storagePrefix = '__GENTLEDUCK_IAM_DEVTOOLS_V2',
  ...inner
}: IIamDevtoolsV2Props) {
  const {
    cycleDock,
    isHorizontal,
    launcherRef,
    maxSize,
    onDragEnd: onPointerUp,
    onDragMove: onPointerMove,
    onDragStart: onPointerDown,
    onResizeKeyDown,
    open,
    panelRef,
    position: dock,
    setOpen,
    size,
  } = useIamDockablePanel({
    defaultSize: DEFAULT_SIZE,
    initialIsOpen,
    keyResizeStep: KEY_RESIZE_STEP,
    maxSizeFraction: MAX_SIZE_FRACTION,
    minSize: MIN_SIZE,
    positionKeySuffix: '_DOCK',
    positionProp,
    storagePrefix,
  })
  const titleId = React.useId()

  // Focus the panel on open so the next Tab reaches its controls, not the host page.
  React.useEffect(() => {
    if (open) panelRef.current?.focus()
  }, [open, panelRef])

  return (
    <>
      {!hideButton && buttonPosition !== 'relative' && (
        <div className={cn('z-[2147483000]', LAUNCHER_CLASS[buttonPosition], open && 'hidden')}>
          <TooltipProvider delayDuration={300}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  aria-expanded={open}
                  aria-label="Open duck-iam devtools"
                  className="size-10 rounded-full shadow-lg"
                  onClick={() => setOpen(true)}
                  ref={launcherRef}
                  size="icon"
                  variant="default">
                  <ShieldCheck />
                </Button>
              </TooltipTrigger>
              <TooltipContent className="px-2 py-1 text-xs">duck-iam devtools</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      )}

      {open && (
        <div
          aria-labelledby={titleId}
          className={cn(
            'fixed z-[2147483000] flex flex-col overflow-hidden border-border bg-background shadow-2xl',
            DOCK_CLASS[dock],
          )}
          ref={panelRef}
          role="dialog"
          style={isHorizontal ? { width: size } : { height: size }}
          tabIndex={-1}>
          {/* biome-ignore lint/a11y/useSemanticElements: `<hr>` is the thematic-break separator; this is the focusable window-splitter variant of the role, which has no element form. */}
          <div
            aria-label="Resize devtools panel"
            aria-orientation={isHorizontal ? 'vertical' : 'horizontal'}
            aria-valuemax={Math.round(maxSize)}
            aria-valuemin={MIN_SIZE}
            aria-valuenow={Math.round(size)}
            className={cn(
              'absolute z-10 bg-transparent transition-colors hover:bg-primary/40 focus-visible:bg-primary/60 focus-visible:outline-none',
              HANDLE_CLASS[dock],
            )}
            onKeyDown={onResizeKeyDown}
            onPointerCancel={onPointerUp}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            role="separator"
            tabIndex={0}
          />

          <TooltipProvider delayDuration={300}>
            <header className="flex h-11 shrink-0 items-center gap-2 border-border border-b bg-card px-3">
              <ShieldCheck aria-hidden className="size-4 text-primary" />
              <span className="font-semibold text-sm" id={titleId}>
                duck-iam
              </span>
              <Badge className="font-normal" size="sm" variant="secondary">
                devtools v2
              </Badge>
              <Separator className="h-4" orientation="vertical" />
              <IamV2Chip className="rounded-full uppercase tracking-wider" mono={false} tone="allow">
                <span aria-hidden className="size-1.5 animate-pulse rounded-full bg-emerald-500" />
                live
              </IamV2Chip>
              <div className="ms-auto flex items-center gap-1">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button className="h-7 gap-1.5 px-2 text-xs" onClick={cycleDock} size="sm" variant="ghost">
                      <LayoutPanelLeft size={12} />
                      {dock}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="px-2 py-1 text-xs">{`Docked ${dock} — click to move`}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      aria-label="Close devtools"
                      className="size-7"
                      onClick={() => {
                        setOpen(false)
                        launcherRef.current?.focus()
                      }}
                      size="icon-sm"
                      variant="ghost">
                      <X size={13} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="flex items-center gap-1.5 px-2 py-1 text-xs">
                    Close
                    <Kbd className="h-4 px-1 text-[0.625rem]">Esc</Kbd>
                  </TooltipContent>
                </Tooltip>
              </div>
            </header>
          </TooltipProvider>

          <div className="flex min-h-0 flex-1 flex-col">
            <IamDevtoolsInnerV2 {...inner} embedded />
          </div>
        </div>
      )}
    </>
  )
}
