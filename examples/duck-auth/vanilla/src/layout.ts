import { BACKENDS, pickBackend, pickedBackend } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { h } from './h'

/** Which backend every call goes to; picking one reloads the page against it. */
export function BackendPicker(): HTMLSelectElement {
  const select = h(
    'select',
    { ariaLabel: 'Backend', className: ui.select },
    ...Object.keys(BACKENDS).map((name) => h('option', { value: name, selected: name === pickedBackend() }, name)),
  )
  select.onchange = () => pickBackend(select.value)
  return select
}

export function AuthLayout(props: {
  title: string
  description: string
  children: Node[]
  footer?: (Node | string)[]
}): HTMLElement {
  document.title = `${props.title} · duck-auth · Vanilla`
  const card = h(
    'div',
    { className: `${ui.card.root} w-full max-w-sm` },
    h(
      'div',
      { className: ui.card.header },
      h('h1', { className: `${ui.card.title} text-xl` }, props.title),
      h('div', { className: ui.card.description }, props.description),
    ),
    h('div', { className: ui.card.content }, ...props.children),
  )
  if (props.footer) {
    card.append(
      h('div', { className: `${ui.card.footer} justify-center text-muted-foreground text-sm` }, ...props.footer),
    )
  }
  return h(
    'main',
    { className: 'flex min-h-svh flex-col items-center justify-center gap-6 p-6' },
    card,
    BackendPicker(),
  )
}
