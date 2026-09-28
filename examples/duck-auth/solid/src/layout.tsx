import { BACKENDS, pickBackend, pickedBackend } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { For, type JSX, Show } from 'solid-js'

/** Which backend every call goes to; picking one reloads the page against it. */
export function BackendPicker() {
  return (
    <select aria-label="Backend" class={ui.select} onChange={(event) => pickBackend(event.currentTarget.value)}>
      <For each={Object.keys(BACKENDS)}>
        {(name) => (
          <option value={name} selected={name === pickedBackend()}>
            {name}
          </option>
        )}
      </For>
    </select>
  )
}

export function AuthLayout(props: { title: string; description: string; children: JSX.Element; footer?: JSX.Element }) {
  document.title = `${props.title} · duck-auth · Solid`
  return (
    <main class="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
      <div class={`${ui.card.root} w-full max-w-sm`}>
        <div class={ui.card.header}>
          <h1 class={`${ui.card.title} text-xl`}>{props.title}</h1>
          <div class={ui.card.description}>{props.description}</div>
        </div>
        <div class={ui.card.content}>{props.children}</div>
        <Show when={props.footer}>
          {(footer) => <div class={`${ui.card.footer} justify-center text-muted-foreground text-sm`}>{footer()}</div>}
        </Show>
      </div>
      <BackendPicker />
    </main>
  )
}
