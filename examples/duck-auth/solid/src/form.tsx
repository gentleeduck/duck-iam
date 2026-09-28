import { errorText } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { createSignal, type JSX, Show, splitProps } from 'solid-js'

/** A form's submit: hands `send` the fields and the button pressed, and keeps its answer. `null` shows nothing. */
export function createSubmit(send: (form: FormData) => Promise<Envelope<unknown> | null>) {
  const [res, setRes] = createSignal<Envelope<unknown> | null>(null)
  const [pending, setPending] = createSignal(false)

  async function onSubmit(event: SubmitEvent & { currentTarget: HTMLFormElement }) {
    event.preventDefault()
    if (pending()) return
    const form = new FormData(event.currentTarget, event.submitter)
    setPending(true)
    setRes(await send(form))
    setPending(false)
  }

  return { res, pending, onSubmit }
}

export function Field(props: { label: string; name: string } & JSX.InputHTMLAttributes<HTMLInputElement>) {
  const [local, rest] = splitProps(props, ['label'])
  return (
    <div class="grid gap-2">
      <label for={props.name} class={ui.label}>
        {local.label}
      </label>
      <input id={props.name} required class={ui.input} {...rest} />
    </div>
  )
}

/** The last answer: a failure as an alert, a success as `done` when there is one to say. */
export function Notice(props: { res: Envelope<unknown> | null; done?: string; invalid?: string }) {
  const text = () => props.res && (props.res.ok ? props.done : errorText(props.res, props.invalid))
  return (
    <Show when={text()}>
      {(text) => (
        <div role="alert" class={ui.alert({ variant: props.res?.ok ? 'default' : 'destructive' })}>
          <p class={ui.alertDescription}>{text()}</p>
        </div>
      )}
    </Show>
  )
}
