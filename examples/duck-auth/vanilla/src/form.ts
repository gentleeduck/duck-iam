import { type Envelope, errorText } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { h } from './h'

/** A form's submit: hands `send` the fields and the button pressed, and shows its answer in `alert`. `null` shows nothing. */
export function createSubmit(
  send: (form: FormData) => Promise<Envelope<unknown> | null>,
  done?: string,
  invalid?: string,
) {
  const alert = h('div', { role: 'alert', hidden: true })

  async function onsubmit(event: SubmitEvent) {
    event.preventDefault()
    const form = event.currentTarget
    if (!(form instanceof HTMLFormElement)) return
    const fields = new FormData(form, event.submitter)
    const buttons = form.querySelectorAll('button')
    for (const button of buttons) button.disabled = true
    showNotice(alert, await send(fields), done, invalid)
    for (const button of buttons) button.disabled = false
  }

  return { alert, onsubmit }
}

export function Field(label: string, props: Partial<HTMLInputElement> & { name: string }): HTMLDivElement {
  return h(
    'div',
    { className: 'grid gap-2' },
    h('label', { htmlFor: props.name, className: ui.label }, label),
    h('input', { id: props.name, required: true, className: ui.input, ...props }),
  )
}

/** The last answer in `alert`: a failure, or `done` when there is one to say. */
export function showNotice(alert: HTMLElement, res: Envelope<unknown> | null, done?: string, invalid?: string): void {
  const text = res && (res.ok ? done : errorText(res, invalid))
  alert.hidden = !text
  alert.className = ui.alert({ variant: res?.ok ? 'default' : 'destructive' })
  alert.replaceChildren(h('p', { className: ui.alertDescription }, text || ''))
}
