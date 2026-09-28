import type { Envelope } from '@gentleduck/auth/client/vanilla'

/** A form's submit: hands `send` the fields and the button pressed, and keeps its answer. `null` shows nothing. */
export function createSubmit(send: (form: FormData) => Promise<Envelope<unknown> | null>) {
  let res = $state<Envelope<unknown> | null>(null)
  let pending = $state(false)

  return {
    get res() {
      return res
    },
    get pending() {
      return pending
    },
    async onsubmit(event: SubmitEvent & { currentTarget: HTMLFormElement }) {
      event.preventDefault()
      if (pending) return
      const form = new FormData(event.currentTarget, event.submitter)
      pending = true
      res = await send(form)
      pending = false
    },
  }
}
