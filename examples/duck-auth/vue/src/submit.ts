import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { reactive, shallowRef } from 'vue'

/** A form's submit: hands `send` the fields and the button pressed, and keeps its answer. `null` shows nothing. */
export function useSubmit(send: (form: FormData) => Promise<Envelope<unknown> | null>) {
  const submit = reactive({ res: shallowRef<Envelope<unknown> | null>(null), pending: false, onSubmit })

  async function onSubmit(event: Event): Promise<void> {
    if (submit.pending || !(event.currentTarget instanceof HTMLFormElement)) return
    const form = new FormData(event.currentTarget, event instanceof SubmitEvent ? event.submitter : null)
    submit.pending = true
    submit.res = await send(form)
    submit.pending = false
  }

  return submit
}
