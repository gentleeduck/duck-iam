import { errorText } from '@examples/duck-auth-ui/api'
import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { Alert, AlertDescription } from '@gentleduck/registry-ui/alert'
import { Input } from '@gentleduck/registry-ui/input'
import { Label } from '@gentleduck/registry-ui/label'
import { type ComponentProps, type FormEvent, useState } from 'react'

/** A form's submit: hands `send` the fields and the button pressed, and keeps its answer. `null` shows nothing. */
export function useSubmit(send: (form: FormData) => Promise<Envelope<unknown> | null>) {
  const [res, setRes] = useState<Envelope<unknown> | null>(null)
  const [pending, setPending] = useState(false)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    const { nativeEvent } = event
    const form = new FormData(event.currentTarget, nativeEvent instanceof SubmitEvent ? nativeEvent.submitter : null)
    setPending(true)
    setRes(await send(form))
    setPending(false)
  }

  return { res, pending, onSubmit }
}

export function Field({ label, ...props }: { label: string; name: string } & ComponentProps<'input'>) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={props.name}>{label}</Label>
      <Input id={props.name} required {...props} />
    </div>
  )
}

/** The last answer: a failure as an alert, a success as `done` when there is one to say. */
export function Notice({ res, done, invalid }: { res: Envelope<unknown> | null; done?: string; invalid?: string }) {
  if (!res || (res.ok && !done)) return null
  return (
    <Alert variant={res.ok ? 'default' : 'destructive'}>
      <AlertDescription>{res.ok ? done : errorText(res, invalid)}</AlertDescription>
    </Alert>
  )
}
