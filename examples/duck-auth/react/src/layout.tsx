import { BACKENDS, pickBackend, pickedBackend } from '@examples/duck-auth-ui/api'
import { Card, CardContent, CardDescription, CardFooter, CardHeader } from '@gentleduck/registry-ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@gentleduck/registry-ui/select'
import type { ReactNode } from 'react'

/** Which backend every call goes to; picking one reloads the page against it. */
export function BackendPicker() {
  return (
    <Select defaultValue={pickedBackend()} onValueChange={pickBackend}>
      <SelectTrigger aria-label="Backend" className="w-32">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {Object.keys(BACKENDS).map((name) => (
          <SelectItem key={name} value={name}>
            {name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

export function AuthLayout(props: { title: string; description: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
      <title>{`${props.title} · duck-auth · React`}</title>
      <Card className="w-full max-w-sm">
        <CardHeader>
          <h1 className="font-semibold text-xl leading-none">{props.title}</h1>
          <CardDescription>{props.description}</CardDescription>
        </CardHeader>
        <CardContent>{props.children}</CardContent>
        {props.footer && (
          <CardFooter className="justify-center text-muted-foreground text-sm">{props.footer}</CardFooter>
        )}
      </Card>
      <BackendPicker />
    </main>
  )
}
