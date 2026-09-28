import { Card, CardContent, CardDescription, CardFooter, CardHeader } from '@gentleduck/registry-ui/card'
import type { ReactNode } from 'react'

export function AuthLayout(props: { title: string; description: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <main className="flex min-h-svh items-center justify-center p-6">
      <title>{`${props.title} · duck-auth · Next.js`}</title>
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
    </main>
  )
}
