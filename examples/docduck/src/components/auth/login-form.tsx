'use client'

import { Badge } from '@gentleduck/ui/badge'
import { Button } from '@gentleduck/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@gentleduck/ui/card'
import { Input } from '@gentleduck/ui/input'
import { Label } from '@gentleduck/ui/label'
import { Separator } from '@gentleduck/ui/separator'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'
import { signIn } from '@/lib/auth-client'
import { loginSchema } from '@/lib/validations'

export function LoginForm() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setFieldErrors({})
    setLoading(true)

    const formData = new FormData(e.currentTarget)
    const raw = {
      email: formData.get('email'),
      password: formData.get('password'),
    }

    const parsed = loginSchema.safeParse(raw)
    if (!parsed.success) {
      const errors: Record<string, string> = {}
      for (const issue of parsed.error.issues) {
        const key = issue.path[0]
        if (typeof key === 'string' && !errors[key]) {
          errors[key] = issue.message
        }
      }
      setFieldErrors(errors)
      setLoading(false)
      return
    }

    const result = await signIn.email({
      email: parsed.data.email,
      password: parsed.data.password,
    })

    if (result.error) {
      toast.error(result.error.message ?? 'Login failed')
      setLoading(false)
    } else {
      router.push('/workspaces')
      router.refresh()
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">Sign in</CardTitle>
        <CardDescription>Enter your credentials to access your account</CardDescription>
      </CardHeader>
      <CardContent>
        <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="alice@example.com"
              aria-invalid={!!fieldErrors.email}
            />
            {fieldErrors.email && <p className="text-destructive text-sm">{fieldErrors.email}</p>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              placeholder="password123"
              aria-invalid={!!fieldErrors.password}
            />
            {fieldErrors.password && <p className="text-destructive text-sm">{fieldErrors.password}</p>}
          </div>
        </form>
      </CardContent>
      <CardFooter className="flex flex-col gap-4">
        <Button type="submit" form="login-form" className="w-full" loading={loading}>
          Sign in
        </Button>
        <p className="text-center text-muted-foreground text-sm">
          Don&apos;t have an account?{' '}
          <Link href="/auth/register" className="font-medium text-foreground underline">
            Register
          </Link>
        </p>
        <Separator />
        <div className="w-full rounded-md bg-muted p-3 text-muted-foreground text-xs">
          <p className="mb-2 font-medium">
            Demo accounts <Badge variant="secondary">password123</Badge>
          </p>
          <ul className="space-y-0.5">
            <li>alice@example.com — owner@acme, viewer@startup</li>
            <li>bob@example.com — editor@acme, owner@startup</li>
            <li>charlie@example.com — viewer@acme</li>
            <li>diana@example.com — admin@acme</li>
          </ul>
        </div>
      </CardFooter>
    </Card>
  )
}
