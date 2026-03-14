import { LoginForm } from '@/components/auth/login-form'

export default function LoginPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-muted p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="font-bold text-3xl">DocDuck</h1>
          <p className="mt-2 text-muted-foreground">Collaborative Document Editor</p>
        </div>
        <LoginForm />
      </div>
    </div>
  )
}
