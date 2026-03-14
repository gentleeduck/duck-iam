import { RegisterForm } from '@/components/auth/register-form'

export default function RegisterPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-muted p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="font-bold text-3xl">DocDuck</h1>
          <p className="mt-2 text-muted-foreground">Create your account</p>
        </div>
        <RegisterForm />
      </div>
    </div>
  )
}
