export interface SignInDto {
  providerId: string
  input: unknown
}

export interface SignUpDto {
  email: string
  name: string
  password: string
}
