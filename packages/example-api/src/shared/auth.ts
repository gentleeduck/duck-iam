import { UnauthorizedException } from '@nestjs/common'

export interface AuthenticatedRequest {
  headers: { authorization?: string }
}

export function extractUserId(req: AuthenticatedRequest): string {
  const auth = req.headers.authorization
  if (!auth?.startsWith('Bearer ')) throw new UnauthorizedException('Missing authorization')
  return auth.slice(7)
}
