import { throwAuthError } from '@gentleduck/auth'
import { Injectable } from '@nestjs/common'

export interface UserRecord {
  id: string
  email: string
  name: string
  createdAt: Date
}

const store = new Map<string, UserRecord>()

@Injectable()
export class UsersService {
  upsert(id: string, profile: { email: string; name: string }): UserRecord {
    const existing = store.get(id)
    if (existing) return existing
    const user: UserRecord = { id, email: profile.email, name: profile.name, createdAt: new Date() }
    store.set(id, user)
    return user
  }

  findById(id: string): UserRecord {
    const user = store.get(id)
    if (!user) throwAuthError('AUTH_UNAUTHENTICATED')
    return user
  }

  findAll(): UserRecord[] {
    return Array.from(store.values())
  }
}
