import type { Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions'

export namespace SqlBridge {
  export type ProfileMetadataBase = Identities.ProfileMetadataBase

  export type Me<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    identities: Identity<Identities.Me<Profile>>
    credentials: Credential<Credential.Me>
    sessions: Session<Sessions.Me>
    // TODO: add events emitter here
  }

  export type Identity<Row> = {
    findById(id: string): Promise<Row | null>
    findByEmail(email: string): Promise<Row | null>
    findByProviderSub(providerId: string, sub: string): Promise<Row | null>
    insert(row: Row): Promise<void>
    updateConditional(id: string, patch: Partial<Omit<Row, 'id'>>, expectedVersion: number): Promise<Row | null>
    softDelete(id: string, deletedAt: Date): Promise<void>
    restore(id: string): Promise<Row | null>
    erase(id: string): Promise<void>
    insertProviderLink(identityId: string, providerId: string, providerSub: string | null, addedAt: Date): Promise<void>
    deleteProviderLink(identityId: string, providerId: string): Promise<void>
    merge(survivorId: string, dupId: string): Promise<void>
  }

  export type Credential<Row> = {
    findById(id: string, tenantId: string | undefined): Promise<Row | null>
    listByIdentity(identityId: string, kind: Credential.Kind | null, tenantId: string | undefined): Promise<Row[]>
    findByProviderSub(provider: string, sub: string, tenantId: string | undefined): Promise<Row | null>
    findByHashedSecret(secretHash: string, kind: Credential.Kind, tenantId: string | undefined): Promise<Row | null>
    insert(row: Row): Promise<void>
    updateConditional(
      id: string,
      patch: Partial<Omit<Row, 'id'>>,
      expectedVersion: number,
      tenantId: string | undefined,
    ): Promise<Row | null>
    revoke(id: string, revokedAt: Date, tenantId: string | undefined): Promise<void>
    delete(id: string, tenantId: string | undefined): Promise<void>
    deleteByKind(identityId: string, kind: Credential.Kind, tenantId: string | undefined): Promise<void>
  }

  export type Session<Row> = {
    insert(row: Row): Promise<void>
    findByHash(sidHash: string): Promise<Row | null>
    update(id: string, patch: Partial<Omit<Row, 'id'>>): Promise<Row | null>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<Row[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    deleteExpired(now: Date): Promise<number>
  }

  export type Event<Row> = {
    insert(row: Row): Promise<void>
  }
}
