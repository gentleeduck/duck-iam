import { describe, expect, it } from 'vitest'
import type { IamRequest } from '../../types'
import { enrichSubjectWithScopedRoles } from '../engine.libs'

function subject(roles: string[], scopedRoles?: IamRequest.IScopedRole[]): IamRequest.ISubject {
  return { id: 'user-1', roles, scopedRoles, attributes: {} }
}

describe('enrichSubjectWithScopedRoles', () => {
  it('returns the subject unchanged when scope is undefined', () => {
    const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
    expect(enrichSubjectWithScopedRoles(s, undefined)).toBe(s)
  })

  it('returns the subject unchanged when there are no scoped roles', () => {
    const s = subject(['viewer'])
    expect(enrichSubjectWithScopedRoles(s, 'org-1')).toBe(s)
  })

  describe("scopeMode: 'flat' (default)", () => {
    it('merges a scoped role on exact scope match', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1').roles).toEqual(['viewer', 'editor'])
    })

    it('does not merge a scoped role granted at an ancestor scope', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3').roles).toEqual(['viewer'])
    })

    it('is the default when scopeMode is omitted', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2').roles).toEqual(['viewer'])
    })
  })

  describe("scopeMode: 'hierarchical'", () => {
    it('merges a role granted at an ancestor of the request scope', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical').roles).toEqual(['viewer', 'editor'])
    })

    it('unions grants from multiple ancestor levels', () => {
      const s = subject(
        ['viewer'],
        [
          { role: 'org-editor', scope: 'org-1' },
          { role: 'team-admin', scope: 'org-1.team-2' },
        ],
      )
      const enriched = enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical')
      expect(enriched.roles).toEqual(['viewer', 'org-editor', 'team-admin'])
    })

    it('does not leak a grant from an unrelated org into the walk', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-2' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical').roles).toEqual(['viewer'])
    })

    it('does not match a descendant scope of the request scope (ancestors only, not siblings/children)', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1.team-2.repo-3' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2', 'hierarchical').roles).toEqual(['viewer'])
    })

    it('degrades to exact match when the request scope has no dots', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1', 'hierarchical').roles).toEqual(['viewer', 'editor'])
      expect(enrichSubjectWithScopedRoles(s, 'org-2', 'hierarchical').roles).toEqual(['viewer'])
    })

    it('does not double-add a role already present from a base assignment', () => {
      const s = subject(['viewer', 'editor'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1.team-2', 'hierarchical').roles).toEqual(['viewer', 'editor'])
    })
  })

  describe("scopeCombine: 'override' (only under scopeMode: 'hierarchical')", () => {
    it('applies only the most specific matching level, ignoring a broader grant', () => {
      const s = subject(
        ['viewer'],
        [
          { role: 'org-editor', scope: 'org-1' },
          { role: 'repo-restricted', scope: 'org-1.team-2.repo-3' },
        ],
      )
      const enriched = enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical', 'override')
      expect(enriched.roles).toEqual(['viewer', 'repo-restricted'])
    })

    it('falls through to a broader level when no narrower level has a grant', () => {
      const s = subject(['viewer'], [{ role: 'org-editor', scope: 'org-1' }])
      const enriched = enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical', 'override')
      expect(enriched.roles).toEqual(['viewer', 'org-editor'])
    })

    it('unions multiple grants at the same winning level', () => {
      const s = subject(
        ['viewer'],
        [
          { role: 'org-editor', scope: 'org-1' },
          { role: 'repo-a', scope: 'org-1.team-2.repo-3' },
          { role: 'repo-b', scope: 'org-1.team-2.repo-3' },
        ],
      )
      const enriched = enrichSubjectWithScopedRoles(s, 'org-1.team-2.repo-3', 'hierarchical', 'override')
      expect(enriched.roles).toEqual(['viewer', 'repo-a', 'repo-b'])
    })

    it('is a no-op under scopeMode: flat (override only affects hierarchical)', () => {
      const s = subject(['viewer'], [{ role: 'editor', scope: 'org-1' }])
      expect(enrichSubjectWithScopedRoles(s, 'org-1', 'flat', 'override').roles).toEqual(['viewer', 'editor'])
    })
  })
})
