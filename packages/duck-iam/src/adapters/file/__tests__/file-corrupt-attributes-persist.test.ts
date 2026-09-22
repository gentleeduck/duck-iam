import { describe, expect, it } from 'vitest'
import { IamFile, IamFileAdapter } from '../index'

// Pins that a corrupt attributes row still throws after a flush and reload, as on redis/http;
// losing it on flush would make an ABAC deny fail open after a restart.
function makeFs(initial: string): { fs: IamFile.IFS; read: () => string } {
  const files = new Map<string, string>([['/store.json', initial]])
  return {
    fs: {
      async mkdir() {},
      async readFile(p: string) {
        const v = files.get(p)
        if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        return v
      },
      async writeFile(p: string, d: string) {
        files.set(p, d)
      },
    },
    read: () => files.get('/store.json') ?? '',
  }
}

const CORRUPT = JSON.stringify({
  assignments: { 'someone-else': [{ role: 'viewer' }] },
  attributes: { bad: 'not-an-object', good: { tier: 'gold' } },
  policies: {},
  // `assignRole` refuses an unstored role, and the unrelated write below must succeed.
  roles: { editor: { id: 'editor', name: 'Editor', permissions: [] } },
})

function adapterOn(fs: IamFile.IFS) {
  return new IamFileAdapter({ fs, onPolicyError: () => {}, path: '/store.json', rootDir: '/' })
}

describe('file adapter: a corrupt attributes row survives a flush', () => {
  it('still throws after an unrelated write and a fresh load', async () => {
    const { fs, read } = makeFs(CORRUPT)

    const first = adapterOn(fs)
    await expect(first.getSubjectAttributes('bad')).rejects.toThrow(/corrupted attributes/)

    // An unrelated write, whose flush must not erase the corrupt row.
    await first.assignRole('someone-else', 'editor')

    const second = adapterOn(fs)
    await expect(second.getSubjectAttributes('bad')).rejects.toThrow(/corrupted attributes/)

    // The raw value goes back out verbatim, and the marker never reaches disk.
    const onDisk = JSON.parse(read())
    expect(onDisk.attributes.bad).toBe('not-an-object')
    expect(Object.hasOwn(onDisk, 'corruptAttributes')).toBe(false)
  })

  it('keeps the unrelated rows and the unrelated write', async () => {
    const { fs, read } = makeFs(CORRUPT)
    const adapter = adapterOn(fs)

    expect(await adapter.getSubjectAttributes('good')).toEqual({ tier: 'gold' })
    await adapter.assignRole('someone-else', 'editor')

    const onDisk = JSON.parse(read())
    expect(onDisk.attributes.good).toEqual({ tier: 'gold' })
    expect(onDisk.assignments['someone-else']).toEqual([{ role: 'viewer' }, { role: 'editor' }])
  })

  // An admin write is the sanctioned repair: it clears the marker, and the row
  // must then read back normally in this process and the next.
  it('an admin write repairs the row for good', async () => {
    const { fs } = makeFs(CORRUPT)
    const first = adapterOn(fs)

    await first.setSubjectAttributes('bad', { tier: 'silver' })
    expect(await first.getSubjectAttributes('bad')).toEqual({ tier: 'silver' })

    const second = adapterOn(fs)
    expect(await second.getSubjectAttributes('bad')).toEqual({ tier: 'silver' })
  })
})
