import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { putProfile, readConfig } from '../dist/credentials.js'
import { writePrivate } from '../dist/private-file.js'

for (const makeDefault of [false, true]) {
  for (const referenceType of ['env', 'file']) {
    test(`${makeDefault ? 'init' : 'profile set'} preserves endpoints when updating a ${referenceType} reference`, async () => {
      const root = await mkdtemp(join(tmpdir(), 'shodan-credentials-'))
      const path = join(root, 'config.json')
      const profileName = makeDefault ? 'default' : 'selected'
      const original = {
        auth: 'api-key', origin: 'https://127.0.0.1:12345', streamOrigin: 'https://127.0.0.1:12346', apiKey: { env: 'OLD_KEY' },
      }
      const other = { auth: 'api-key', origin: 'https://127.0.0.1:12347', apiKey: { env: 'OTHER_KEY' } }
      const reference = referenceType === 'env' ? { env: 'NEW_KEY' } : { file: join(root, 'secret') }
      try {
        await writePrivate(path, JSON.stringify({ version: 1, defaultProfile: 'other', profiles: { [profileName]: original, other } }))
        await putProfile(path, profileName, reference, makeDefault)
        assert.deepEqual(await readConfig(path), {
          version: 1, defaultProfile: makeDefault ? profileName : 'other', profiles: { [profileName]: { ...original, apiKey: reference }, other },
        })
      } finally { await rm(root, { recursive: true, force: true }) }
    })
  }
}
