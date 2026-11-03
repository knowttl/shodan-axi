import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { readPrivate, writePrivate } from '../dist/private-file.js'

test('Windows ACL boundary protects writes and verifies requested reads', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-acl-'))
  const target = join(root, 'config.json')
  const actions = []
  const options = { platform: 'win32', acl: (path, action, directory) => { actions.push({ path, action, directory }) } }
  try {
    await writePrivate(target, 'value', options)
    assert.equal(await readFile(target, 'utf8'), 'value')
    assert.equal(await readPrivate(target, false, true, options), 'value')
    assert.equal(actions[0].action, 'restrict')
    assert.equal(actions[0].directory, true)
    assert.equal(actions[1].action, 'restrict')
    assert.equal(actions[1].directory, false)
    assert.deepEqual(actions.at(-1), { path: target, action: 'verify', directory: false })
  } finally { await rm(root, { recursive: true, force: true }) }
})
