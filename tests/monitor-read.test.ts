import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.ts'

test('alert list filters expired alerts when requested', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('alert-expiration')
    const clock = join(root, 'clock.mjs')
    await writeFile(clock, 'Date.now = () => Date.parse("2026-01-01T00:00:00Z")\n')
    const result = await run(['alert', 'list', '--expired', 'false'], { NODE_OPTIONS: `--import=${join(root, 'routing.mjs')} --import=${clock}` })
    assert.deepEqual(result.body.items.map((item: { id: string }) => item.id), ['current', 'permanent'])
  })
})

test('monitor reads preserve selected resources without notifier configuration', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    assert.equal((await run(['alert', 'info', 'alert-a'])).body.id, 'alert-a')
    assert.deepEqual((await run(['alert', 'list'])).body.items.map((item: { id: string }) => item.id), ['alert-a'])
    assert.equal((await run(['alert', 'triggers'])).body.items[0].rule, '*')
    const list = await run(['notifier', 'list'])
    assert.equal(list.code, 0)
    assert.equal(list.body.items[0].id, 'notifier-a')
    assert.equal(list.body.items[0].description, null)
    assert.equal(Object.hasOwn(list.body.items[0], 'args'), false)
    assert.deepEqual((await run(['notifier', 'providers'])).body.telegram.required, ['chat_id', 'token'])
    const detail = await run(['notifier', 'get', 'notifier-a'])
    assert.equal(detail.code, 0)
    assert.equal(detail.body.id, 'notifier-a')
    assert.equal(detail.body.description, null)
    assert.doesNotMatch(detail.stdout + list.stdout, /private-value|person@example/)
    const before = calls.length
    assert.notEqual((await run(['alert', 'info', '../escape'])).code, 0)
    assert.equal(calls.length, before)
  })
})
