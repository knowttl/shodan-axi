import assert from 'node:assert/strict'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

test('monitor reads preserve selected resources without notifier configuration', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    assert.equal((await run(['alert', 'info', 'alert-a'])).body.id, 'alert-a')
    assert.deepEqual((await run(['alert', 'list'])).body.items.map(item => item.id), ['alert-a'])
    assert.equal((await run(['alert', 'triggers'])).body.items[0].rule, '*')
    const list = await run(['notifier', 'list'])
    assert.equal(list.body.items[0].id, 'notifier-a')
    assert.equal(Object.hasOwn(list.body.items[0], 'args'), false)
    assert.deepEqual((await run(['notifier', 'providers'])).body.telegram.required, ['chat_id', 'token'])
    const detail = await run(['notifier', 'get', 'notifier-a'])
    assert.equal(detail.body.id, 'notifier-a')
    assert.doesNotMatch(detail.stdout + list.stdout, /private-value|person@example/)
    const before = calls.length
    assert.notEqual((await run(['alert', 'info', '../escape'])).code, 0)
    assert.equal(calls.length, before)
  })
})
