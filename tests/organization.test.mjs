import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

test('organization reads omit issued credentials unless explicitly saved privately', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const info = await run(['org', 'info'])
    assert.equal(info.body.name, 'Synthetic Org')
    assert.equal(info.body.members[0].email, 'existing@example.test')
    assert.doesNotMatch(info.stdout + info.stderr, /issued-secret|api_key/)
    const destination = join(root, 'issued-key')
    const saved = await run(['org', 'info', '--credential-file', destination])
    assert.equal(saved.code, 0)
    assert.doesNotMatch(saved.stdout + saved.stderr, /issued-secret|api_key/)
    assert.equal(await readFile(destination, 'utf8'), 'issued-secret')
    if (process.platform !== 'win32') assert.equal((await stat(destination)).mode & 0o077, 0)
  })
})

for (const silent of [false, true]) {
  test(`organization membership binds notification choice ${silent ? 'silent' : 'enabled'}`, { timeout: 30000 }, async () => {
    await withInvestigation(async ({ root, calls, run }) => {
      const options = ['--allow-operation', 'OP-037', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
      const args = ['org', 'add', 'new@example.test', ...(silent ? ['--silent'] : []), ...options]
      const preview = await run(args)
      assert.equal(preview.body.effects[0].notify, !silent)
      const mismatch = await run(['org', 'add', 'new@example.test', ...(silent ? [] : ['--silent']), ...options, '--execute', '--confirm', preview.body.token])
      assert.equal(mismatch.body.error, 'PLAN_STALE')
      const denied = await run([...args, '--execute', '--confirm', preview.body.token], { SHODAN_AXI_READ_ONLY: 'true' })
      assert.equal(denied.body.error, 'READ_ONLY')
      const done = await run([...args, '--execute', '--confirm', preview.body.token])
      assert.equal(done.body.status, 'completed')
      assert.equal(done.body.steps[0].status, 'verified')
      const mutation = calls.filter(call => call.method === 'PUT')
      assert.equal(mutation.length, 1)
      assert.equal(mutation[0].query.notify, String(!silent))
      const info = await run(['org', 'info'])
      assert.deepEqual(info.body.members.map(member => member.email), ['existing@example.test', 'other@example.test', 'new@example.test'])
      assert.equal(info.body.admins[0].email, 'owner@example.test')
      assert.doesNotMatch(done.stdout + await readFile(join(root, '.local/state/shodan-axi/writes.log'), 'utf8'), /issued-secret/)
    })
  })
}

test('organization removal previews downgrade and verifies the selected member', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    const args = ['org', 'remove', 'existing@example.test', '--allow-operation', 'OP-038', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
    const preview = await run(args)
    assert.equal(preview.body.effects[0].downgrade, true)
    setMode('org-unchanged')
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token])).body.status, 'READBACK_UNVERIFIED')
    setMode('normal')
    const next = await run(args)
    const result = await run([...args, '--execute', '--confirm', next.body.token])
    assert.equal(result.body.steps[0].status, 'verified')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 2)
    const info = await run(['org', 'info'])
    assert.deepEqual(info.body.members.map(member => member.email), ['other@example.test'])
    assert.equal(info.body.admins[0].email, 'owner@example.test')
  })
})

test('a lost organization write response is not retried', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    const args = ['org', 'remove', 'existing@example.test', '--allow-operation', 'OP-038', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
    const preview = await run(args)
    setMode('lost-write')
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'OUTCOME_UNKNOWN')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 1)
  })
})
