import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

const admission = 'synthetic-host-admission-binding-01'
const grant = { '--allow-operation': 'OP-015', '--accept-unknown-cost': true, '--query-credit-budget': '1', '--max-requests': '3' }
const write = (requestId, phase, words, flags, confirmation) => ({ version: 1, type: 'write', requestId, admission, phase, words, flags, ...(confirmation ? { confirmation } : {}) })
const writes = calls => calls.filter(call => call.method !== 'GET')

test('hosted write previews without mutating then executes once for the owner session', { timeout: 60000 }, async () => {
  await withInvestigation(async ({ launchWorker, calls }) => {
    const worker = launchWorker()
    worker.send(write('preview-1', 'preview', ['alert', 'remove', 'alert-a'], grant))
    const preview = await worker.next()
    assert.equal(preview.type, 'write-result'); assert.equal(preview.result.status, 'preview')
    assert.equal(writes(calls).length, 0)
    worker.send(write('execute-1', 'execute', ['alert', 'remove', 'alert-a'], grant, preview.result.token))
    const executed = await worker.next()
    assert.equal(executed.result.status, 'completed')
    assert.deepEqual(executed.result.steps.map(step => step.status), ['verified'])
    assert.equal((await worker.next()).stopReason, 'completed')
    assert.equal(await worker.closed, 0)
    assert.deepEqual(writes(calls).map(call => call.method), ['DELETE'])

    const replay = launchWorker()
    replay.send(write('execute-2', 'execute', ['alert', 'remove', 'alert-a'], grant, preview.result.token))
    assert.equal((await replay.next()).result.error, 'PLAN_NOT_FOUND')
    replay.close(); await replay.closed
    assert.equal(writes(calls).length, 1)
  })
})

test('hosted write refuses a confirmation previewed outside the owner session', { timeout: 60000 }, async () => {
  await withInvestigation(async ({ runHosted, launchWorker, calls }) => {
    const preview = await runHosted(['alert', 'remove', 'alert-a', '--allow-operation', 'OP-015', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3'])
    const worker = launchWorker()
    worker.send(write('execute-1', 'execute', ['alert', 'remove', 'alert-a'], grant, preview.body.token))
    assert.equal((await worker.next()).result.error, 'PLAN_STALE')
    worker.close(); await worker.closed
    assert.equal(writes(calls).length, 0)
  })
})

test('hosted write refuses requests outside the approved policy before any change', { timeout: 60000 }, async () => {
  await withInvestigation(async ({ root, launchWorker, calls }) => {
    const worker = launchWorker()
    const { '--allow-operation': _grant, ...ungranted } = grant
    const download = { '--allow-operation': 'OP-003', '--query-credit-budget': '1', '--max-requests': '3', '--limit': '2', '--max-bytes': '10000' }
    for (const [name, words, flags, phase, confirmation, error] of [
      ['unapproved scan', ['scan', 'submit', '192.0.2.1'], { ...grant, '--allow-operation': 'OP-009' }, 'preview', undefined, 'INVALID_INPUT'],
      ['caller-selected profile', ['alert', 'remove', 'alert-a'], { ...grant, '--profile': 'other' }, 'preview', undefined, 'INVALID_INPUT'],
      ['missing operation grant', ['alert', 'remove', 'alert-a'], ungranted, 'preview', undefined, 'WRITE_GRANT_REQUIRED'],
      ['request bound above the ceiling', ['alert', 'remove', 'alert-a'], { ...grant, '--max-requests': '1001' }, 'preview', undefined, 'CREDIT_BUDGET_REQUIRED'],
      ['relative download destination', ['download', 'port:443'], { ...download, '--filename': 'relative' }, 'preview', undefined, 'INVALID_INPUT'],
      ['execute without a token', ['alert', 'remove', 'alert-a'], grant, 'execute', undefined, 'INVALID_INPUT'],
    ]) {
      worker.send(write(name, phase, words, flags, confirmation))
      const result = await worker.next()
      assert.equal(result.result?.error, error, `${name}: ${JSON.stringify(result)}`)
    }
    worker.close(); await worker.closed
    assert.equal(writes(calls).length, 0)
    await assert.rejects(stat(join(root, 'relative.json.gz')), { code: 'ENOENT' })
  })
})

test('hosted download previews then saves the export for the owner session', { timeout: 60000 }, async () => {
  await withInvestigation(async ({ root, launchWorker }) => {
    const destination = join(root, 'export.json.gz')
    const flags = { '--allow-operation': 'OP-003', '--filename': destination, '--limit': '2', '--max-bytes': '100000', '--max-requests': '3', '--query-credit-budget': '1' }
    const worker = launchWorker()
    worker.send(write('preview-1', 'preview', ['download', 'port:443'], flags))
    const preview = await worker.next()
    assert.equal(preview.result.status, 'preview')
    await assert.rejects(stat(destination), { code: 'ENOENT' })
    worker.send(write('execute-1', 'execute', ['download', 'port:443'], flags, preview.result.token))
    const executed = await worker.next()
    assert.equal(executed.result.path, destination); assert.equal(executed.result.complete, true)
    assert.ok((await stat(destination)).size > 0)
    assert.equal((await worker.next()).stopReason, 'completed')
    assert.equal(await worker.closed, 0)
  })
})

test('inventory publishes the approved writes and budget ceilings', async () => {
  const { commands, hostedWrites } = JSON.parse(await readFile(new URL('../command-inventory.json', import.meta.url), 'utf8'))
  assert.deepEqual(hostedWrites.budget, { queryCredits: 1000, scanCredits: 1000000, requests: 1000 })
  assert.equal(hostedWrites.confirmation.singleUse, true)
  const approved = hostedWrites.approved.map(item => item.command)
  assert.ok(approved.every(command => commands.some(item => item.command === command)))
  const writeCommands = commands.filter(item => item.effect === 'write' && !item.command.startsWith('scan ')).map(item => item.command)
  assert.deepEqual([...new Set(writeCommands)].sort(), approved.filter(command => !command.includes('download')).sort())
  assert.ok(!approved.some(command => command.startsWith('scan ')))
  assert.deepEqual(hostedWrites.approved.find(item => item.command === 'alert domain').operations, ['OP-040', 'OP-013', 'OP-019'])
})
