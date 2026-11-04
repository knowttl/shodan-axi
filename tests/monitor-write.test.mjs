import assert from 'node:assert/strict'
import { mkdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

const permit = ['--allow-operation', 'OP-015', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']

test('delete requires a bound preview and dispatches at most once', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    assert.notEqual((await run(['alert', 'remove', 'alert-a'])).code, 0)
    const preview = await run(['alert', 'remove', 'alert-a', ...permit])
    assert.equal(preview.body.status, 'preview')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 0)
    const token = preview.body.token
    const wrong = await run(['alert', 'remove', 'other', ...permit, '--execute', '--confirm', token])
    assert.equal(wrong.body.error, 'PLAN_STALE')
    const denied = await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', token], { SHODAN_AXI_READ_ONLY: 'true' })
    assert.equal(denied.body.error, 'READ_ONLY')
    const done = await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', token])
    assert.equal(done.body.steps[0].readback, 'verified-absent')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 1)
    assert.equal((await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', token])).body.error, 'PLAN_NOT_FOUND')
    assert.doesNotMatch(await readFile(join(root, '.local/state/shodan-axi/writes.log'), 'utf8'), /fake-secret/)
  })
})

test('lost write response reports an unknown outcome without retry', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    const preview = await run(['alert', 'remove', 'alert-a', ...permit])
    setMode('lost-write')
    const result = await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'OUTCOME_UNKNOWN')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 1)
  })
})

test('credential revision and concurrent confirmation cannot dispatch twice', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const preview = await run(['alert', 'remove', 'alert-a', ...permit])
    const args = ['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', preview.body.token]
    assert.equal((await run(args, { TEST_SHODAN_KEY: 'rotated-secret' })).body.error, 'PLAN_STALE')
    const results = await Promise.all([run(args), run(args)])
    assert.equal(results.filter(result => result.body.status === 'completed').length, 1)
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 1)
  })
})

test('the protected journal override is honored and symlinks are refused', { timeout: 30000, skip: process.platform === 'win32' }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const directory = join(root, 'journal'); await mkdir(directory, { mode: 0o700 })
    const log = join(directory, 'writes.log'); const env = { SHODAN_AXI_WRITE_LOG: log }
    const preview = await run(['alert', 'remove', 'alert-a', ...permit], env)
    const target = join(directory, 'target'); await writeFile(target, 'unchanged', { mode: 0o600 })
    await symlink(target, log)
    const attempt = await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', preview.body.token], env)
    assert.notEqual(attempt.code, 0)
    assert.equal(await readFile(target, 'utf8'), 'unchanged')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 0)
  })
})

test('changed private notifier input invalidates its confirmation', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const path = join(root, 'notifier.json')
    await writeFile(path, JSON.stringify({ provider: 'email', args: { to: 'first@example.test' } }), { mode: 0o600 })
    const options = ['--body-file', path, '--allow-operation', 'OP-027', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
    const preview = await run(['notifier', 'create', ...options])
    await writeFile(path, JSON.stringify({ provider: 'email', args: { to: 'other@example.test' } }), { mode: 0o600 })
    assert.equal((await run(['notifier', 'create', ...options, '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_STALE')
    assert.equal(calls.filter(call => call.method !== 'GET').length, 0)
  })
})

test('tampered plans and changed observed state cannot authorize a write', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const preview = await run(['alert', 'remove', 'alert-a', ...permit])
    const planPath = join(root, '.local/state/shodan-axi/plans', `${preview.body.token}.json`)
    const plan = JSON.parse(await readFile(planPath, 'utf8'))
    plan.preconditions = ['forged']
    await writeFile(planPath, JSON.stringify(plan), { mode: 0o600 })
    assert.equal((await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', preview.body.token])).body.error, 'PLAN_STALE')
    const fresh = await run(['alert', 'remove', 'alert-a', ...permit])
    const update = ['alert', 'update', 'alert-a', '192.0.2.0/25', '--allow-operation', 'OP-016', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
    const updatePreview = await run(update)
    assert.equal((await run([...update, '--execute', '--confirm', updatePreview.body.token])).body.status, 'completed')
    assert.equal((await run(['alert', 'remove', 'alert-a', ...permit, '--execute', '--confirm', fresh.body.token])).body.error, 'PLAN_STALE')
    assert.equal(calls.filter(call => call.method === 'DELETE').length, 0)
  })
})

test('clear deletes only its confirmed snapshot', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const clear = await run(['alert', 'clear', ...permit])
    assert.equal(clear.body.status, 'preview')
    const createPermit = ['--allow-operation', 'OP-013', '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
    const create = await run(['alert', 'create', 'Later alert', '192.0.2.9', ...createPermit])
    assert.equal((await run(['alert', 'create', 'Later alert', '192.0.2.9', ...createPermit, '--execute', '--confirm', create.body.token])).body.status, 'completed')
    const result = await run(['alert', 'clear', ...permit, '--execute', '--confirm', clear.body.token])
    assert.equal(result.body.status, 'completed')
    assert.deepEqual(calls.filter(call => call.method === 'DELETE').map(call => call.path), ['/shodan/alert/alert-a'])
    assert.equal((await run(['alert', 'info', 'alert-new'])).body.id, 'alert-new')
  })
})

test('domain alert previews resolved addresses and enables the approved trigger', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const options = ['--triggers', 'new_service', '--allow-operation', 'OP-040,OP-013,OP-019', '--accept-unknown-cost', '--query-credit-budget', '4', '--max-requests', '6']
    const preview = await run(['alert', 'domain', 'example.test', ...options])
    assert.equal(preview.body.status, 'preview')
    assert.deepEqual(preview.body.effects.map(effect => effect.operation), ['OP-013', 'OP-019'])
    const result = await run(['alert', 'domain', 'example.test', ...options, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'completed')
    assert.deepEqual(result.body.steps.map(step => step.readback), ['verified', 'verified'])
    assert.equal(calls.filter(call => call.method === 'POST').length, 1)
    assert.equal(calls.filter(call => call.method === 'PUT').length, 1)
  })
})

test('import validates all input and stops after an uncertain mutation', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    const path = join(root, 'import.json.gz')
    const input = [{ name: 'Imported', filters: { ip: ['192.0.2.0/24'] }, triggers: { new_service: {} }, notifiers: [{ id: 'old', provider: 'email', args: { to: 'hidden@example.test' } }] }]
    await writeFile(path, gzipSync(JSON.stringify(input)), { mode: 0o600 })
    const options = ['--allow-operation', 'OP-027,OP-013,OP-019,OP-023', '--accept-unknown-cost', '--query-credit-budget', '4', '--max-requests', '10']
    const preview = await run(['alert', 'import', path, ...options])
    assert.equal(preview.body.status, 'preview')
    assert.deepEqual(preview.body.effects.map(item => item.operation), ['OP-027', 'OP-013', 'OP-019', 'OP-023'])
    assert.doesNotMatch(preview.stdout, /hidden@example/)
    setMode('lost-create-alert')
    const result = await run(['alert', 'import', path, ...options, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'OUTCOME_UNKNOWN')
    assert.deepEqual(result.body.completed.map(item => item.operation), ['OP-027'])
    assert.equal(result.body.uncertain.operation, 'OP-013')
    assert.deepEqual(result.body.unsent.map(item => item.operation), ['OP-019', 'OP-023'])
    assert.equal(calls.filter(call => call.method !== 'GET').length, 2)
  })
})

test('import executes only the confirmed ordered actions without exposing notifier input', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const path = join(root, 'import.json.gz')
    const input = [{ name: 'Imported', filters: { ip: ['192.0.2.0/24'] }, triggers: { new_service: {} }, notifiers: [{ id: 'old', provider: 'email', args: { to: 'hidden@example.test' } }] }]
    await writeFile(path, gzipSync(JSON.stringify(input)), { mode: 0o600 })
    const options = ['--allow-operation', 'OP-027,OP-013,OP-019,OP-023', '--accept-unknown-cost', '--query-credit-budget', '4', '--max-requests', '10']
    const preview = await run(['alert', 'import', path, ...options])
    const result = await run(['alert', 'import', path, ...options, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'completed')
    assert.deepEqual(result.body.steps.map(item => item.operation), ['OP-027', 'OP-013', 'OP-019', 'OP-023'])
    assert.deepEqual(calls.filter(call => call.method !== 'GET').map(call => call.path), ['/notifier', '/shodan/alert', '/shodan/alert/alert-new/trigger/new_service', '/shodan/alert/alert-new/notifier/notifier-new'])
    assert.doesNotMatch(result.stdout + await readFile(join(root, '.local/state/shodan-axi/writes.log'), 'utf8'), /hidden@example/)
  })
})

test('import stops when a prior action cannot be verified', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    const path = join(root, 'import.json.gz')
    const input = [{ name: 'Imported', filters: { ip: ['192.0.2.0/24'] }, triggers: { new_service: {} }, notifiers: [{ id: 'old', provider: 'email', args: { to: 'hidden@example.test' } }] }]
    await writeFile(path, gzipSync(JSON.stringify(input)), { mode: 0o600 })
    const options = ['--allow-operation', 'OP-027,OP-013,OP-019,OP-023', '--accept-unknown-cost', '--query-credit-budget', '4', '--max-requests', '10']
    const preview = await run(['alert', 'import', path, ...options])
    setMode('trigger-unverified')
    const result = await run(['alert', 'import', path, ...options, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'READBACK_UNVERIFIED')
    assert.deepEqual(result.body.unsent.map(item => item.operation), ['OP-023'])
    assert.equal(calls.filter(call => call.method !== 'GET').length, 3)
  })
})

test('each supported mutation dispatches exactly its selected request', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const createBody = join(root, 'notifier-create.json'); const updateBody = join(root, 'notifier-update.json')
    await writeFile(createBody, JSON.stringify({ provider: 'email', description: 'Synthetic', args: { to: 'hidden@example.test' } }), { mode: 0o600 })
    await writeFile(updateBody, JSON.stringify({ args: { to: 'new@example.test' } }), { mode: 0o600 })
    const cases = [
      ['OP-013', ['alert', 'create', 'Created', '192.0.2.9'], 'POST', '/shodan/alert'],
      ['OP-016', ['alert', 'update', 'alert-a', '192.0.2.0/25'], 'POST', '/shodan/alert/alert-a'],
      ['OP-019', ['alert', 'enable', 'alert-a', 'any'], 'PUT', '/shodan/alert/alert-a/trigger/any'],
      ['OP-020', ['alert', 'disable', 'alert-a', 'any'], 'DELETE', '/shodan/alert/alert-a/trigger/any'],
      ['OP-021', ['alert', 'ignore', 'alert-a', 'any', '192.0.2.7:443'], 'PUT', '/shodan/alert/alert-a/trigger/any/ignore/192.0.2.7%3A443'],
      ['OP-022', ['alert', 'unignore', 'alert-a', 'any', '192.0.2.7:443'], 'DELETE', '/shodan/alert/alert-a/trigger/any/ignore/192.0.2.7%3A443'],
      ['OP-070', ['alert', 'ignore', 'alert-a', 'any', '192.0.2.7:443', '--vulns', 'CVE-2020-0001'], 'PUT', '/shodan/alert/alert-a/trigger/any/ignore/192.0.2.7%3A443/CVE-2020-0001'],
      ['OP-023', ['alert', 'notifier', 'add', 'alert-a', 'notifier-a'], 'PUT', '/shodan/alert/alert-a/notifier/notifier-a'],
      ['OP-024', ['alert', 'notifier', 'remove', 'alert-a', 'notifier-a'], 'DELETE', '/shodan/alert/alert-a/notifier/notifier-a'],
      ['OP-027', ['notifier', 'create', '--body-file', createBody], 'POST', '/notifier'],
      ['OP-030', ['notifier', 'update', 'notifier-a', '--body-file', updateBody], 'PUT', '/notifier/notifier-a'],
      ['OP-028', ['notifier', 'remove', 'notifier-a'], 'DELETE', '/notifier/notifier-a'],
      ['OP-015', ['alert', 'remove', 'alert-a'], 'DELETE', '/shodan/alert/alert-a'],
    ]
    for (const [operation, args, method, path] of cases) {
      const options = ['--allow-operation', operation, '--accept-unknown-cost', '--query-credit-budget', '1', '--max-requests', '3']
      const preview = await run([...args, ...options])
      assert.equal(preview.body.status, 'preview', operation)
      const before = calls.filter(call => call.method !== 'GET').length
      const result = await run([...args, ...options, '--execute', '--confirm', preview.body.token])
      assert.equal(result.body.status, 'completed', operation)
      const writes = calls.filter(call => call.method !== 'GET')
      assert.equal(writes.length, before + 1, operation)
      assert.equal(writes.at(-1).method, method, operation)
      assert.equal(writes.at(-1).path, path, operation)
      assert.doesNotMatch(result.stdout + preview.stdout, /hidden@example|new@example/)
    }
  })
})
