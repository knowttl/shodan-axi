import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFile } from 'node:fs/promises'
import { withInvestigation } from './investigation-fixture.ts'

test('published scan job output schemas are closed at every object boundary', async () => {
  const inventory = JSON.parse(await readFile(new URL('../command-inventory.json', import.meta.url), 'utf8'))
  const list = inventory.commands.find((command: { command: string }) => command.command === 'scan list').outputSchema
  const status = inventory.commands.find((command: { command: string }) => command.command === 'scan status').outputSchema
  assert.ok(list, 'scan list must publish its output schema')
  assert.ok(status, 'scan status must publish its output schema')
  assert.equal(list.additionalProperties, false)
  assert.deepEqual(Object.keys(list.properties).sort(), ['complete', 'items', 'pagination', 'total'])
  assert.equal(list.properties.items.items.additionalProperties, false)
  assert.deepEqual(Object.keys(list.properties.items.items.properties).sort(), ['created', 'credits_left', 'id', 'size', 'status', 'status_check'])
  assert.deepEqual(list.properties.items.items.required.sort(), ['id', 'status'])
  assert.equal(status.additionalProperties, false)
  assert.deepEqual(Object.keys(status.properties).sort(), ['count', 'created', 'error', 'id', 'polling', 'status'])
  assert.deepEqual(status.required.sort(), ['id', 'polling', 'status'])
})

test('scan reads preserve job identity and disclose incomplete list scope', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    assert.equal((await run(['scan', 'protocols'])).body.https, 'Synthetic HTTPS module')
    const list = await run(['scan', 'list'])
    assert.deepEqual(list.body, { items: [{ id: 'scan-a', status: 'PROCESSING', created: '2026-01-01', status_check: '2026-01-02', credits_left: 98, size: 2 }], total: 2, complete: false, pagination: 'undocumented' })
    assert.doesNotMatch(list.stdout, /issued-secret|api_key/)
    const status = await run(['scan', 'status', 'scan-a', '--poll-attempts', '2', '--poll-interval-ms', '0', '--max-requests', '2'])
    assert.deepEqual(status.body, { id: 'scan-a', status: 'PROCESSING', count: 2, created: '2026-01-01', polling: 'attempt-limit' })
    assert.equal(calls.filter(call => call.path === '/shodan/scan/scan-a').length, 2)
    assert.doesNotMatch(status.stdout, /issued-secret|api_key/)
    assert.equal((await run(['scan', 'list', '--page', '2'])).body.error, 'INVALID_INPUT')
  })
})

test('scan submission binds expanded targets, force and credit budget', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const args = ['scan', 'submit', '192.0.2.0/31,192.0.2.1', '--allow-operation', 'OP-009', '--scan-credit-budget', '3', '--max-requests', '1']
    const rejected = await run(['scan', 'submit', '192.0.2.0/31', '--allow-operation', 'OP-009', '--scan-credit-budget', '1', '--max-requests', '1'])
    assert.equal(rejected.body.error, 'CREDIT_BUDGET_REQUIRED')
    const preview = await run(args)
    assert.equal(preview.body.targetCount, 2)
    assert.equal(preview.body.estimatedScanCredits, 3)
    assert.equal(preview.body.force, false)
    const token = preview.body.token
    assert.equal((await run([...args, '--force', '--execute', '--confirm', token])).body.error, 'PLAN_STALE')
    assert.equal((await run([...args, '--execute', '--confirm', token], { SHODAN_AXI_READ_ONLY: 'true' })).body.error, 'READ_ONLY')
    const result = await run([...args, '--execute', '--confirm', token])
    assert.equal(result.body.status, 'submitted')
    assert.equal(result.body.scanId, 'scan-a')
    assert.equal(result.body.vendorCompletion, 'unknown')
    const sent = calls.filter(call => call.method === 'POST')
    assert.equal(sent.length, 1)
    assert.equal(new URLSearchParams(sent[0]!.body).get('ips'), '192.0.2.0/31,192.0.2.1')
    assert.equal((await run([...args, '--execute', '--confirm', token])).body.error, 'PLAN_NOT_FOUND')
  })
})

test('scan polling failure preserves the last observed job identity and status', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('scan-poll-failure')
    const result = await run(['scan', 'status', 'scan-a', '--poll-attempts', '2', '--poll-interval-ms', '0', '--max-requests', '2'])
    assert.equal(result.body.id, 'scan-a')
    assert.equal(result.body.status, 'PROCESSING')
    assert.equal(result.body.polling, 'error')
    assert.equal(result.body.error, 'UPSTREAM_ERROR')
  })
})

test('Internet scan requires unknown-cost acceptance and preserves its job ID', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const args = ['scan', 'internet', '443', 'https', '--allow-operation', 'OP-010', '--scan-credit-budget', '1', '--max-requests', '1']
    assert.equal((await run(args)).body.error, 'WRITE_GRANT_REQUIRED')
    const approved = [...args, '--accept-unknown-cost']
    const preview = await run(approved)
    assert.equal(preview.body.scope, 'internet')
    assert.equal(preview.body.estimatedScanCredits, 'unknown')
    const result = await run([...approved, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.scanId, 'scan-internet')
    assert.equal(calls.filter(call => call.method === 'POST').length, 1)
  })
})

test('IPv6 expansion and forced scan bind the submitted form', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls }) => {
    const args = ['scan', 'submit', '2001:db8::/127', '--force', '--allow-operation', 'OP-009', '--scan-credit-budget', '2', '--max-requests', '1']
    const preview = await run(args)
    assert.equal(preview.body.targetCount, 2)
    assert.equal(preview.body.force, true)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'submitted')
    assert.equal(new URLSearchParams(calls.find(call => call.method === 'POST')!.body).get('force'), 'true')
  })
})

for (const mode of ['lost-write', 'scan-rejected']) test(`${mode} scan response reports an unknown outcome without retry`, { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    const args = ['scan', 'submit', '192.0.2.0/31', '--allow-operation', 'OP-009', '--scan-credit-budget', '2', '--max-requests', '1']
    const preview = await run(args)
    setMode(mode)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.status, 'OUTCOME_UNKNOWN')
    assert.equal(calls.filter(call => call.method === 'POST').length, 1)
  })
})
