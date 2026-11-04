import assert from 'node:assert/strict'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

const limits = { limit: 2, maxBytes: 10000, timeout: 5000, idleTimeout: 3000 }
const args = ['stream', '--allow-operation', 'OP-046', '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000']
const start = confirmation => ({ version: 1, type: 'start', requestId: 'start-1', operation: 'OP-046', selector: null, bounds: limits, confirmation })

test('private worker frames admitted events, loss and a terminal summary', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token))
    assert.deepEqual(await worker.next(), { version: 1, type: 'ready', requestId: 'start-1' })
    const first = await worker.next(); const loss = await worker.next(); const second = await worker.next(); const closed = await worker.next()
    assert.equal(first.type, 'event'); assert.equal(first.event.data, 'Café')
    assert.equal(loss.type, 'loss'); assert.equal(loss.discarded, 3)
    assert.equal(second.type, 'event'); assert.equal(second.event.ip_str, '192.0.2.8')
    assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'max-events'); assert.equal(closed.count, 2)
    assert.deepEqual(closed.bounds, limits)
    assert.equal(await worker.closed, 0)
    assert.equal(calls.filter(call => call.path === '/shodan/banners').length, 1)
  })
})

test('hosted banner output closes its schema and redacts credential patterns', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, setMode }) => {
    setMode('stream-secrets')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token))
    assert.equal((await worker.next()).type, 'ready')
    const { event } = await worker.next()
    assert.equal(event.data, 'AccountKey=[REDACTED]')
    assert.equal('api_key' in event, false); assert.equal('arbitrary' in event, false)
    await worker.closed
  })
})

test('hosted provisional threat events redact sensitive keys and values', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, setMode }) => {
    setMode('stream-secrets')
    const threatArgs = ['threatnet', 'events', ...args.slice(1).map(value => value === 'OP-046' ? 'OP-067' : value)]
    const preview = await run(threatArgs)
    const worker = launchWorker(); worker.send({ ...start(preview.body.token), operation: 'OP-067' })
    assert.equal((await worker.next()).type, 'ready')
    const { event } = await worker.next()
    assert.deepEqual(event.nested, { api_key: '[REDACTED]', note: 'AccountKey=[REDACTED]', pem: '[REDACTED]', jwt: '[REDACTED]', sas: 'https://example.test/?sig=[REDACTED]' })
    await worker.closed
  })
})

test('private worker acknowledges extension and stops without reconnecting', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, setMode }) => {
    setMode('stream-wait')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token))
    assert.equal((await worker.next()).type, 'ready')
    assert.equal((await worker.next()).type, 'event')
    const deadlineMs = Date.now() + 6000
    worker.send({ version: 1, type: 'extend', requestId: 'extend-1', deadlineMs })
    assert.deepEqual(await worker.next(), { version: 1, type: 'extended', requestId: 'extend-1', deadlineMs })
    worker.send({ version: 1, type: 'stop', requestId: 'stop-1' })
    const closed = await worker.next()
    assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'cancelled'); assert.equal(closed.count, 1)
    assert.equal(await worker.closed, 0)
    assert.equal(calls.filter(call => call.path === '/shodan/banners').length, 1)
  })
})

test('private worker refuses an unconfirmed start before connecting', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const worker = launchWorker(); worker.send(start('00000000-0000-4000-8000-000000000001'))
    const closed = await worker.next()
    assert.equal(closed.type, 'closed'); assert.equal(closed.error, 'PLAN_NOT_FOUND')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})

test('duplicate protocol request IDs terminate without opening a stream', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker(); const request = start(preview.body.token)
    worker.send(request); worker.send(request)
    const closed = await worker.next()
    assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'protocol-error')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})

test('stop during admission does not open a stream', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token)); worker.send({ version: 1, type: 'stop', requestId: 'stop-early' })
    const closed = await worker.next()
    assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'cancelled')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})
