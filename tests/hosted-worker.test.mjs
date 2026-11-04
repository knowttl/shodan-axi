import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { test } from 'node:test'
import { withInvestigation } from './investigation-fixture.mjs'

const limits = { limit: 2, maxBytes: 10000, timeout: 5000, idleTimeout: 3000 }
const args = ['stream', '--allow-operation', 'OP-046', '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000']
const admission = 'synthetic-host-admission-binding-01'
const start = confirmation => ({ version: 1, type: 'start', requestId: 'start-1', admission, operation: 'OP-046', selector: null, bounds: limits, confirmation })

for (const [name, frame, error] of [
  ['malformed JSON', '{broken}\n', 'INVALID_INPUT'],
  ['invalid UTF-8', Buffer.from([0xff, 10]), 'INVALID_INPUT'],
  ['missing extension binding', `${JSON.stringify({ version: 1, type: 'extend', requestId: 'extend-1', deadlineMs: 1 })}\n`, 'INVALID_INPUT'],
  ['wrong extension binding', `${JSON.stringify({ version: 1, type: 'extend', requestId: 'extend-1', admission: 'incorrect-host-admission-binding-01', deadlineMs: 1 })}\n`, 'ADMISSION_REQUIRED'],
  ['rejected deadline', `${JSON.stringify({ version: 1, type: 'extend', requestId: 'extend-1', admission, deadlineMs: 1 })}\n`, 'INVALID_INPUT'],
  ['duplicate request', `${JSON.stringify({ version: 1, type: 'stop', requestId: 'start-1' })}\n`, 'INVALID_INPUT'],
  ['second start', `${JSON.stringify({ ...start('00000000-0000-4000-8000-000000000001'), requestId: 'start-2' })}\n`, 'INVALID_INPUT'],
  ['repeated admission', `${JSON.stringify({ version: 1, type: 'admit', requestId: 'admit-2', admission, profilePath: '/unused' })}\n`, 'ADMISSION_REQUIRED'],
  ['oversized frame', `${'x'.repeat(2 * 1024 * 1024 + 1)}\n`, 'INVALID_INPUT'],
  ['oversized pending frame', 'x'.repeat(2 * 1024 * 1024 + 1), 'INVALID_INPUT'],
]) {
  test(`worker preserves final accounting after ${name}`, { timeout: 30000 }, async () => {
    await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
      setMode('stream-wait-accounting')
      const preview = await run(args)
      const worker = launchWorker(); worker.send(start(preview.body.token))
      assert.equal((await worker.next()).type, 'ready')
      const first = await worker.next()
      assert.equal(first.type, 'event')
      assert.equal((await worker.next()).discarded, 3)
      worker.sendRaw(frame)
      const closed = await worker.next()
      assert.equal(closed.type, 'closed')
      assert.equal(closed.stopReason, 'protocol-error')
      assert.equal(closed.error, error)
      assert.equal(closed.count, 1)
      assert.equal(closed.bytes, Buffer.byteLength(`${JSON.stringify(first.event)}\n${JSON.stringify({ event: 'debug', discarded: 3 })}\n{"ip_str":`))
      assert.equal(closed.debugDiscarded, 3)
      assert.equal(closed.partialRecordCount, 1)
      assert.deepEqual(closed.bounds, limits)
      assert.equal(await worker.closed, 0)
      assert.equal(calls.length, 1)
    })
  })
}

test('private worker frames admitted events, loss and a terminal summary', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ runHosted: run, launchWorker, calls, hostProfile, setMode }) => {
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
    assert.deepEqual((await readFile(worker.readsPath, 'utf8')).trim().split('\n').map(line => JSON.parse(line)), [hostProfile])
    assert.equal(calls.filter(call => call.path === '/shodan/banners').length, 1)
  })
})

test('direct launch with ambient credentials refuses start before reading credentials or connecting', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, config, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker({ admitted: false, overrides: { SHODAN_AXI_CONFIG: config, TEST_SHODAN_KEY: 'fake-secret', SHODAN_AXI_API_KEY: 'developer-secret' } })
    worker.send(start(preview.body.token))
    assert.equal((await worker.next()).error, 'ADMISSION_REQUIRED')
    assert.equal(await worker.closed, 0)
    await assert.rejects(readFile(worker.readsPath), { code: 'ENOENT' })
    assert.equal(calls.length, 0)
  })
})

for (const binding of [undefined, 'incorrect-host-admission-binding-01']) {
  test(`worker rejects start with ${binding ? 'incorrect' : 'missing'} admission binding`, { timeout: 30000 }, async () => {
    await withInvestigation(async ({ runHosted: run, launchWorker, calls }) => {
      const preview = await run(args)
      const worker = launchWorker()
      worker.send({ ...start(preview.body.token), admission: binding })
      assert.equal((await worker.next()).stopReason, 'protocol-error')
      assert.equal(await worker.closed, 0)
      await assert.rejects(readFile(worker.readsPath), { code: 'ENOENT' })
      assert.equal(calls.length, 0)
    })
  })

  test(`worker rejects extension with ${binding ? 'incorrect' : 'missing'} admission binding`, { timeout: 30000 }, async () => {
    await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
      setMode('stream-wait')
      const preview = await run(args)
      const worker = launchWorker(); worker.send(start(preview.body.token))
      assert.equal((await worker.next()).type, 'ready')
      assert.equal((await worker.next()).type, 'event')
      worker.send({ version: 1, type: 'extend', requestId: 'extend-1', admission: binding, deadlineMs: Date.now() + 6000 })
      const closed = await worker.next()
      assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'protocol-error')
      assert.equal(await worker.closed, 0)
      assert.equal(calls.length, 1)
    })
  })
}

test('worker refuses a developer profile even after a handshake', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, launchWorker, calls, config }) => {
    const preview = await run(args)
    const worker = launchWorker({ profilePath: config, overrides: { TEST_SHODAN_KEY: 'fake-secret' } })
    worker.send(start(preview.body.token))
    assert.equal((await worker.next()).error, 'ADMISSION_REQUIRED')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})

test('admitted worker ignores ambient credential and origin overrides', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker({ overrides: { SHODAN_AXI_PROFILE: 'developer', SHODAN_AXI_CONFIG: '/unreadable/config.json', SHODAN_AXI_API_KEY: 'developer-secret', SHODAN_AXI_STREAM_ORIGIN: 'https://invalid.example' } })
    worker.send(start(preview.body.token))
    assert.equal((await worker.next()).type, 'ready')
    await worker.closed
    assert.equal(calls.length, 1)
    assert.equal(calls[0].query.key, 'fake-secret')
  })
})

test('worker refuses ambient SecretRefs in a host profile', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ hostProfile, launchWorker, calls }) => {
    await writeFile(hostProfile, JSON.stringify({ version: 1, defaultProfile: 'artium', profiles: { artium: { auth: 'api-key', apiKey: { env: 'SHODAN_AXI_API_KEY' } } } }))
    const worker = launchWorker({ overrides: { SHODAN_AXI_API_KEY: 'developer-secret' } })
    worker.send(start('00000000-0000-4000-8000-000000000001'))
    assert.equal((await worker.next()).error, 'ADMISSION_REQUIRED')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})

test('hosted banner output closes its schema and redacts credential patterns', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ runHosted: run, launchWorker, setMode }) => {
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
  await withInvestigation(async ({ runHosted: run, launchWorker, setMode }) => {
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
  await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
    setMode('stream-wait')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token))
    assert.equal((await worker.next()).type, 'ready')
    assert.equal((await worker.next()).type, 'event')
    const deadlineMs = Date.now() + 6000
    worker.send({ version: 1, type: 'extend', requestId: 'extend-1', admission, deadlineMs })
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
  await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
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
  await withInvestigation(async ({ runHosted: run, launchWorker, calls, setMode }) => {
    setMode('stream-json')
    const preview = await run(args)
    const worker = launchWorker(); worker.send(start(preview.body.token)); worker.send({ version: 1, type: 'stop', requestId: 'stop-early' })
    const closed = await worker.next()
    assert.equal(closed.type, 'closed'); assert.equal(closed.stopReason, 'cancelled')
    assert.equal(await worker.closed, 0)
    assert.equal(calls.length, 0)
  })
})
