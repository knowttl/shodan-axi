import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import https from 'node:https'
import { syncBuiltinESMExports } from 'node:module'
import { join } from 'node:path'
import { test } from 'node:test'
import { transfer, transferDraft } from '../dist/bulk-transfer.js'
import { createTestTls } from './tls-fixture.mjs'

async function fixture(t) {
  const root = await mkdtemp(join(process.cwd(), '.transfer-'))
  const previousState = { XDG_STATE_HOME: process.env.XDG_STATE_HOME, LOCALAPPDATA: process.env.LOCALAPPDATA }
  let server
  t.after(async () => {
    t.mock.restoreAll()
    syncBuiltinESMExports()
    for (const [name, value] of Object.entries(previousState)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
    if (server) await new Promise(resolve => server.close(resolve))
    await rm(root, { recursive: true, force: true })
  })
  process.env.XDG_STATE_HOME = root
  process.env.LOCALAPPDATA = root
  const { keyFile, certFile } = await createTestTls(root, 'IP:127.0.0.1')
  const bytes = Buffer.alloc(1024 * 1024 + 10, 'x')
  const calls = []
  let mode = 'normal'; let location
  server = https.createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, (request, response) => {
    const url = new URL(request.url, origin)
    calls.push({ path: url.pathname, key: url.searchParams.get('key'), range: request.headers.range })
    if (url.pathname === '/shodan/data/raw-daily') {
      response.end(JSON.stringify([{ name: 'synthetic.json', size: bytes.length, sha1: mode === 'checksum' ? '0'.repeat(40) : createHash('sha1').update(bytes).digest('hex'), url: location ?? `${origin}/fixture?signature=private-signature` }]))
      return
    }
    if (mode === 'redirect') { response.writeHead(302, { location: `${origin}/private` }); response.end(); return }
    const match = /^bytes=(\d+)-(\d+)$/.exec(request.headers.range ?? '')
    if (!match) { response.writeHead(416); response.end(); return }
    const start = Number(match[1]); const end = Number(match[2])
    if (mode === 'interrupt' && start > 0) { request.socket.destroy(); return }
    response.writeHead(206, { etag: mode === 'version-change' ? '"v2"' : '"v1"', 'content-range': `bytes ${start}-${end}/${bytes.length}` })
    response.end(mode === 'oversized' ? Buffer.alloc(end - start + 2) : bytes.subarray(start, mode === 'short' ? end : end + 1))
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const origin = `https://127.0.0.1:${server.address().port}`
  const request = https.request
  const ca = await readFile(certFile)
  t.mock.method(https, 'request', (url, options, callback) => {
    assert.equal(url.origin, origin)
    return request(url, { ...options, ca }, callback)
  })
  syncBuiltinESMExports()
  const selection = { name: 'test', source: 'test', profile: { auth: 'api-key', origin, apiKey: { env: 'TEST_SHODAN_KEY' } } }
  const draft = transferDraft(['data', 'download', 'raw-daily', 'synthetic.json'], new Map([
    ['--filename', join(root, 'data.json')], ['--max-bytes', String(bytes.length)], ['--max-requests', '3'], ['--allow-operation', 'OP-034,OP-035,OP-071'],
  ]))
  const run = (draft, flags = new Map()) => transfer(draft, flags, selection, 'fake-secret', [origin])
  const execute = async draft => {
    const preview = await run(draft)
    return run(draft, new Map([['--execute', true], ['--confirm', preview.token]]))
  }
  return { root, draft, run, execute, calls, bytes, origin, selection, setMode: value => { mode = value }, setLocation: value => { location = value } }
}

test('internal transfer confirms bounded ranges and verifies saved bytes', async t => {
  const { draft, run, calls, bytes } = await fixture(t)
  const preview = await run(draft)
  assert.equal(preview.status, 'preview')
  assert.equal(calls.length, 1)
  const result = await run(draft, new Map([['--execute', true], ['--confirm', preview.token]]))
  assert.equal(result.complete, true)
  assert.deepEqual(await readFile(draft.destination), bytes)
  assert.equal(result.bytes, bytes.length)
  assert.equal(result.sha256, createHash('sha256').update(bytes).digest('hex'))
  assert.equal(result.sha1, createHash('sha1').update(bytes).digest('hex'))
  assert.deepEqual(calls.slice(2), [
    { path: '/fixture', key: null, range: 'bytes=0-1048575' },
    { path: '/fixture', key: null, range: 'bytes=1048576-1048585' },
  ])
  assert.doesNotMatch(JSON.stringify({ preview, result }), /private-signature/)
})

test('internal transfer defaults to the empty release policy', async t => {
  const { draft, selection, calls } = await fixture(t)
  await assert.rejects(transfer(draft, new Map(), selection, 'fake-secret'), { code: 'STORAGE_POLICY_UNAVAILABLE' })
  assert.equal(calls.length, 1)
})

for (const location of ['http://127.0.0.1/file', 'https://unreviewed.example/file', 'https://user:password@127.0.0.1/file']) {
  test(`internal transfer refuses unapproved location ${location}`, async t => {
    const { draft, run, calls, setLocation, origin } = await fixture(t)
    setLocation(location.replace('127.0.0.1', new URL(origin).host))
    await assert.rejects(run(draft), { code: 'STORAGE_POLICY_UNAVAILABLE' })
    assert.equal(calls.length, 1)
  })
}

for (const bounds of [{ maxBytes: 10 }, { maxRequests: 2 }]) {
  test(`internal transfer refuses insufficient ${Object.keys(bounds)[0]}`, async t => {
    const { draft, run, calls } = await fixture(t)
    await assert.rejects(run({ ...draft, ...bounds }), { code: 'LIMIT_REACHED' })
    assert.equal(calls.length, 1)
  })
}

for (const target of ['destination', 'partial', 'symlink']) {
  test(`internal transfer preserves existing ${target}`, async t => {
    const { root, draft, execute, calls } = await fixture(t)
    const existing = target === 'destination' ? draft.destination : `${draft.destination}.partial`
    const protectedFile = join(root, 'protected')
    await writeFile(protectedFile, 'original', { mode: 0o600 })
    if (target === 'symlink') await symlink(protectedFile, existing)
    else await writeFile(existing, 'original', { mode: 0o600 })
    await assert.rejects(execute(draft), { code: target === 'destination' ? 'DESTINATION_EXISTS' : 'EEXIST' })
    assert.equal(await readFile(existing, 'utf8'), 'original')
    assert.equal(await readFile(protectedFile, 'utf8'), 'original')
    assert.equal(calls.length, 2)
  })
}

for (const { mode, error } of [
  { mode: 'checksum', error: { code: 'INVALID_RESPONSE' } },
  { mode: 'redirect', error: { code: 'SOURCE_CHANGED' } },
  { mode: 'short', error: { code: 'UPSTREAM_ERROR' } },
  { mode: 'oversized', error: /./ },
]) {
  test(`internal transfer leaves ${mode} output incomplete`, async t => {
    const { draft, execute, calls, setMode } = await fixture(t)
    setMode(mode)
    await assert.rejects(execute(draft), error)
    await assert.rejects(readFile(draft.destination), { code: 'ENOENT' })
    assert.equal(calls.some(call => call.path === '/private'), false)
  })
}

test('resuming refuses a changed source before appending bytes', async t => {
  const { draft, execute, setMode } = await fixture(t)
  setMode('interrupt')
  await assert.rejects(execute(draft), { code: 'UPSTREAM_ERROR' })
  const before = await readFile(`${draft.destination}.partial`)
  assert.equal(before.length, 1024 * 1024)
  setMode('version-change')
  await assert.rejects(execute({ ...draft, mode: 'resume' }), { code: 'SOURCE_CHANGED' })
  assert.deepEqual(await readFile(`${draft.destination}.partial`), before)
  await assert.rejects(readFile(draft.destination), { code: 'ENOENT' })
})

test('resuming a matching source verifies the completed dataset', async t => {
  const { draft, execute, bytes, setMode } = await fixture(t)
  setMode('interrupt')
  await assert.rejects(execute(draft), { code: 'UPSTREAM_ERROR' })
  setMode('normal')
  const result = await execute({ ...draft, mode: 'resume' })
  assert.equal(result.complete, true)
  assert.deepEqual(await readFile(draft.destination), bytes)
  assert.equal(result.sha256, createHash('sha256').update(bytes).digest('hex'))
})
