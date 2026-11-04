import assert from 'node:assert/strict'
import { mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gunzipSync } from 'node:zlib'
import { withInvestigation } from './investigation-fixture.mjs'

const selections = [
  [['stream'], 'OP-046', '/shodan/banners'],
  [['stream', '--asn', '64500,64501'], 'OP-047', '/shodan/asn/64500,64501'],
  [['stream', '--countries', 'CA,US'], 'OP-048', '/shodan/countries/CA,US'],
  [['stream', '--ports', '443,8443'], 'OP-049', '/shodan/ports/443,8443'],
  [['stream', '--vulns', 'CVE-2020-0001'], 'OP-050', '/shodan/vulns/CVE-2020-0001'],
  [['stream', '--custom-filters', 'port:443'], 'OP-051', '/shodan/custom'],
  [['stream', '--alert', 'all'], 'OP-052', '/shodan/alert'],
  [['stream', '--alert', 'alert-a'], 'OP-053', '/shodan/alert/alert-a'],
  [['stream', '--tags', 'self-signed'], 'OP-065', '/shodan/tags/self-signed'],
  [['threatnet', 'events'], 'OP-067', '/threatnet/events'],
  [['threatnet', 'backscatter'], 'OP-068', '/threatnet/backscatter'],
  [['threatnet', 'ssh'], 'OP-069', '/threatnet/ssh'],
]
const options = operation => ['--allow-operation', operation, '--accept-unknown-cost', '--limit', '2', '--max-bytes', '10000', '--timeout', '5000', '--idle-timeout', '3000']

test('each stream selector uses one confirmed connection and preserves framed events', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, calls, setMode }) => {
    setMode('stream-json')
    for (const [command, operation, path] of selections) {
      const before = calls.length
      const args = [...command, ...options(operation)]
      const preview = await run(args)
      assert.equal(preview.body.status, 'preview', preview.stdout)
      assert.equal(calls.length, before)
      const result = await run([...args, '--execute', '--confirm', preview.body.token])
      assert.equal(result.body.stopReason, 'max-events', result.stdout)
      assert.equal(result.body.count, 2)
      assert.equal(result.body.debugDiscarded, 3)
      assert.equal(result.body.partialRecordCount, 0)
      assert.equal(calls.length, before + 1)
      assert.equal(calls.at(-1).path, path)
      assert.equal(result.body.events[0].data ?? result.body.events[0].text, 'Café')
      if (command[0] === 'threatnet') assert.equal(result.body.domainSchemaValidated, false)
    }
  })
})

test('SSE framing, incomplete records and malformed records are distinct', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    const args = ['stream', ...options('OP-046')]
    for (const [mode, expected] of [['stream-sse', 'max-events'], ['stream-partial', 'upstream-eof']]) {
      setMode(mode)
      const preview = await run(args)
      const result = await run([...args, '--execute', '--confirm', preview.body.token])
      assert.equal(result.body.stopReason, expected, result.stdout)
      assert.equal(result.body.partialRecordCount, mode === 'stream-partial' ? 1 : 0)
    }
    setMode('stream-malformed')
    const preview = await run(args)
    assert.equal((await run([...args, '--execute', '--confirm', preview.body.token])).body.error, 'INVALID_RESPONSE')
  })
})

test('read-only mode and conflicting selectors fail before credentials or requests', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const args = ['stream', ...options('OP-046')]
    const env = { SHODAN_AXI_CONFIG: join(root, 'missing'), SHODAN_AXI_READ_ONLY: 'true' }
    assert.equal((await run([...args, '--execute', '--confirm', '00000000-0000-4000-8000-000000000001'], env)).body.error, 'READ_ONLY')
    assert.equal((await run([...args, '--asn', '1', '--ports', '443'], env)).body.error, 'INVALID_INPUT')
    assert.equal(calls.length, 0)
  })
})

test('follow writes bounded gzip records and retains selected files', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('stream-json')
    const directory = join(root, 'stream-output')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', directory, '--max-file-bytes', '150', '--retain', '1', '--compresslevel', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'max-events', result.stdout)
    const files = await readdir(directory)
    assert.equal(files.length, 1)
    const compressed = await readFile(join(directory, files[0]))
    assert.equal(compressed[8], 4)
    assert.ok(compressed.length <= 150)
    const records = gunzipSync(compressed).toString().trim().split('\n').map(line => JSON.parse(line))
    assert.equal(records.at(-1).ip_str, '192.0.2.8')
  })
})

test('follow rejects a symlinked output directory before connecting', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls, setMode }) => {
    setMode('stream-json')
    const directory = join(root, 'real-directory'); const link = join(root, 'indirect')
    await mkdir(directory, { mode: 0o700 }); await symlink(directory, link, 'dir')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', link, '--max-file-bytes', '1000', '--retain', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.error, 'CONFIG_INSECURE')
    assert.equal(calls.length, 0)
  })
})

test('idle streams stop at the selected idle timeout', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    for (const mode of ['stream-idle', 'stream-no-headers']) {
      setMode(mode)
      for (const [command, operation] of [[['stream'], 'OP-046'], [['threatnet', 'events'], 'OP-067']]) {
        for (const follow of [false, true]) {
          const args = [...command, ...options(operation).map(value => value === '3000' ? '500' : value)]
          if (follow) args.push('--follow', '--datadir', join(root, `${mode}-${operation}`), '--max-file-bytes', '1000', '--retain', '1')
          const preview = await run(args)
          const result = await run([...args, '--execute', '--confirm', preview.body.token])
          assert.equal(result.code, 0, result.stdout)
          assert.equal(result.body.stopReason, 'idle-timeout', result.stdout)
          assert.equal(result.body.count, 0)
          assert.equal(result.body.bytes, mode === 'stream-idle' ? 1 : 0)
        }
      }
    }
  })
})

test('cancelling follow closes the connection after the last complete event', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('stream-wait')
    const args = ['stream', ...options('OP-046'), '--follow', '--datadir', join(root, 'follow'), '--max-file-bytes', '1000', '--retain', '1']
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token], {}, child => { child.stdout.once('data', () => { child.kill('SIGINT') }) })
    assert.equal(result.body.stopReason, 'cancelled', result.stdout)
    assert.equal(result.body.count, 1)
  })
})

test('stream byte bounds and upstream denials never fabricate events', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('stream-json')
    const args = ['stream', ...options('OP-046').map(value => value === '10000' ? '10' : value)]
    const preview = await run(args)
    const result = await run([...args, '--execute', '--confirm', preview.body.token])
    assert.equal(result.body.stopReason, 'max-bytes', result.stdout)
    assert.equal(result.body.count, 0)
    setMode('stream-denied')
    const deniedPreview = await run(args)
    assert.equal((await run([...args, '--execute', '--confirm', deniedPreview.body.token])).body.error, 'UPSTREAM_ERROR')
    assert.equal((await run([...args, '--execute', '--confirm', deniedPreview.body.token])).body.error, 'PLAN_NOT_FOUND')
  })
})

test('byte cuts preserve complete events in bounded and follow reads', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    for (const mode of ['stream-byte-cut', 'stream-sse-byte-cut']) {
      for (const follow of [false, true]) {
        setMode(mode)
        const directory = join(root, `${mode}-${follow}`)
        const args = ['stream', ...options('OP-046').map(value => value === '2' ? '10' : value === '10000' ? '500' : value)]
        if (follow) args.push('--follow', '--datadir', directory, '--max-file-bytes', '1000', '--retain', '1')
        const preview = await run(args)
        const result = await run([...args, '--execute', '--confirm', preview.body.token])
        assert.equal(result.code, 0, result.stdout)
        assert.equal(result.body.stopReason, 'max-bytes')
        assert.equal(result.body.bytes, 500)
        assert.equal(result.body.count, 2)
        assert.equal(result.body.partialRecordCount, 1)
        const events = follow ? result.stdout.trim().split('\n').slice(0, -1).map(line => JSON.parse(line).event) : result.body.events
        assert.deepEqual(events.map(event => event.ip_str), ['192.0.2.7', '192.0.2.8'])
        if (follow) {
          const files = await readdir(directory)
          const saved = gunzipSync(await readFile(join(directory, files[0]))).toString().trim().split('\n').map(line => JSON.parse(line))
          assert.deepEqual(saved, events)
        }
      }
    }
  })
})

test('invalid input preserves accepted events and loss metadata with a failing exit', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    for (const mode of ['stream-invalid-json', 'stream-invalid-schema', 'stream-invalid-utf8', 'stream-invalid-utf8-eof', 'stream-sse-invalid-json', 'stream-sse-invalid-schema', 'stream-sse-invalid-utf8', 'stream-sse-invalid-utf8-eof']) {
      for (const follow of [false, true]) {
        setMode(mode)
        const args = ['stream', ...options('OP-046')]
        if (follow) args.push('--follow', '--datadir', join(root, `${mode}-${follow}`), '--max-file-bytes', '1000', '--retain', '1')
        const preview = await run(args)
        const result = await run([...args, '--execute', '--confirm', preview.body.token])
        assert.equal(result.code, 1, result.stdout)
        assert.equal(result.body.error, 'INVALID_RESPONSE')
        assert.equal(result.body.stopReason, 'invalid-response')
        assert.equal(result.body.count, 1)
        assert.equal(result.body.debugDiscarded, 3)
        const event = follow ? JSON.parse(result.stdout.split('\n')[0]).event : result.body.events[0]
        assert.equal(event.data, 'Café')
      }
    }
  })
})

test('filesystem failures are reported as storage errors with a failing exit', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, setMode }) => {
    setMode('stream-json')
    const preload = join(root, 'storage-failure.mjs')
    await writeFile(preload, `import fs from 'node:fs/promises'; import { syncBuiltinESMExports } from 'node:module';
const fail = () => { throw Object.assign(new Error('disk failure'), { code: 'ENOSPC' }) };
for (const name of ['open', 'readdir', 'lstat', 'unlink']) {
  const original = fs[name];
  fs[name] = async function (path, ...args) {
    const selected = String(path).includes('/stream-output/');
    if (selected && (name !== 'lstat' || String(path).endsWith('.jsonl.gz')) && process.env.TEST_STORAGE_FAILURE === name) fail();
    const result = await original.call(this, path, ...args);
    if (selected && name === 'open') for (const method of ['writeFile', 'close']) {
      const originalMethod = result[method].bind(result);
      result[method] = async (...values) => { if (process.env.TEST_STORAGE_FAILURE === method) { if (method === 'close') await originalMethod(); fail() } return originalMethod(...values) };
    }
    return result;
  };
}
syncBuiltinESMExports();`)
    for (const failure of ['open', 'readdir', 'lstat', 'unlink', 'writeFile', 'close']) {
      const directory = join(root, 'stream-output', failure)
      await mkdir(directory, { recursive: true, mode: 0o700 })
      await writeFile(join(directory, 'stream-2026-01-01-00000000-0000-4000-8000-000000000001.jsonl.gz'), '')
      const args = ['stream', ...options('OP-046'), '--follow', '--datadir', directory, '--max-file-bytes', '1000', '--retain', '1']
      const preview = await run(args)
      const result = await run([...args, '--execute', '--confirm', preview.body.token], { TEST_STORAGE_FAILURE: failure, NODE_OPTIONS: `--import=${join(root, 'routing.mjs')} --import=${preload}` })
      assert.equal(result.code, 1, result.stdout)
      assert.equal(result.body.error, 'STORAGE_ERROR', result.stdout)
      assert.equal(result.body.stopReason, 'storage-error')
      assert.equal(result.body.count, failure === 'close' ? 2 : 0)
    }
  })
})
