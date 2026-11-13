import assert from 'node:assert/strict'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { getCACertificates, setDefaultCACertificates } from 'node:tls'
import { withInvestigation } from './investigation-fixture.ts'
import { budgetRules } from '../dist/mutations.js'
import { exportDraft } from '../dist/bulk-export.js'
import { hostedWriteBudget } from '../dist/hosted-writes.js'
import type { VendorCall } from './investigation-fixture.ts'
import type { Selection } from '../dist/credentials.js'
import type { AddressInfo } from 'node:net'

const admission = 'synthetic-host-admission-binding-01'
const grant = { '--allow-operation': 'OP-015', '--accept-unknown-cost': true, '--query-credit-budget': '1', '--max-requests': '3' }
const write = (requestId: string, phase: string, words: string[], flags: Record<string, string | boolean>, confirmation?: string) => ({ version: 1, type: 'write', requestId, admission, phase, words, flags, ...(confirmation ? { confirmation } : {}) })
const writes = (calls: VendorCall[]) => calls.filter(call => call.method !== 'GET')

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
    assert.deepEqual(executed.result.steps.map((step: { status: string }) => step.status), ['verified'])
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
    ] satisfies [unknown, ...unknown[]][]) {
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

for (const words of [['download', 'port:443'], ['alert', 'download']]) {
  for (const mode of ['export-count-changed', 'export-credits-changed']) {
    test(`${words.join(' ')} rejects ${mode} after preview`, { timeout: 60000 }, async () => {
      await withInvestigation(async ({ root, launchWorker, calls, setMode }) => {
        const destination = join(root, 'export.json.gz')
        const flags = { '--allow-operation': 'OP-003', '--filename': destination, '--limit': '2', '--max-bytes': '100000', '--max-requests': '4', '--query-credit-budget': '1' }
        const worker = launchWorker()
        worker.send(write('preview', 'preview', words, flags))
        const preview = await worker.next()
        assert.equal(preview.result.status, 'preview')
        setMode(mode)
        worker.send(write('execute', 'execute', words, flags, preview.result.token))
        assert.equal((await worker.next()).result.error, 'PLAN_STALE')
        assert.equal(calls.filter(call => call.path === '/shodan/host/search').length, 0)
        await assert.rejects(stat(destination), { code: 'ENOENT' })
        worker.close(); await worker.closed
      })
    })
  }
}

test('inventory publishes the approved writes and budget ceilings', async () => {
  const { commands, hostedWrites } = JSON.parse(await readFile(new URL('../command-inventory.json', import.meta.url), 'utf8'))
  assert.deepEqual(hostedWrites.budget, { queryCredits: 1000, scanCredits: 1000000, requests: 1000 })
  assert.equal(hostedWrites.confirmation.singleUse, true)
  const approved: string[] = hostedWrites.approved.map((item: { command: string }) => item.command)
  assert.ok(approved.every(command => commands.some((item: { command: string }) => item.command === command)))
  assert.deepEqual(approved.sort(), [
    'alert clear', 'alert create', 'alert disable', 'alert domain', 'alert download', 'alert enable',
    'alert ignore', 'alert import', 'alert notifier add', 'alert notifier remove', 'alert remove',
    'alert unignore', 'alert update', 'download', 'notifier create', 'notifier remove',
    'notifier update', 'org add', 'org remove',
  ].sort())
  assert.deepEqual(hostedWrites.approved.find((item: { command: string }) => item.command === 'alert domain').operations, ['OP-040', 'OP-013', 'OP-019'])
  assert.deepEqual(Object.keys(hostedWrites.budgetRules).sort(), approved)
})

test('published budget rules match mutation and export boundaries', async () => {
  const { hostedWrites } = JSON.parse(await readFile(new URL('../command-inventory.json', import.meta.url), 'utf8'))
  for (const [command, steps, preconditions, credits, requests] of [
    ['alert remove', 1, 1, 1, 3], ['alert clear', 0, 0, 1, 1],
    ['alert clear', 2, 2, 2, 6], ['alert import', 3, 2, 3, 8], ['alert domain', 3, 1, 5, 8],
  ] satisfies [unknown, ...unknown[]][]) {
    const policy = hostedWrites.budgetRules[command]
    const actual = budgetRules({ command, steps: Array(steps).fill({}), preconditions: Array(preconditions).fill('') })
    assert.equal(actual.minimumCredit, credits)
    assert.equal(actual.minimumRequests, requests)
    assert.equal(Math.max(1, policy.creditPerStep * steps + policy.extraCredits), credits)
    assert.equal(policy.requestPerPrecondition * preconditions + Math.max(policy.requestsPerStep * steps, policy.minimumRequests) + policy.extraRequests, requests)
  }
  assert.deepEqual(hostedWrites.budgetRules['alert domain'].preflight, { creditsPerTrigger: 1, extraCredits: 3, minimumRequests: 2 })
  for (const command of ['download', 'alert download']) {
    assert.deepEqual(hostedWrites.budgetRules[command], { kind: command, resultsPerCredit: 100, searchOverheadRequests: 2, alertOverheadRequests: 2, requestsPerNetwork: 1 })
  }
  const flags = new Map(Object.entries({ '--allow-operation': 'OP-003', '--filename': '/export', '--limit': '101', '--max-bytes': '1000', '--max-requests': '4', '--query-credit-budget': '2' }))
  assert.equal(exportDraft(['download', 'port:443'], flags).budget, 2)
  flags.set('--query-credit-budget', '1')
  assert.throws(() => exportDraft(['download', 'port:443'], flags))
  flags.set('--query-credit-budget', '2'); flags.set('--max-requests', '3')
  assert.throws(() => exportDraft(['download', 'port:443'], flags))
})

test('shared bounds match real plans for each write family', { timeout: 120000 }, async () => {
  await withInvestigation(async ({ root, server, certFile, run, setMode }) => {
    const defaults = getCACertificates('default')
    setDefaultCACertificates([...defaults, await readFile(certFile, 'utf8')])
    try {
      const selection: Selection = { name: 'selected', source: 'file', profile: { auth: 'api-key', origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, apiKey: { env: 'TEST_SHODAN_KEY' } } }
      const credentials = async () => ({ selection, key: 'fake-secret' })
      const path = join(root, 'import.json')
      await writeFile(path, JSON.stringify([{ name: 'Imported', filters: { ip: ['192.0.2.0/24'] }, triggers: { new_service: {} }, notifiers: [{ id: 'old', provider: 'email', args: { to: 'a@example.test' } }] }]), { mode: 0o600 })
      for (const [words, flags, credit, requests, preflight] of [
        [['alert', 'remove', 'alert-a'], { '--allow-operation': 'OP-015', '--accept-unknown-cost': true }, 1, 3],
        [['alert', 'clear'], { '--allow-operation': 'OP-015', '--accept-unknown-cost': true }, 1, 3],
        [['alert', 'domain', 'example.test'], { '--allow-operation': 'OP-040,OP-013,OP-019', '--accept-unknown-cost': true, '--triggers': 'new_service' }, 4, 6, { minimumCredit: 4, minimumRequests: 2 }],
        [['alert', 'import', path], { '--allow-operation': 'OP-027,OP-013,OP-019,OP-023', '--accept-unknown-cost': true }, 4, 10],
        [['download', 'port:443'], { '--allow-operation': 'OP-003', '--filename': join(root, 'search'), '--limit': '2', '--max-bytes': '10000' }, 1, 3],
        [['alert', 'download'], { '--allow-operation': 'OP-003', '--filename': join(root, 'alerts'), '--limit': '2', '--max-bytes': '10000', '--query-credit-budget': '2' }, 1, 5],
      ] satisfies [string[], Record<string, string | true>, number, number, { minimumCredit: number; minimumRequests: number }?][]) {
        const bounds = await hostedWriteBudget(words, new Map(Object.entries(flags)), credentials)
        assert.deepEqual(bounds, { creditFlag: '--query-credit-budget', minimumCredit: credit, maximumCredit: 1000, minimumRequests: requests, maximumRequests: 1000, ...(preflight ? { preflight } : {}) })
        const args = [...words, ...Object.entries(flags).flatMap(([name, value]) => value === true ? [name] : [name, value])]
        if (!flags['--query-credit-budget']) args.push('--query-credit-budget', String(credit))
        args.push('--max-requests', String(requests))
        const preview = await run(args)
        assert.equal(preview.body.status, 'preview', preview.stdout)
      }
      setMode('alert-export-networks')
      for (const [words, expected] of [[['download', 'port:443'], [4, 4, 4, 4, 4]], [['alert', 'download'], [6, 5, 6, 7, 1004]]] satisfies [unknown, ...unknown[]][]) {
        for (const [index, budget] of [undefined, '1', '2', '3', '1000'].entries()) {
          const flags = { '--allow-operation': 'OP-003', '--filename': join(root, 'bounds'), '--limit': '101', '--max-bytes': '10000', ...(budget ? { '--query-credit-budget': budget } : {}), '--max-requests': '1' }
          const bounds = await hostedWriteBudget(words, new Map(Object.entries(flags)), credentials)
          assert.equal(bounds.minimumCredit, 2)
          assert.equal(bounds.minimumRequests, expected[index])
          const args = [...words, ...Object.entries(flags).flatMap(([name, value]) => [name, value])]
          assert.equal((await run(args)).body.error, 'INVALID_INPUT')
        }
      }
    } finally {
      setDefaultCACertificates(defaults)
    }
  })
})

test('domain budget calculation requires no DNS lookup or credentials', async () => {
  const credentials = () => { throw new Error('Credentials must not be requested') }
  for (const budgets of [{}, { '--query-credit-budget': '1', '--max-requests': '1' }, { '--query-credit-budget': '4', '--max-requests': '6' }]) {
    const flags = new Map(Object.entries({ '--triggers': 'new_service', ...budgets }))
    assert.deepEqual(await hostedWriteBudget(['alert', 'domain', 'example.test'], flags, credentials), { creditFlag: '--query-credit-budget', minimumCredit: 4, maximumCredit: 1000, minimumRequests: 6, maximumRequests: 1000, preflight: { minimumCredit: 4, minimumRequests: 2 } })
  }
})
