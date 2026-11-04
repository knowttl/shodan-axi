import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { lstat, rename } from 'node:fs/promises'
import { dirname, isAbsolute, join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { z } from 'zod'
import type { Selection } from './credentials.js'
import { ToolError } from './errors.js'
import { save } from './evidence.js'
import { draftMutation, mutate, planKey, stateRoot } from './mutations.js'
import { preparePrivateDirectory, readPrivate, writePrivate } from './private-file.js'
import { collectScanEvents } from './scan-results.js'
import { stream, streamDraft, type StreamObserver } from './stream.js'

type Flags = Map<string, string | boolean>
const get = (flags: Flags, name: string): string | undefined => { const value = flags.get(name); return typeof value === 'string' ? value : undefined }
const invalid = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Review the scan collection options') }
const number = (flags: Flags, name: string, max: number): number => {
  const value = get(flags, name)
  if (!value || !/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > max) return invalid(`${name} must be a positive bounded integer`)
  return Number(value)
}
const digest = (value: string): string => createHash('sha256').update(value).digest('hex')
const plan = z.object({ token: z.string().uuid(), binding: z.string(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
const preview = z.object({ status: z.literal('preview'), token: z.string().uuid() })
const mutation = z.object({ status: z.string(), scanId: z.string().optional(), steps: z.array(z.object({ id: z.string().optional(), status: z.string() })).optional() })
const resultSchema = z.object({ operation: z.string(), limit: z.number().int(), maxBytes: z.number().int(), timeout: z.number().int(), idleTimeout: z.number().int(), count: z.number().int(), bytes: z.number().int(), upstreamConnections: z.number().int(), stopReason: z.string(), error: z.string().optional(), message: z.string().optional(), help: z.string().optional(), debugDiscarded: z.number().int(), partialRecordCount: z.number().int() })

export async function collectScan(words: string[], flags: Flags, credentials: () => Promise<{ selection: Selection; key: string }>): Promise<unknown> {
  const allowed = ['--json', '--output', '--config', '--profile', '--allow-operation', '--accept-unknown-cost', '--scan-credit-budget', '--query-credit-budget', '--max-requests', '--force', '--wait', '--limit', '--max-bytes', '--idle-timeout', '--filename', '--quiet', '--verbose', '--execute', '--confirm']
  for (const flag of flags.keys()) if (!allowed.includes(flag)) invalid(`Flag ${flag} is not available for scan collection`)
  if (flags.has('--execute') !== flags.has('--confirm')) invalid('Execution requires a confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Writes are disabled', 'Use a writable environment')
  const wait = number(flags, '--wait', 3600); const limit = number(flags, '--limit', 10000); const maxBytes = number(flags, '--max-bytes', 1024 * 1024); const idle = number(flags, '--idle-timeout', 3600000)
  const target = words[1] === 'submit'
  if (!target && words[1] !== 'internet') invalid('Invalid scan collection command')
  if (!target && flags.has('--force')) invalid('--force is available only for targeted scans')
  if (!target && flags.has('--verbose')) invalid('--verbose is available only for targeted scans')
  if (target && flags.has('--quiet')) invalid('--quiet is available only for Internet scans')
  const grant = get(flags, '--allow-operation')?.split(',') ?? []
  const required = target ? ['OP-009', 'OP-013', 'OP-015', 'OP-053'] : ['OP-010', 'OP-049']
  if (!required.every(item => grant.includes(item)) || !flags.has('--accept-unknown-cost')) throw new ToolError('WRITE_GRANT_REQUIRED', 'Scan collection needs each exact operation grant and unknown-cost acceptance', 'Review the collection effects and grants')
  const scanCredit = number(flags, '--scan-credit-budget', 1000000); const requests = number(flags, '--max-requests', 1000)
  const queryCredit = target ? number(flags, '--query-credit-budget', 1000) : 0
  if (requests < (target ? 10 : 2) || (target && queryCredit < 8)) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Scan collection needs sufficient request and query budgets', 'Review each planned request')
  const scanFlags: Flags = new Map<string, string | boolean>([['--allow-operation', target ? 'OP-009' : 'OP-010'], ['--scan-credit-budget', String(scanCredit)], ['--max-requests', '1'], ['--accept-unknown-cost', true]])
  if (flags.has('--force')) scanFlags.set('--force', true)
  const scanDraft = await draftMutation(words, scanFlags)
  const context = scanDraft.context
  if (!context || (!('targets' in context) && !('port' in context))) return invalid('Scan scope is missing')
  if ('estimatedScanCredits' in context && scanCredit < context.estimatedScanCredits) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Scan credit budget is below the estimated cost', 'Increase the scan credit budget')
  const filename = get(flags, '--filename')
  if (filename && (!isAbsolute(filename) || filename.split(/[\\/]/).includes('..'))) invalid('Result filename must be a safe absolute path')
  const { selection, key } = await credentials()
  const root = stateRoot(); const dir = join(root, 'plans'); const signingKey = await planKey(root)
  const binding = digest(JSON.stringify({ scanDraft, wait, limit, maxBytes, idle, filename, quiet: flags.has('--quiet'), verbose: flags.has('--verbose'), grant, scanCredit, queryCredit, requests, selection, credential: digest(key) }))
  if (!flags.has('--execute')) {
    const unsigned = { token: randomUUID(), binding, created: Date.now() }
    await writePrivate(join(dir, `${unsigned.token}.json`), JSON.stringify({ ...unsigned, mac: createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex') }))
    return { status: 'preview', token: unsigned.token, effects: required, ...(target ? { temporaryAlert: { targets: 'targets' in context ? context.targets : [], cleanup: 'delete once' } } : {}), context, waitSeconds: wait, limit, maxBytes, idleTimeoutMs: idle, scanCreditBudget: scanCredit, queryCreditBudget: queryCredit, maxRequests: requests, ...(filename ? { filename } : {}), cost: 'unknown', help: 'Repeat with the same options and --execute --confirm <token>' }
  }
  const token = get(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return invalid('Invalid confirmation token')
  const path = join(dir, `${token}.json`)
  let parsed: ReturnType<typeof plan.safeParse>
  try { parsed = plan.safeParse(JSON.parse(await readPrivate(path, true))) } catch { throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview') }
  if (!parsed.success) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  const { mac, ...unsigned } = parsed.data
  if (!timingSafeEqual(createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest(), Buffer.from(mac, 'hex')) || unsigned.token !== token || unsigned.binding !== binding || Date.now() - unsigned.created > 900000) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  if (filename) {
    await preparePrivateDirectory(dirname(filename))
    try { await lstat(filename); throw new ToolError('DESTINATION_EXISTS', 'Output already exists', 'Choose another destination') } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
  }
  try { await rename(path, join(dir, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'Confirmation was already consumed', 'Create a new preview') }
  const executeMutation = async (draft: Awaited<ReturnType<typeof draftMutation>>, options: Flags): Promise<z.infer<typeof mutation>> => {
    const first = preview.parse(await mutate(draft, options, selection, key))
    return mutation.parse(await mutate(draft, new Map([...options, ['--execute', true], ['--confirm', first.token]]), selection, key))
  }
  const alertFlags: Flags = new Map<string, string | boolean>([['--allow-operation', 'OP-013'], ['--accept-unknown-cost', true], ['--query-credit-budget', '1'], ['--max-requests', '3']])
  let alertId: string | undefined; let cleanup = target ? 'not-created' : 'not-required'; let scan: z.infer<typeof mutation> | undefined; let failure: string | undefined
  const alertName = `scan-${token}`
  const events: unknown[] = []; let streamResult: z.infer<typeof resultSchema> | undefined
  try {
    if (target && 'targets' in context) {
      const alertDraft = await draftMutation(['alert', 'create', alertName, context.targets.join(',')], alertFlags)
      cleanup = 'unknown'
      const created = await executeMutation(alertDraft, alertFlags)
      alertId = created.steps?.[0]?.id
      if (!alertId || created.status !== 'completed') throw new Error('alert creation could not be verified')
    }
    const streamFlags: Flags = new Map<string, string | boolean>([['--json', true], ['--allow-operation', target ? 'OP-053' : 'OP-049'], ['--accept-unknown-cost', true], ['--limit', String(limit)], ['--max-bytes', String(maxBytes)], ['--timeout', String(wait * 1000)], ['--idle-timeout', String(idle)], [target ? '--alert' : '--ports', target ? alertId ?? '' : String('port' in context ? context.port : '')]])
    const streamPlan = streamDraft(['stream'], streamFlags)
    const streamPreview = preview.parse(await stream(streamPlan, streamFlags, selection, key))
    let stop: (() => void) | undefined
    const observer: StreamObserver = {
      control: cancel => { stop = cancel }, loss: () => Promise.resolve(), event: event => { events.push(event); return Promise.resolve() },
      ready: async () => { scan = await executeMutation(scanDraft, scanFlags); if (scan.status !== 'submitted') { failure = scan.status; stop?.() } },
    }
    streamResult = resultSchema.parse(await stream(streamPlan, new Map([...streamFlags, ['--execute', true], ['--confirm', streamPreview.token]]), selection, key, observer))
    if (streamResult.error) failure = streamResult.error
  } catch { failure = 'OUTCOME_UNKNOWN' }
  finally {
    if (alertId) {
      try {
        const deleteFlags: Flags = new Map<string, string | boolean>([['--allow-operation', 'OP-015'], ['--accept-unknown-cost', true], ['--query-credit-budget', '1'], ['--max-requests', '3']])
        const deleted = await executeMutation(await draftMutation(['alert', 'remove', alertId], deleteFlags), deleteFlags)
        cleanup = deleted.status === 'completed' ? 'completed' : 'failed'
      } catch { cleanup = 'failed' }
    }
  }
  if (!scan && !failure) failure = 'STREAM_NOT_READY'
  const scope = 'targets' in context ? { kind: 'targets' as const, networks: context.targets } : { kind: 'port' as const, port: context.port }
  const collected = collectScanEvents(scope, events)
  let saved
  if (filename) {
    try { saved = await save(filename, gzipSync(Buffer.from(collected.events.map(event => `${JSON.stringify(event)}\n`).join('')))) } catch { failure = 'STORAGE_ERROR' }
  }
  return { status: failure || cleanup === 'failed' ? 'partial' : 'completed', ...(failure ? { error: failure } : {}), ...(scan?.scanId ? { scanId: scan.scanId } : {}), vendorCompletion: 'unknown', vendorCancellation: 'not-requested', ...collected, ...(flags.has('--quiet') ? { events: [] } : {}), ...(flags.has('--verbose') ? { display: collected.events.map(event => JSON.stringify(event)).join('\n') } : {}), ...(streamResult ? { stream: streamResult } : {}), cleanup, ...(cleanup === 'unknown' ? { reconciliation: { alertName, help: 'Run alert list, locate this exact name and inspect its targets; preview and confirm alert remove <id> for any matching temporary alert before retrying' } } : {}), ...(cleanup === 'failed' && alertId ? { cleanupAlertId: alertId } : {}), ...(saved ? { saved } : {}), attribution: 'Matching stream records are not proof of scan ownership' }
}
