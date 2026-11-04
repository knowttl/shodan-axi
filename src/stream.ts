import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { request } from 'node:https'
import type { IncomingMessage } from 'node:http'
import { isAbsolute, join } from 'node:path'
import { rename } from 'node:fs/promises'
import { z } from 'zod'
import type { Selection } from './credentials.js'
import { ToolError } from './errors.js'
import { planKey, stateRoot } from './mutations.js'
import { preparePrivateDirectory, readPrivate, writePrivate } from './private-file.js'
import { clean } from './redact.js'
import { StreamStorage } from './stream-storage.js'

type Flags = Map<string, string | boolean>
const option = (flags: Flags, name: string): string | undefined => { const item = flags.get(name); return typeof item === 'string' ? item : undefined }
const fail = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run the stream command with --help') }
const number = (flags: Flags, name: string, maximum: number): number => {
  const value = option(flags, name)
  if (!value || !/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > maximum) return fail(`${name} must be a positive bounded integer`)
  return Number(value)
}
const digest = (value: string): string => createHash('sha256').update(value).digest('hex')
const planSchema = z.object({ token: z.string().uuid(), binding: z.string(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
const banner = z.object({ ip_str: z.string(), port: z.number().int().min(0).max(65535), transport: z.string(), timestamp: z.string(), data: z.string() }).passthrough()
const record = z.record(z.string(), z.unknown())
const debug = z.object({ event: z.literal('debug'), discarded: z.number().int().nonnegative().default(0) })
const selectors = [
  { flag: '--asn', id: 'OP-047', path: 'asn', pattern: /^(?:AS)?\d+(?:,(?:AS)?\d+)*$/i },
  { flag: '--countries', id: 'OP-048', path: 'countries', pattern: /^[A-Z]{2}(?:,[A-Z]{2})*$/ },
  { flag: '--ports', id: 'OP-049', path: 'ports', pattern: /^\d+(?:,\d+)*$/ },
  { flag: '--vulns', id: 'OP-050', path: 'vulns', pattern: /^CVE-\d{4}-\d{4,}(?:,CVE-\d{4}-\d{4,})*$/i },
  { flag: '--custom-filters', id: 'OP-051', path: 'custom', pattern: /^[^\r\n]{1,2048}$/ },
  { flag: '--alert', id: 'OP-053', path: 'alert', pattern: /^[A-Za-z0-9_-]{1,128}$/ },
  { flag: '--tags', id: 'OP-065', path: 'tags', pattern: /^[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*$/ },
] as const

export type StreamDraft = { operation: string; path: string; query?: string; limit: number; maxBytes: number; timeout: number; idleTimeout: number; follow: boolean; storage?: { directory: string; maxFileBytes: number; retention: number; level: number } }

export function streamDraft(words: string[], flags: Flags): StreamDraft {
  const allowed = ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--accept-unknown-cost', '--limit', '--max-bytes', '--timeout', '--idle-timeout', '--execute', '--confirm', '--follow', '--datadir', '--max-file-bytes', '--retain', '--compresslevel', ...selectors.map(item => item.flag)]
  for (const flag of flags.keys()) if (!allowed.includes(flag)) fail(`Flag ${flag} is not available for this stream`)
  const threat = words[0] === 'threatnet'
  if (threat ? words.length !== 2 || !['events', 'backscatter', 'ssh'].includes(words[1] ?? '') : words.length !== 1 || words[0] !== 'stream') return fail('Invalid stream command')
  const selected = selectors.filter(item => flags.has(item.flag))
  if (selected.length > 1 || (threat && selected.length)) return fail('Choose exactly one compatible stream selector')
  const selector = selected[0]; const input = selector ? option(flags, selector.flag) : undefined
  if (selector && (!input || !selector.pattern.test(input))) return fail('Invalid stream selector')
  if (selector?.flag === '--ports' && input?.split(',').some(port => Number(port) < 1 || Number(port) > 65535)) return fail('Invalid port selection')
  const operation = threat ? ({ events: 'OP-067', backscatter: 'OP-068', ssh: 'OP-069' }[words[1] ?? ''] ?? '') : selector?.flag === '--alert' && input === 'all' ? 'OP-052' : selector?.id ?? 'OP-046'
  if (option(flags, '--allow-operation') !== operation) throw new ToolError('WRITE_GRANT_REQUIRED', 'An exact stream operation grant is required', `Pass --allow-operation ${operation}`)
  if (!flags.has('--accept-unknown-cost')) throw new ToolError('WRITE_GRANT_REQUIRED', 'Stream cost is unknown', 'Pass --accept-unknown-cost after reviewing the selection')
  if (flags.has('--execute') !== flags.has('--confirm')) return fail('Execution requires a confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Stream connections are disabled', 'Use a writable environment')
  const follow = flags.has('--follow'); const directory = option(flags, '--datadir')
  if (!follow && ['--datadir', '--max-file-bytes', '--retain', '--compresslevel'].some(flag => flags.has(flag))) return fail('File rotation options require --follow')
  if (follow && (!directory || !isAbsolute(directory) || directory.split(/[\\/]/).includes('..') || (!flags.has('--json') && option(flags, '--output') !== 'json'))) return fail('Follow requires JSON output and a safe absolute data directory')
  let storage: StreamDraft['storage']
  if (follow && directory) {
    const level = option(flags, '--compresslevel') ?? '6'
    if (!/^[0-9]$/.test(level)) return fail('Invalid compression level')
    storage = { directory, maxFileBytes: number(flags, '--max-file-bytes', 1024 * 1024 * 1024), retention: number(flags, '--retain', 1000), level: Number(level) }
  }
  const path = threat ? `/threatnet/${words[1]}` : !selector ? '/shodan/banners' : selector.flag === '--alert' && input === 'all' ? '/shodan/alert' : selector.flag === '--custom-filters' ? '/shodan/custom' : `/shodan/${selector.path}/${encodeURIComponent(input ?? '').replace(/%2C/gi, ',')}`
  return { operation, path, ...(selector?.flag === '--custom-filters' && input ? { query: input } : {}), limit: number(flags, '--limit', 10000), maxBytes: number(flags, '--max-bytes', 1024 * 1024), timeout: number(flags, '--timeout', 3600000), idleTimeout: number(flags, '--idle-timeout', 3600000), follow, ...(storage ? { storage } : {}) }
}

export async function stream(draft: StreamDraft, flags: Flags, selection: Selection, key: string): Promise<unknown> {
  const origin = selection.profile.streamOrigin ?? 'https://stream.shodan.io'
  const root = stateRoot(); const directory = join(root, 'plans'); const signingKey = await planKey(root)
  const binding = digest(JSON.stringify({ draft, selection, credential: digest(key), origin }))
  if (!flags.has('--execute')) {
    const unsigned = { token: randomUUID(), binding, created: Date.now() }
    await writePrivate(join(directory, `${unsigned.token}.json`), JSON.stringify({ ...unsigned, mac: createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex') }))
    return { status: 'preview', token: unsigned.token, operation: draft.operation, selector: draft.path, ...(draft.query ? { query: draft.query } : {}), limit: draft.limit, maxBytes: draft.maxBytes, timeoutMs: draft.timeout, idleTimeoutMs: draft.idleTimeout, follow: draft.follow, ...(draft.storage ? { storage: draft.storage } : {}), cost: 'unknown', help: 'Repeat with --execute --confirm <token>' }
  }
  const token = option(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return fail('Invalid confirmation token')
  const planPath = join(directory, `${token}.json`)
  let raw: unknown
  try { raw = JSON.parse(await readPrivate(planPath, true)) } catch { throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview') }
  const parsed = planSchema.safeParse(raw)
  if (!parsed.success) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  const { mac, ...unsigned } = parsed.data
  if (!timingSafeEqual(createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest(), Buffer.from(mac, 'hex')) || unsigned.token !== token || unsigned.binding !== binding || Date.now() - unsigned.created > 900000) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  if (draft.storage) await preparePrivateDirectory(draft.storage.directory)
  try { await rename(planPath, join(directory, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'Confirmation was already consumed', 'Create a new preview') }
  return readStream(draft, origin, key)
}

async function readStream(draft: StreamDraft, origin: string, key: string): Promise<unknown> {
  const url = new URL(draft.path, origin); url.searchParams.set('key', key)
  const threat = draft.operation.startsWith('OP-06') && draft.operation !== 'OP-065'
  if (!threat) { url.searchParams.set('t', 'json'); url.searchParams.set('debug', '1') }
  if (draft.query) url.searchParams.set('query', draft.query)
  let reason = 'upstream-eof'; let response: IncomingMessage | undefined; let partialRecordCount = 0
  const events: unknown[] = []; let count = 0; let debugDiscarded = 0; let bytes = 0; let pending: Buffer = Buffer.alloc(0); let sseData: string[] = []
  let failure: ToolError | undefined
  const storage = draft.storage ? new StreamStorage(draft.storage.directory, draft.storage.maxFileBytes, draft.storage.retention, draft.storage.level) : undefined
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const decode = (data: Uint8Array): string => {
    try { return decoder.decode(data) } catch { throw new ToolError('INVALID_RESPONSE', 'Invalid stream UTF-8', 'Inspect the stream response') }
  }
  const storageFailure = (): ToolError => new ToolError('STORAGE_ERROR', 'Stream storage could not be completed', 'Check the data directory, available space and file bounds')
  let idle: ReturnType<typeof setTimeout> | undefined
  const stop = (why: string): void => { reason = why; response?.destroy(); req.destroy() }
  const resetIdle = (): void => { clearTimeout(idle); idle = setTimeout(() => { stop('idle-timeout') }, draft.idleTimeout) }
  const timer = setTimeout(() => { stop('max-seconds') }, draft.timeout)
  const cancelled = (): void => { stop('cancelled') }
  process.once('SIGINT', cancelled); process.once('SIGTERM', cancelled)
  const req = request(url, { method: 'GET' })
  try {
    response = await new Promise<IncomingMessage>((resolve, reject) => { req.once('response', resolve); req.once('error', reject); req.end() })
    if (response.statusCode !== 200) throw new ToolError(response.statusCode === 429 ? 'RATE_LIMITED' : 'UPSTREAM_ERROR', `Stream request failed with HTTP ${response.statusCode ?? 0}`, 'Check access and retry later')
    const sse = String(response.headers['content-type'] ?? '').toLowerCase().startsWith('text/event-stream')
    const accept = async (text: string): Promise<void> => {
      let value: unknown
      try { value = JSON.parse(text) } catch { throw new ToolError('INVALID_RESPONSE', 'Invalid stream record', 'Inspect the stream response') }
      const debugRecord = debug.safeParse(value)
      if (debugRecord.success) { debugDiscarded += debugRecord.data.discarded; return }
      const result = (threat ? record : banner).safeParse(value)
      if (!result.success) throw new ToolError('INVALID_RESPONSE', 'Invalid stream record', 'Inspect the stream response')
      const event = clean(result.data, key)
      if (storage) {
        try { await storage.write(event) } catch { throw storageFailure() }
        process.stdout.write(`${JSON.stringify({ event })}\n`)
      }
      else events.push(event)
      count++; resetIdle()
      if (count >= draft.limit) stop('max-events')
    }
    resetIdle()
    try {
      for await (const chunk of response) {
        if (!Buffer.isBuffer(chunk)) throw new ToolError('INVALID_RESPONSE', 'Invalid stream data', 'Inspect the stream response')
        const prefix = chunk.subarray(0, draft.maxBytes - bytes)
        bytes += prefix.length
        pending = Buffer.concat([pending, prefix])
        for (;;) {
          const end = pending.indexOf(10); if (end < 0 || reason !== 'upstream-eof') break
          const line = decode(pending.subarray(0, end)).replace(/\r$/, ''); pending = pending.subarray(end + 1)
          if (sse) {
            if (!line) { if (sseData.length) { const data = sseData.join('\n'); sseData = []; await accept(data) } }
            else if (line.startsWith('data:')) sseData.push(line.slice(5).replace(/^ /, ''))
          } else if (line.trim()) await accept(line)
        }
        if (reason === 'upstream-eof' && bytes === draft.maxBytes) stop('max-bytes')
        if (reason !== 'upstream-eof') break
      }
    } catch (error) {
      if (error instanceof ToolError) throw error
      if (reason === 'upstream-eof') reason = 'upstream-error'
    }
    if (reason === 'upstream-eof') decode(pending)
  } catch (error) {
    if (error instanceof ToolError && ['INVALID_RESPONSE', 'STORAGE_ERROR'].includes(error.code)) {
      failure = error; reason = error.code === 'STORAGE_ERROR' ? 'storage-error' : 'invalid-response'
    } else if (!['cancelled', 'max-seconds', 'idle-timeout'].includes(reason)) {
      if (error instanceof ToolError) throw error
      throw new ToolError('UPSTREAM_ERROR', 'Stream request could not be completed', 'Check connectivity and retry later')
    }
  } finally {
    clearTimeout(timer); clearTimeout(idle); process.removeListener('SIGINT', cancelled); process.removeListener('SIGTERM', cancelled); response?.destroy(); req.destroy()
    try { await storage?.close() } catch { failure = storageFailure(); reason = 'storage-error' }
  }
  if (reason !== 'max-events' && (pending.toString('utf8').trim() || sseData.length)) partialRecordCount = 1
  return { operation: draft.operation, events, count, debugDiscarded, partialRecordCount, stopReason: reason, bytes, upstreamConnections: 1, ...(failure ? { error: failure.code, message: failure.message, help: failure.help } : {}), ...(threat ? { domainSchemaValidated: false, contractStatus: 'source-only-unverified' } : {}) }
}
