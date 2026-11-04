import { randomUUID } from 'node:crypto'
import { Socket } from 'node:net'
import { isAbsolute } from 'node:path'
import { z } from 'zod'
import { readConfig, secret, type Selection } from './credentials.js'
import { ToolError } from './errors.js'
import { banner } from './contracts.js'
import { cleanUpstream } from './redact.js'
import { stream, streamDraft, type StreamObserver } from './stream.js'

const requestId = z.string().min(1).max(128)
const admissionBinding = z.string().min(32).max(128)
const admit = z.object({ version: z.literal(1), type: z.literal('admit'), requestId, admission: admissionBinding, profilePath: z.string().refine(isAbsolute) }).strict()
const bounds = z.object({ limit: z.number().int().positive().max(10000), maxBytes: z.number().int().positive().max(1024 * 1024), timeout: z.number().int().positive().max(3600000), idleTimeout: z.number().int().positive().max(3600000) }).strict()
const selector = z.object({ flag: z.enum(['--asn', '--countries', '--ports', '--vulns', '--custom-filters', '--alert', '--tags']), value: z.string().min(1).max(2048) }).strict().nullable()
const start = z.object({ version: z.literal(1), type: z.literal('start'), requestId, admission: admissionBinding, operation: z.string().regex(/^OP-(?:04[6-9]|05[0-3]|065|06[7-9])$/), selector, bounds, confirmation: z.string().uuid() }).strict()
const extend = z.object({ version: z.literal(1), type: z.literal('extend'), requestId, admission: admissionBinding, deadlineMs: z.number().int().positive().safe() }).strict()
const stop = z.object({ version: z.literal(1), type: z.literal('stop'), requestId }).strict()
const message = z.discriminatedUnion('type', [admit, start, extend, stop])

export function main(): void {
  const socket = new Socket({ fd: 3, readable: true, writable: true })
  const seen = new Set<string>(); let pending: Buffer = Buffer.alloc(0); let started = false; let finished = false; let stopRequested = false
  let cancel: (() => void) | undefined; let renew: ((deadlineMs: number) => boolean) | undefined
  let approvedBounds: z.infer<typeof bounds> | undefined
  let admission: z.infer<typeof admit> | undefined
  let protocolError: string | undefined
  const send = async (value: unknown): Promise<void> => new Promise((resolve, reject) => {
    const text = `${JSON.stringify(value)}\n`
    if (Buffer.byteLength(text) > 2 * 1024 * 1024) { reject(new Error('frame limit')); return }
    socket.write(text, error => { if (error) reject(error); else resolve() })
  })
  const close = async (reason: string, error?: string, progress?: { count: number; bytes: number; partialRecordCount: number; debugDiscarded: number }): Promise<void> => {
    if (finished) return
    finished = true
    const failure = protocolError ?? error
    await send({ version: 1, type: 'closed', requestId: randomUUID(), count: 0, bytes: 0, partialRecordCount: 0, debugDiscarded: 0, ...progress, stopReason: protocolError ? 'protocol-error' : reason, ...(approvedBounds ? { bounds: approvedBounds } : {}), ...(failure ? { error: failure } : {}) }).catch(() => undefined)
    socket.end()
  }
  const reject = async (error = 'INVALID_INPUT'): Promise<void> => {
    if (finished || protocolError) return
    protocolError = error; stopRequested = true; cancel?.()
    if (!started) await close('protocol-error', error)
  }
  const run = async (input: z.infer<typeof start>, admitted: z.infer<typeof admit>): Promise<void> => {
    approvedBounds = input.bounds
    const flags = new Map<string, string | boolean>([['--json', true], ['--allow-operation', input.operation], ['--accept-unknown-cost', true], ['--limit', String(input.bounds.limit)], ['--max-bytes', String(input.bounds.maxBytes)], ['--timeout', String(input.bounds.timeout)], ['--idle-timeout', String(input.bounds.idleTimeout)], ['--execute', true], ['--confirm', input.confirmation]])
    if (input.selector) flags.set(input.selector.flag, input.selector.value)
    const threat: Record<string, string> = { 'OP-067': 'events', 'OP-068': 'backscatter', 'OP-069': 'ssh' }
    const family = threat[input.operation]
    const words = family ? ['threatnet', family] : ['stream']
    try {
      const draft = streamDraft(words, flags)
      if (stopRequested) { await close('cancelled'); return }
      const config = await readConfig(admitted.profilePath, true)
      const profile = config.profiles.artium
      if (config.defaultProfile !== 'artium' || Object.keys(config.profiles).length !== 1 || profile?.auth !== 'api-key' || !('env' in profile.apiKey) || !/^ARTIUM_SECRET_\d+$/.test(profile.apiKey.env)) throw new ToolError('ADMISSION_REQUIRED', 'A private host profile is required', 'Start the session through Artium')
      const selected: Selection = { name: 'artium', source: 'file', profile }
      if (stopRequested) { await close('cancelled'); return }
      const key = await secret(selected)
      if (stopRequested) { await close('cancelled'); return }
      const observer: StreamObserver = {
        ready: async () => { await send({ version: 1, type: 'ready', requestId: input.requestId }) },
        event: async event => { await send({ version: 1, type: 'event', requestId: randomUUID(), event: cleanUpstream(family ? event : banner.parse(event)) }) },
        loss: async discarded => { await send({ version: 1, type: 'loss', requestId: randomUUID(), discarded, reason: 'upstream-discarded' }) },
        control: (stopControl, extendControl) => { cancel = stopControl; renew = extendControl; if (stopRequested) cancel() },
      }
      const result = z.object({ stopReason: z.string(), count: z.number().int().nonnegative(), bytes: z.number().int().nonnegative(), partialRecordCount: z.number().int().nonnegative(), debugDiscarded: z.number().int().nonnegative(), error: z.string().optional() }).parse(await stream(draft, flags, selected, key, observer))
      await close(result.stopReason, result.error, result)
    } catch (error) { await close('worker-error', error instanceof ToolError ? error.code : 'UPSTREAM_ERROR') }
  }
  const handle = async (line: Buffer): Promise<void> => {
    if (finished || protocolError) return
    let raw: unknown
    try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)) } catch { await reject(); return }
    const parsed = message.safeParse(raw)
    if (!parsed.success || seen.has(parsed.data.requestId)) { await reject(); return }
    const input = parsed.data; seen.add(input.requestId)
    if (input.type === 'admit') {
      if (admission || started) { await reject('ADMISSION_REQUIRED'); return }
      admission = input; return
    }
    if (!admission || (input.type !== 'stop' && input.admission !== admission.admission)) { await reject('ADMISSION_REQUIRED'); return }
    if (input.type === 'start') {
      if (started) { await reject(); return }
      started = true; void run(input, admission); return
    }
    if (!started) { await reject(); return }
    if (input.type === 'stop') { stopRequested = true; cancel?.(); return }
    if (!cancel || !renew) { await reject(); return }
    if (!renew(input.deadlineMs)) { await reject(); return }
    await send({ version: 1, type: 'extended', requestId: input.requestId, deadlineMs: input.deadlineMs })
  }
  let queue = Promise.resolve()
  socket.on('data', (chunk: Buffer) => {
    if (finished || protocolError) return
    pending = Buffer.concat([pending, chunk])
    for (;;) {
      const end = pending.indexOf(10)
      if (end < 0) break
      const line = pending.subarray(0, end); pending = pending.subarray(end + 1)
      if (line.length > 2 * 1024 * 1024) { void reject(); return }
      queue = queue.then(async () => { await handle(line) }).catch(async () => { await reject() })
    }
    if (pending.length > 2 * 1024 * 1024) { void reject() }
  })
  socket.on('end', () => { stopRequested = true; cancel?.() })
  socket.on('error', () => { stopRequested = true; cancel?.(); socket.destroy() })
}
