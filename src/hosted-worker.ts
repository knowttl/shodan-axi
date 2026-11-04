import { randomUUID } from 'node:crypto'
import { Socket } from 'node:net'
import { z } from 'zod'
import { configPath, secret, select } from './credentials.js'
import { ToolError } from './errors.js'
import { banner } from './contracts.js'
import { cleanUpstream } from './redact.js'
import { stream, streamDraft, type StreamObserver } from './stream.js'

const requestId = z.string().min(1).max(128)
const bounds = z.object({ limit: z.number().int().positive().max(10000), maxBytes: z.number().int().positive().max(1024 * 1024), timeout: z.number().int().positive().max(3600000), idleTimeout: z.number().int().positive().max(3600000) }).strict()
const selector = z.object({ flag: z.enum(['--asn', '--countries', '--ports', '--vulns', '--custom-filters', '--alert', '--tags']), value: z.string().min(1).max(2048) }).strict().nullable()
const start = z.object({ version: z.literal(1), type: z.literal('start'), requestId, operation: z.string().regex(/^OP-(?:04[6-9]|05[0-3]|065|06[7-9])$/), selector, bounds, confirmation: z.string().uuid() }).strict()
const extend = z.object({ version: z.literal(1), type: z.literal('extend'), requestId, deadlineMs: z.number().int().positive().safe() }).strict()
const stop = z.object({ version: z.literal(1), type: z.literal('stop'), requestId }).strict()
const message = z.discriminatedUnion('type', [start, extend, stop])

export function main(): void {
  const socket = new Socket({ fd: 3, readable: true, writable: true })
  const seen = new Set<string>(); let pending: Buffer = Buffer.alloc(0); let started = false; let finished = false; let stopRequested = false
  let cancel: (() => void) | undefined; let renew: ((deadlineMs: number) => boolean) | undefined
  let approvedBounds: z.infer<typeof bounds> | undefined
  const send = async (value: unknown): Promise<void> => new Promise((resolve, reject) => {
    const text = `${JSON.stringify(value)}\n`
    if (Buffer.byteLength(text) > 2 * 1024 * 1024) { reject(new Error('frame limit')); return }
    socket.write(text, error => { if (error) reject(error); else resolve() })
  })
  const close = async (reason: string, error?: string): Promise<void> => {
    if (finished) return
    finished = true
    if (approvedBounds) await send({ version: 1, type: 'closed', requestId: randomUUID(), stopReason: reason, count: 0, bytes: 0, partialRecordCount: 0, debugDiscarded: 0, bounds: approvedBounds, ...(error ? { error } : {}) }).catch(() => undefined)
    socket.end()
  }
  const run = async (input: z.infer<typeof start>): Promise<void> => {
    approvedBounds = input.bounds
    const flags = new Map<string, string | boolean>([['--json', true], ['--allow-operation', input.operation], ['--accept-unknown-cost', true], ['--limit', String(input.bounds.limit)], ['--max-bytes', String(input.bounds.maxBytes)], ['--timeout', String(input.bounds.timeout)], ['--idle-timeout', String(input.bounds.idleTimeout)], ['--execute', true], ['--confirm', input.confirmation]])
    if (input.selector) flags.set(input.selector.flag, input.selector.value)
    const threat: Record<string, string> = { 'OP-067': 'events', 'OP-068': 'backscatter', 'OP-069': 'ssh' }
    const family = threat[input.operation]
    const words = family ? ['threatnet', family] : ['stream']
    try {
      const draft = streamDraft(words, flags)
      if (finished || stopRequested) { await close('cancelled'); return }
      const selected = await select(configPath())
      if (finished || stopRequested) { await close('cancelled'); return }
      const key = await secret(selected)
      if (finished || stopRequested) { await close('cancelled'); return }
      const observer: StreamObserver = {
        ready: async () => { await send({ version: 1, type: 'ready', requestId: input.requestId }) },
        event: async event => { await send({ version: 1, type: 'event', requestId: randomUUID(), event: cleanUpstream(family ? event : banner.parse(event)) }) },
        loss: async discarded => { await send({ version: 1, type: 'loss', requestId: randomUUID(), discarded, reason: 'upstream-discarded' }) },
        control: (stopControl, extendControl) => { cancel = stopControl; renew = extendControl; if (stopRequested) cancel() },
      }
      const result = z.object({ stopReason: z.string(), count: z.number().int().nonnegative(), bytes: z.number().int().nonnegative(), partialRecordCount: z.number().int().nonnegative(), debugDiscarded: z.number().int().nonnegative(), error: z.string().optional() }).parse(await stream(draft, flags, selected, key, observer))
      if (!finished) {
        finished = true
        await send({ version: 1, type: 'closed', requestId: randomUUID(), ...result, bounds: input.bounds })
        socket.end()
      }
    } catch (error) { await close('worker-error', error instanceof ToolError ? error.code : 'UPSTREAM_ERROR') }
  }
  const handle = async (line: Buffer): Promise<void> => {
    let raw: unknown
    try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)) } catch { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT'); return }
    const parsed = message.safeParse(raw)
    if (!parsed.success || seen.has(parsed.data.requestId)) { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT'); return }
    const input = parsed.data; seen.add(input.requestId)
    if (input.type === 'start') {
      if (started) { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT'); return }
      started = true; void run(input); return
    }
    if (!started || finished) { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT'); return }
    if (input.type === 'stop') { stopRequested = true; cancel?.(); return }
    if (!cancel || !renew) { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT'); return }
    if (!renew(input.deadlineMs)) { stopRequested = true; cancel(); await close('protocol-error', 'INVALID_INPUT'); return }
    await send({ version: 1, type: 'extended', requestId: input.requestId, deadlineMs: input.deadlineMs })
  }
  let queue = Promise.resolve()
  socket.on('data', (chunk: Buffer) => {
    pending = Buffer.concat([pending, chunk])
    for (;;) {
      const end = pending.indexOf(10)
      if (end < 0) break
      const line = pending.subarray(0, end); pending = pending.subarray(end + 1)
      if (line.length > 2 * 1024 * 1024) { stopRequested = true; cancel?.(); void close('protocol-error', 'INVALID_INPUT'); return }
      queue = queue.then(async () => { await handle(line) }).catch(async () => { stopRequested = true; cancel?.(); await close('protocol-error', 'INVALID_INPUT') })
    }
    if (pending.length > 2 * 1024 * 1024) { stopRequested = true; cancel?.(); void close('protocol-error', 'INVALID_INPUT') }
  })
  socket.on('end', () => { stopRequested = true; cancel?.() })
  socket.on('error', () => { stopRequested = true; cancel?.(); socket.destroy() })
}
