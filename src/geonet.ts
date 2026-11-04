import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { isIP } from 'node:net'
import { isAbsolute, join } from 'node:path'
import { rename } from 'node:fs/promises'
import { z } from 'zod'
import { ToolError } from './errors.js'
import { planKey, stateRoot } from './mutations.js'
import { appendPrivate, readPrivate, writePrivate } from './private-file.js'
import { requestJson } from './vendor.js'

type Flags = Map<string, string | boolean>
const origin = 'https://geonet.shodan.io'
export const probes = [
  { id: 'OP-060', command: 'geonet ping', argument: 'ip' },
  { id: 'OP-061', command: 'geonet geoping', argument: 'ip' },
  { id: 'OP-062', command: 'geonet dns', argument: 'hostname' },
  { id: 'OP-063', command: 'geonet geodns', argument: 'hostname' },
] as const
const planSchema = z.object({ token: z.string().uuid(), binding: z.string(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
const location = z.object({ city: z.string(), country: z.string(), latlon: z.string() })
const ping = z.object({ ip: z.string(), is_alive: z.boolean(), min_rtt: z.number(), avg_rtt: z.number(), max_rtt: z.number(), rtts: z.array(z.number()), packets_sent: z.number().int(), packets_received: z.number().int(), packet_loss: z.number(), from_loc: location })
const dns = z.object({ answers: z.array(z.object({ type: z.string(), value: z.string() })), from_loc: location })
const fail = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run the command with --help for valid arguments') }
const option = (flags: Flags, name: string): string | undefined => { const value = flags.get(name); return typeof value === 'string' ? value : undefined }
const digest = (value: string): string => createHash('sha256').update(value).digest('hex')

export async function geonet(words: string[], flags: Flags): Promise<unknown> {
  const operation = probes.find(probe => probe.command === words.slice(0, 2).join(' '))
  if (!operation) return fail('Unknown geographic probe')
  const allowed = ['--json', '--output', '--help', '--allow-operation', '--max-requests', '--execute', '--confirm', ...(operation.argument === 'hostname' ? ['--type'] : [])]
  for (const flag of flags.keys()) if (!allowed.includes(flag)) fail(`Flag ${flag} is not available for this probe`)
  if (flags.has('--help')) return { command: operation.command, operation: operation.id, effect: 'active', auth: 'none', help: 'Preview with an exact --allow-operation and --max-requests; repeat with --execute --confirm <token>.' }
  const target = words[2]
  if (words.length !== 3 || !target || (operation.argument === 'ip' ? !isIP(target) : target.length > 253 || !target.split('.').every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)))) return fail('Invalid probe target')
  const type = option(flags, '--type') ?? 'A'
  if (operation.argument === 'hostname' && !/^[A-Za-z0-9-]{1,32}$/.test(type)) return fail('Invalid DNS record type')
  if (flags.has('--execute') !== flags.has('--confirm')) return fail('Execution requires an exact confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Active probes are disabled', 'Use a writable environment')
  if (option(flags, '--allow-operation') !== operation.id) throw new ToolError('WRITE_GRANT_REQUIRED', 'An exact active operation grant is required', `Pass --allow-operation ${operation.id}`)
  const maxRequests = option(flags, '--max-requests')
  if (!maxRequests || !/^[1-9]\d*$/.test(maxRequests) || Number(maxRequests) > 1000) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'An explicit request bound is required', 'Pass --max-requests with a positive limit')
  const root = stateRoot(); const directory = join(root, 'plans'); const key = await planKey(root)
  const binding = digest(JSON.stringify({ operation: operation.id, target, type: operation.argument === 'hostname' ? type : null, origin, maxRequests: Number(maxRequests) }))
  if (!flags.has('--execute')) {
    const unsigned = { token: randomUUID(), binding, created: Date.now() }
    const plan = { ...unsigned, mac: createHmac('sha256', key).update(JSON.stringify(unsigned)).digest('hex') }
    await writePrivate(join(directory, `${plan.token}.json`), JSON.stringify(plan))
    return { status: 'preview', token: plan.token, effect: 'active', operation: operation.id, target, probe: words[1], locations: 'service-selected', ...(operation.argument === 'hostname' ? { type } : {}), maxRequests: Number(maxRequests), help: 'Repeat the same request with --execute --confirm <token>' }
  }
  const token = option(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return fail('Invalid confirmation token')
  const path = join(directory, `${token}.json`)
  let rawPlan: unknown
  try { rawPlan = JSON.parse(await readPrivate(path, true)) } catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview'); if (error instanceof SyntaxError) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview'); throw error }
  const parsed = planSchema.safeParse(rawPlan)
  if (!parsed.success) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  const { mac, ...unsigned } = parsed.data
  const expected = createHmac('sha256', key).update(JSON.stringify(unsigned)).digest()
  if (!timingSafeEqual(expected, Buffer.from(mac, 'hex')) || unsigned.token !== token || unsigned.binding !== binding || Date.now() - unsigned.created > 900000) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  try { await rename(path, join(directory, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'Confirmation was already consumed', 'Create a new preview') }
  const log = process.env.SHODAN_AXI_WRITE_LOG ?? join(root, 'writes.log')
  if (!isAbsolute(log)) throw new ToolError('CONFIG_INVALID', 'Write journal path must be absolute', 'Set an absolute protected path')
  await appendPrivate(log, `${JSON.stringify({ token, operation: operation.id, target, phase: 'intent', at: Date.now() })}\n`)
  try {
    const endpoint = `/api/${words[1]}/${encodeURIComponent(target)}`
    const response = await requestJson(origin, endpoint, undefined, operation.argument === 'hostname' ? { rtype: type } : {}, 1024 * 1024, 30000)
    const schema = operation.argument === 'ip' ? ping : dns
    const multi = words[1] === 'geoping' || words[1] === 'geodns'
    const result = (multi ? z.array(schema) : schema).safeParse(response)
    if (!result.success) throw new Error('invalid probe response')
    if (operation.argument === 'ip') {
      const items = Array.isArray(result.data) ? result.data : [result.data]
      if (items.some(item => !('ip' in item) || (isIP(target) === 6 ? new URL(`http://[${item.ip}]`).hostname !== new URL(`http://[${target}]`).hostname : item.ip !== target))) throw new Error('probe target mismatch')
    }
    await appendPrivate(log, `${JSON.stringify({ token, operation: operation.id, target, status: 'completed', phase: 'result', at: Date.now() })}\n`)
    return multi ? { items: result.data, observers: Array.isArray(result.data) ? result.data.length : 0 } : result.data
  } catch (error) {
    await appendPrivate(log, `${JSON.stringify({ token, operation: operation.id, target, status: 'OUTCOME_UNKNOWN', phase: 'result', at: Date.now() })}\n`)
    return { error: 'OUTCOME_UNKNOWN', operation: operation.id, target, ...(error instanceof ToolError ? { cause: error.code } : {}), help: 'The probe may have run; review before issuing another' }
  }
}
