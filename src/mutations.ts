import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { constants } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { open, rename, rm } from 'node:fs/promises'
import { isIP } from 'node:net'
import { gunzipSync } from 'node:zlib'
import { z } from 'zod'
import type { Selection } from './credentials.js'
import { ToolError } from './errors.js'
import { appendPrivate, readPrivate, readPrivateBytes, writePrivate } from './private-file.js'
import { clean } from './redact.js'
import { requestJson } from './vendor.js'
import { windowsAcl } from './windows-acl.js'

type Flags = Map<string, string | boolean>
type Step = { operation: string; method: 'POST' | 'PUT' | 'DELETE'; path: string; body?: string; contentType?: string; target: string; readback: string; assign?: string }
type Draft = { command: string; steps: Step[]; preconditions: string[]; context?: { dnsMore: boolean; futureDnsTracking: false } }
const allowed = ['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm', '--body-file', '--expires', '--vulns', '--triggers']
const value = (flags: Flags, name: string): string | undefined => { const entry = flags.get(name); return typeof entry === 'string' ? entry : undefined }
const digest = (input: string): string => createHash('sha256').update(input).digest('hex')
const bad = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run the command with --help for valid inputs') }
const id = (text: string | undefined): string => text && /^[A-Za-z0-9_-]{1,128}$/.test(text) ? text : bad('Invalid resource identifier')
const component = (text: string | undefined): string => {
  const match = text?.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/)
  if (!match || !isIP(match[1] ?? match[2] ?? '') || Number(match[3]) < 1 || Number(match[3]) > 65535) return bad('Invalid service address')
  return text ?? bad('Invalid service address')
}
const targets = (text: string | undefined): string[] => {
  if (!text) return bad('At least one target is required')
  const result = text.split(',')
  if (!result.every(item => { const [address, prefix, extra] = item.split('/'); const family = isIP(address ?? ''); return family && extra === undefined && (prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= (family === 4 ? 32 : 128))) })) return bad('Invalid target network')
  return result
}
const record = z.record(z.string(), z.unknown())
const safeBody = z.object({ provider: z.string().min(1).optional(), description: z.string().optional(), args: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])) }).strict()

export function isMutation(words: string[]): boolean {
  return words[0] === 'alert' && ['create', 'remove', 'update', 'enable', 'disable', 'ignore', 'unignore', 'notifier', 'clear', 'domain', 'import'].includes(words[1] ?? '')
    || words[0] === 'notifier' && ['create', 'remove', 'update'].includes(words[1] ?? '')
}

export function validateMutationFlags(flags: Flags): void {
  for (const flag of flags.keys()) if (!allowed.includes(flag)) bad(`Flag ${flag} is not available for this command`)
  if (flags.has('--execute') !== flags.has('--confirm')) bad('Execution requires an exact confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Writes are disabled', 'Use a writable environment')
}

const stateRoot = (): string => {
  const base = process.platform === 'win32' ? process.env.LOCALAPPDATA : process.env.XDG_STATE_HOME
  return join(base && isAbsolute(base) ? base : process.platform === 'win32' ? join(homedir(), 'AppData', 'Local') : join(homedir(), '.local', 'state'), 'shodan-axi')
}

async function planKey(root: string): Promise<string> {
  const path = join(root, 'plan-key')
  try {
    const existing = await readPrivate(path, true)
    if (!/^[a-f0-9]{64}$/.test(existing)) throw new ToolError('CONFIG_INSECURE', 'The plan signing key is invalid', 'Inspect protected state before retrying')
    return existing
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error
  }
  const bootstrap = join(root, 'plans', `${randomUUID()}.bootstrap`)
  await writePrivate(bootstrap, '')
  await rm(bootstrap)
  try {
    const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW), 0o600)
    try {
      if (process.platform === 'win32') windowsAcl(path, 'restrict', false)
      await file.writeFile(randomBytes(32).toString('hex'))
      await file.sync()
    } finally { await file.close() }
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error
  }
  const result = await readPrivate(path, true)
  if (!/^[a-f0-9]{64}$/.test(result)) throw new ToolError('CONFIG_INSECURE', 'The plan signing key is invalid', 'Inspect protected state before retrying')
  return result
}

async function bodyFile(flags: Flags): Promise<z.output<typeof safeBody>> {
  const path = value(flags, '--body-file')
  if (!path || !isAbsolute(path)) return bad('A private absolute --body-file is required')
  let data: unknown
  try { data = JSON.parse(await readPrivate(path, true)) } catch (error) { if (error instanceof SyntaxError) return bad('Invalid body JSON'); throw error }
  const parsed = safeBody.safeParse(data)
  if (!parsed.success || !Object.keys(parsed.data.args).length) return bad('Invalid notifier body')
  return parsed.data
}

export async function draftMutation(words: string[], flags: Flags): Promise<Draft> {
  const args = words.slice(2)
  const action = words[1]
  const alert = words[0] === 'alert'
  const item = (operation: string, method: Step['method'], path: string, target: string, readback: string, body?: string, contentType?: string): Step => ({ operation, method, path, target, readback, ...(body === undefined ? {} : { body }), ...(contentType === undefined ? {} : { contentType }) })
  let step: Step
  if (alert && action === 'create' && args.length === 2) {
    const name = args[0]
    if (!name || name.length > 200) return bad('Invalid alert name')
    const networks = targets(args[1]); const expiration = value(flags, '--expires') ?? '0'
    if (!/^\d+$/.test(expiration) || Number(expiration) > 31536000) return bad('Invalid expiration')
    step = item('OP-013', 'POST', '/shodan/alert', name, '/shodan/alert/info', JSON.stringify({ name, filters: { ip: networks }, expires: Number(expiration) }), 'application/json')
  } else if (alert && (action === 'remove' || action === 'update') && args.length === (action === 'remove' ? 1 : 2)) {
    const selected = id(args[0]); const path = `/shodan/alert/${encodeURIComponent(selected)}`
    step = action === 'remove' ? item('OP-015', 'DELETE', path, selected, `${path}/info`) : item('OP-016', 'POST', path, selected, `${path}/info`, JSON.stringify({ filters: { ip: targets(args[1]) } }), 'application/json')
  } else if (alert && (action === 'enable' || action === 'disable') && args.length === 2) {
    const selected = id(args[0]); const trigger = id(args[1]); const base = `/shodan/alert/${encodeURIComponent(selected)}`
    step = item(action === 'enable' ? 'OP-019' : 'OP-020', action === 'enable' ? 'PUT' : 'DELETE', `${base}/trigger/${encodeURIComponent(trigger)}`, `${selected}:${trigger}`, `${base}/info`)
  } else if (alert && (action === 'ignore' || action === 'unignore') && args.length === 3) {
    const selected = id(args[0]); const trigger = id(args[1]); const service = component(args[2]); const base = `/shodan/alert/${encodeURIComponent(selected)}`
    const vulns = value(flags, '--vulns')
    if (vulns && (action !== 'ignore' || !vulns.split(',').every(cve => /^CVE-\d{4}-\d{4,}$/i.test(cve)))) return bad('Invalid vulnerability selection')
    step = item(vulns ? 'OP-070' : action === 'ignore' ? 'OP-021' : 'OP-022', action === 'ignore' ? 'PUT' : 'DELETE', `${base}/trigger/${encodeURIComponent(trigger)}/ignore/${encodeURIComponent(service)}${vulns ? `/${encodeURIComponent(vulns)}` : ''}`, `${selected}:${trigger}:${service}${vulns ? `:${vulns}` : ''}`, `${base}/info`)
  } else if (alert && action === 'notifier' && args.length === 3 && ['add', 'remove'].includes(args[0] ?? '')) {
    const selected = id(args[1]); const notifier = id(args[2]); const base = `/shodan/alert/${encodeURIComponent(selected)}`
    step = item(args[0] === 'add' ? 'OP-023' : 'OP-024', args[0] === 'add' ? 'PUT' : 'DELETE', `${base}/notifier/${encodeURIComponent(notifier)}`, `${selected}:${notifier}`, `${base}/info`)
  } else if (!alert && action === 'remove' && args.length === 1) {
    const selected = id(args[0]); const path = `/notifier/${encodeURIComponent(selected)}`
    step = item('OP-028', 'DELETE', path, selected, path)
  } else if (!alert && (action === 'create' || action === 'update') && args.length === (action === 'create' ? 0 : 1)) {
    const selected = action === 'update' ? id(args[0]) : ''
    const fields = await bodyFile(flags)
    if (action === 'create' && (typeof fields.provider !== 'string' || !fields.provider)) return bad('Notifier provider is required')
    const body = new URLSearchParams(Object.entries({ ...fields.args, ...(fields.provider ? { provider: fields.provider } : {}), ...(fields.description === undefined ? {} : { description: fields.description }) }).map(([name, field]) => [name, String(field)])).toString()
    const path = selected ? `/notifier/${encodeURIComponent(selected)}` : '/notifier'
    step = item(selected ? 'OP-030' : 'OP-027', selected ? 'PUT' : 'POST', path, selected || String(fields.provider), selected ? path : '/notifier', body, 'application/x-www-form-urlencoded')
  } else return bad('Unsupported mutation or invalid arguments')
  const relevant = new Set(['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm'])
  if (step.operation === 'OP-013') relevant.add('--expires')
  if (['OP-021', 'OP-070'].includes(step.operation)) relevant.add('--vulns')
  if (['OP-027', 'OP-030'].includes(step.operation)) relevant.add('--body-file')
  for (const flag of flags.keys()) if (!relevant.has(flag)) bad(`Flag ${flag} is not available for this mutation`)
  return { command: words.slice(0, 2).join(' '), steps: [step], preconditions: [step.readback] }
}

const savedPlan = z.object({ version: z.literal(1), token: z.string().uuid(), fingerprint: z.string(), salt: z.string().uuid(), selection: z.string(), draft: z.string(), preconditions: z.array(z.string()), snapshot: z.array(z.string()).optional(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()

export async function draftClear(words: string[], flags: Flags, selection: Selection, key: string): Promise<Draft> {
  if (words.length !== 2) return bad('Clear does not accept arguments')
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm'].includes(flag)) bad(`Flag ${flag} is not available for clear`)
  if (!value(flags, '--allow-operation')?.split(',').includes('OP-015') || !flags.has('--accept-unknown-cost')) throw new ToolError('WRITE_GRANT_REQUIRED', 'Exact operation grants and unknown-cost acceptance are required', 'Grant OP-015 and accept unknown cost')
  if (!/^[1-9]\d*$/.test(value(flags, '--max-requests') ?? '') || !/^[1-9]\d*$/.test(value(flags, '--query-credit-budget') ?? '')) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Explicit spending and request bounds are required', 'Pass positive --query-credit-budget and --max-requests')
  let ids: string[]
  if (flags.has('--execute')) {
    const token = value(flags, '--confirm')
    if (!token || !z.string().uuid().safeParse(token).success) return bad('Invalid confirmation token')
    let input: unknown
    try { input = JSON.parse(await readPrivate(join(stateRoot(), 'plans', `${token}.json`), true)) } catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview'); throw error }
    const plan = savedPlan.safeParse(input)
    if (!plan.success || !plan.data.snapshot) throw new ToolError('PLAN_STALE', 'The confirmation does not contain a clear snapshot', 'Create a new preview')
    ids = plan.data.snapshot.map(item => id(item))
  } else {
    const result = z.array(z.object({ id: z.string() }).passthrough()).safeParse(await requestJson(selection.profile.origin, '/shodan/alert/info', key))
    if (!result.success) throw new ToolError('INVALID_RESPONSE', 'The service returned an invalid alert list', 'Retry later')
    ids = result.data.map(row => id(row.id))
    if (new Set(ids).size !== ids.length || ids.length > 1000) return bad('Invalid alert snapshot')
  }
  const steps: Step[] = ids.map(selected => ({ operation: 'OP-015', method: 'DELETE', path: `/shodan/alert/${encodeURIComponent(selected)}`, target: selected, readback: `/shodan/alert/${encodeURIComponent(selected)}/info` }))
  return { command: 'alert clear', steps, preconditions: steps.map(step => step.readback) }
}

export async function draftDomain(words: string[], flags: Flags, selection: Selection, key: string): Promise<Draft> {
  const domain = words[2]
  if (words.length !== 3 || !domain || domain.length > 253 || !domain.split('.').every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return bad('Invalid domain')
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm', '--triggers'].includes(flag)) bad(`Flag ${flag} is not available for domain`)
  const triggers = (value(flags, '--triggers') ?? 'malware,industrial_control_system,internet_scanner,iot,open_database,new_service,ssl_expired,vulnerable').split(',').map(item => id(item))
  const grants = value(flags, '--allow-operation')?.split(',') ?? []
  if (!['OP-040', 'OP-013', 'OP-019'].every(operation => grants.includes(operation)) || !flags.has('--accept-unknown-cost')) throw new ToolError('WRITE_GRANT_REQUIRED', 'Domain alert requires grants for DNS, alert and trigger steps', 'Grant OP-040, OP-013 and OP-019 and accept unknown cost')
  const budget = value(flags, '--query-credit-budget') ?? ''; const maximum = value(flags, '--max-requests') ?? ''
  if (!/^[1-9]\d*$/.test(budget) || Number(budget) < triggers.length + 3 || !/^[1-9]\d*$/.test(maximum) || Number(maximum) < 2) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Domain alert requires sufficient spending and request bounds', 'Increase --query-credit-budget and --max-requests')
  const dnsPath = `/dns/domain/${encodeURIComponent(domain)}?history=false`
  const result = z.object({ domain: z.string(), data: z.array(z.object({ type: z.string(), value: z.string() }).passthrough()), more: z.boolean() }).passthrough().safeParse(await requestJson(selection.profile.origin, dnsPath, key))
  if (!result.success || result.data.domain.toLowerCase() !== domain.toLowerCase()) throw new ToolError('INVALID_RESPONSE', 'The service returned an invalid DNS page', 'Retry the selected domain')
  const addresses = [...new Set(result.data.data.filter(row => row.type === 'A' && isIP(row.value) === 4).map(row => row.value))]
  if (!addresses.length) throw new ToolError('NOT_FOUND', 'No IPv4 addresses were returned for the domain', 'Choose a domain with indexed A records')
  const create: Step = { operation: 'OP-013', method: 'POST', path: '/shodan/alert', target: domain, readback: '/shodan/alert/info', body: JSON.stringify({ name: domain, filters: { ip: addresses }, expires: 0 }), contentType: 'application/json', assign: 'created' }
  const rest: Step[] = triggers.map(trigger => ({ operation: 'OP-019', method: 'PUT', path: `/shodan/alert/{created}/trigger/${encodeURIComponent(trigger)}`, target: `{created}:${trigger}`, readback: '/shodan/alert/{created}/info' }))
  return { command: 'alert domain', steps: [create, ...rest], preconditions: [dnsPath], context: { dnsMore: result.data.more, futureDnsTracking: false } }
}

export async function draftImport(words: string[], flags: Flags): Promise<Draft> {
  const path = words[2]
  if (words.length !== 3 || !path || !isAbsolute(path)) return bad('A private absolute import file is required')
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--accept-unknown-cost', '--execute', '--confirm'].includes(flag)) bad(`Flag ${flag} is not available for import`)
  const bytes = await readPrivateBytes(path, true)
  let data: string
  try { data = (bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes, { maxOutputLength: 1024 * 1024 }) : bytes).toString('utf8') } catch { return bad('Invalid or oversized compressed import') }
  let raw: unknown
  try { raw = JSON.parse(data) } catch {
    try { raw = data.trim().split('\n').map((line): unknown => JSON.parse(line)) } catch { return bad('Invalid import JSON') }
  }
  const notifier = z.object({ id: z.string(), provider: z.string().optional(), description: z.string().optional(), args: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional() }).passthrough()
  const ignored = z.union([z.string(), z.object({ ip: z.string(), port: z.number().int().min(1).max(65535) }).passthrough()])
  const schema = z.array(z.object({ name: z.string().min(1).max(200), filters: z.object({ ip: z.array(z.string()).min(1) }).passthrough(), triggers: z.record(z.string(), z.object({ ignore: z.array(ignored).optional() }).passthrough()).default({}), notifiers: z.array(notifier).default([]) }).passthrough()).max(100)
  const parsed = schema.safeParse(Array.isArray(raw) ? raw : [raw])
  if (!parsed.success) return bad('Invalid alert import')
  const steps: Step[] = []; const notifiers = new Map<string, { alias: string; definition: string }>()
  for (const alert of parsed.data) for (const entry of alert.notifiers) {
    if (entry.id === 'default') continue
    id(entry.id)
    if (!entry.provider || !entry.args || !Object.keys(entry.args).length) return bad('Imported notifier lacks provider configuration')
    const definition = digest(JSON.stringify({ provider: entry.provider, description: entry.description, args: entry.args }))
    const existing = notifiers.get(entry.id)
    if (existing) { if (existing.definition !== definition) return bad('Conflicting imported notifier definitions'); continue }
    const alias = `notifier-${notifiers.size}`; notifiers.set(entry.id, { alias, definition })
    const body = new URLSearchParams(Object.entries({ ...entry.args, provider: entry.provider, ...(entry.description === undefined ? {} : { description: entry.description }) }).map(([name, field]) => [name, String(field)])).toString()
    steps.push({ operation: 'OP-027', method: 'POST', path: '/notifier', target: entry.provider, readback: '/notifier', body, contentType: 'application/x-www-form-urlencoded', assign: alias })
  }
  for (const [index, alert] of parsed.data.entries()) {
    for (const network of alert.filters.ip) targets(network)
    const alias = `alert-${index}`
    steps.push({ operation: 'OP-013', method: 'POST', path: '/shodan/alert', target: alert.name, readback: '/shodan/alert/info', body: JSON.stringify({ name: alert.name, filters: { ip: alert.filters.ip }, expires: 0 }), contentType: 'application/json', assign: alias })
    for (const [name, trigger] of Object.entries(alert.triggers)) {
      id(name)
      const base = `/shodan/alert/{${alias}}`
      steps.push({ operation: 'OP-019', method: 'PUT', path: `${base}/trigger/${encodeURIComponent(name)}`, target: `{${alias}}:${name}`, readback: `${base}/info` })
      for (const entry of trigger.ignore ?? []) {
        const service = component(typeof entry === 'string' ? entry : `${isIP(entry.ip) === 6 ? `[${entry.ip}]` : entry.ip}:${entry.port}`)
        steps.push({ operation: 'OP-021', method: 'PUT', path: `${base}/trigger/${encodeURIComponent(name)}/ignore/${encodeURIComponent(service)}`, target: `{${alias}}:${name}:${service}`, readback: `${base}/info` })
      }
    }
    for (const entry of alert.notifiers) {
      if (entry.id === 'default') continue
      const mapped = notifiers.get(entry.id)?.alias
      if (!mapped) return bad('Imported notifier mapping is missing')
      steps.push({ operation: 'OP-023', method: 'PUT', path: `/shodan/alert/{${alias}}/notifier/{${mapped}}`, target: `{${alias}}:{${mapped}}`, readback: `/shodan/alert/{${alias}}/info` })
    }
  }
  if (steps.length > 1000) return bad('Import has too many operations')
  return { command: 'alert import', steps, preconditions: ['/notifier', '/shodan/alert/info'] }
}

export async function mutate(draft: Draft, flags: Flags, selection: Selection, key: string): Promise<unknown> {
  const granted = value(flags, '--allow-operation')?.split(',') ?? []
  if (!draft.steps.every(step => granted.includes(step.operation)) || !flags.has('--accept-unknown-cost')) throw new ToolError('WRITE_GRANT_REQUIRED', 'Exact operation grants and unknown-cost acceptance are required', 'Pass --allow-operation and --accept-unknown-cost')
  const credit = value(flags, '--query-credit-budget'); const maximum = value(flags, '--max-requests')
  if (!credit || !/^[1-9]\d*$/.test(credit) || Number(credit) < draft.steps.length + (draft.command === 'alert domain' ? 2 : 0) || Number(credit) > 1000 || !maximum || !/^[1-9]\d*$/.test(maximum) || Number(maximum) > 1000 || Number(maximum) < draft.preconditions.length + Math.max(2 * draft.steps.length, draft.command === 'alert clear' ? 1 : 0) + (draft.command === 'alert domain' ? 1 : 0)) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Explicit spending and request bounds are required', 'Pass sufficient --query-credit-budget and --max-requests')
  const root = stateRoot(); const planDir = join(root, 'plans')
  const signingKey = await planKey(root)
  const selectionBinding = digest(JSON.stringify({ name: selection.name, source: selection.source, profile: selection.profile }))
  const draftBinding = digest(JSON.stringify({ draft, granted, credit, maximum }))
  const observe = async (): Promise<string[]> => Promise.all(draft.preconditions.map(async path => {
    try { return digest(JSON.stringify(await requestJson(selection.profile.origin, path, key))) }
    catch (error) { if (error instanceof ToolError && error.code === 'NOT_FOUND') return 'not-found'; throw error }
  }))
  if (!flags.has('--execute')) {
    const token = randomUUID(); const salt = randomUUID(); const preconditions = await observe()
    const unsigned = { version: 1, token, fingerprint: digest(`${salt}:${key}`), salt, selection: selectionBinding, draft: draftBinding, preconditions, ...(draft.command === 'alert clear' ? { snapshot: draft.steps.map(step => step.target) } : {}), created: Date.now() }
    const plan = { ...unsigned, mac: createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex') }
    await writePrivate(join(planDir, `${token}.json`), JSON.stringify(plan))
    return { status: 'preview', token, effects: draft.steps.map(({ operation, method, target, body }) => ({ operation, method, target, cost: 'unknown', ...(['OP-013', 'OP-016'].includes(operation) && body ? { networks: z.object({ filters: z.object({ ip: z.array(z.string()) }) }).parse(JSON.parse(body)).filters.ip } : {}) })), ...(draft.context ?? {}), queryCreditBudget: Number(credit), maxRequests: Number(maximum), help: 'Repeat the same command and grants with --execute --confirm <token>' }
  }
  const token = value(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return bad('Invalid confirmation token')
  const planPath = join(planDir, `${token}.json`)
  let saved: unknown
  try { saved = JSON.parse(await readPrivate(planPath, true)) } catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview'); throw error }
  const plan = savedPlan.safeParse(saved)
  if (!plan.success) throw new ToolError('PLAN_STALE', 'The confirmation does not match the current request', 'Create a new preview')
  const { mac, ...unsigned } = plan.data
  const expected = createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest()
  if (!timingSafeEqual(expected, Buffer.from(mac, 'hex')) || plan.data.token !== token || plan.data.fingerprint !== digest(`${plan.data.salt}:${key}`) || plan.data.selection !== selectionBinding || plan.data.draft !== draftBinding || Date.now() - plan.data.created > 900000) throw new ToolError('PLAN_STALE', 'The confirmation does not match the current request', 'Create a new preview')
  if (JSON.stringify(await observe()) !== JSON.stringify(plan.data.preconditions)) throw new ToolError('PLAN_STALE', 'The observed state changed', 'Create a new preview')
  try { await rename(planPath, join(planDir, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'The confirmation was already consumed', 'Create a new preview') }
  const log = process.env.SHODAN_AXI_WRITE_LOG ?? join(root, 'writes.log')
  if (!isAbsolute(log)) throw new ToolError('CONFIG_INVALID', 'Write journal path must be absolute', 'Set an absolute protected path')
  const results: unknown[] = []
  const created = new Map<string, string>()
  for (const original of draft.steps) {
    const resolve = (text: string, encode: boolean): string => text.replace(/\{([a-zA-Z0-9_-]+)\}/g, (_whole, name: string) => {
      const selected = created.get(name)
      if (!selected) throw new ToolError('OUTCOME_UNKNOWN', 'A prerequisite identifier is unavailable', 'Inspect completed steps before retrying')
      return encode ? encodeURIComponent(selected) : selected
    })
    const step = { ...original, path: resolve(original.path, true), target: ['OP-013', 'OP-027'].includes(original.operation) ? original.target : resolve(original.target, false), readback: resolve(original.readback, true) }
    await appendPrivate(log, `${JSON.stringify(clean({ token, operation: step.operation, target: step.target, phase: 'intent', at: Date.now() }, key))}\n`)
    try {
      const sentAt = Date.now()
      const response = await requestJson(selection.profile.origin, step.path, key, {}, 1024 * 1024, 30000, false, undefined, { method: step.method, ...(step.body === undefined ? {} : { body: step.body }), ...(step.contentType === undefined ? {} : { contentType: step.contentType }) })
      const parsed = record.safeParse(response)
      if (!parsed.success || (Object.hasOwn(parsed.data, 'success') && parsed.data.success !== true) || Object.hasOwn(parsed.data, 'error')) throw new Error('invalid acknowledgement')
      if (['OP-013', 'OP-016'].includes(step.operation)) {
        if (typeof parsed.data.id !== 'string' || (step.operation === 'OP-016' && parsed.data.id !== step.target)) throw new Error('invalid alert acknowledgement')
      } else if (parsed.data.success !== true) throw new Error('invalid acknowledgement')
      const createdId = ['OP-013', 'OP-027'].includes(step.operation) && typeof parsed.data.id === 'string' ? id(parsed.data.id) : undefined
      if (['OP-013', 'OP-027'].includes(step.operation) && !createdId) throw new Error('missing created identifier')
      if (createdId && step.assign) created.set(step.assign, createdId)
      const readbackPath = createdId ? step.operation === 'OP-013' ? `/shodan/alert/${encodeURIComponent(createdId)}/info` : `/notifier/${encodeURIComponent(createdId)}` : step.readback
      const hasReadback = ['OP-013', 'OP-016', 'OP-019', 'OP-020', 'OP-023', 'OP-024', 'OP-027', 'OP-015', 'OP-028'].includes(step.operation)
      let readback = 'unverified'
      if (hasReadback) try {
        const observed = record.safeParse(await requestJson(selection.profile.origin, readbackPath, key))
        if (observed.success) {
          if (step.operation === 'OP-013' || step.operation === 'OP-016') {
            const expected = record.safeParse(step.body ? JSON.parse(step.body) : {})
            if (expected.success && observed.data.id === (createdId ?? step.target) && JSON.stringify(observed.data.filters) === JSON.stringify(expected.data.filters)) {
              if (step.operation === 'OP-016') readback = 'verified'
              else if (observed.data.name === expected.data.name && typeof expected.data.expires === 'number') {
                const expiration = typeof observed.data.expiration === 'string' ? Date.parse(observed.data.expiration) : NaN
                if (observed.data.expiration === undefined) readback = 'acknowledged-unverified'
                else if (expected.data.expires === 0 ? observed.data.expiration === null : expiration >= sentAt + expected.data.expires * 1000 - 1000 && expiration <= Date.now() + expected.data.expires * 1000) readback = 'verified'
              }
            }
          } else if (step.operation === 'OP-019' || step.operation === 'OP-020') {
            const triggers = record.safeParse(observed.data.triggers)
            const trigger = step.target.split(':')[1] ?? ''
            if (observed.data.id === step.target.split(':')[0] && triggers.success && Object.hasOwn(triggers.data, trigger) === (step.operation === 'OP-019')) readback = 'verified'
          } else if (step.operation === 'OP-023' || step.operation === 'OP-024') {
            const notifier = step.target.split(':')[1] ?? ''
            const attached = z.array(z.union([z.string(), z.object({ id: z.string() }).passthrough()])).safeParse(observed.data.notifiers)
            if (observed.data.id === step.target.split(':')[0] && attached.success && attached.data.some(entry => (typeof entry === 'string' ? entry : entry.id) === notifier) === (step.operation === 'OP-023')) readback = 'verified'
          } else if (step.operation === 'OP-027' && observed.data.id === createdId) {
            const args = record.safeParse(observed.data.args)
            let matches = true; let complete = true
            for (const [name, expected] of new URLSearchParams(step.body)) {
              const actual = name === 'provider' || name === 'description' ? observed.data[name] : args.success ? args.data[name] : undefined
              if (actual === undefined) complete = false
              else if (!['string', 'number', 'boolean'].includes(typeof actual) || String(actual) !== expected) matches = false
            }
            if (matches) readback = complete ? 'verified' : 'acknowledged-unverified'
          }
        }
      } catch (error) { if (error instanceof ToolError && error.code === 'NOT_FOUND' && ['OP-015', 'OP-028'].includes(step.operation)) readback = 'verified-absent' }
      const status = !hasReadback || readback === 'acknowledged-unverified' ? 'acknowledged-unverified' : readback === 'unverified' ? 'failed' : 'verified'
      const outcome = { operation: step.operation, target: step.target, status, acknowledged: true, ...(createdId ? { id: createdId } : {}), readback }
      results.push(outcome)
      await appendPrivate(log, `${JSON.stringify(clean({ token, ...outcome, phase: 'result', at: Date.now() }, key))}\n`)
      if (status === 'failed') {
        const unsent = draft.steps.slice(results.length).map(next => ({ operation: next.operation, target: next.target, status: 'not-attempted' }))
        return { status: 'READBACK_UNVERIFIED', completed: results, unsent, steps: [...results, ...unsent] }
      }
    } catch {
      const outcome = { operation: step.operation, target: step.target, status: 'failed', recovery: `Read ${step.readback} before retrying` }
      await appendPrivate(log, `${JSON.stringify(clean({ token, ...outcome, phase: 'result', at: Date.now() }, key))}\n`)
      const unsent = draft.steps.slice(results.length + 1).map(next => ({ operation: next.operation, target: next.target, status: 'not-attempted' }))
      return { status: 'OUTCOME_UNKNOWN', completed: results, uncertain: outcome, unsent, steps: [...results, outcome, ...unsent] }
    }
  }
  return { status: 'completed', steps: results }
}
