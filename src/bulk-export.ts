import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { lstat, link, open, rename, unlink } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { Readable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { createGzip } from 'node:zlib'
import { z } from 'zod'
import { ToolError } from './errors.js'
import { planKey, stateRoot } from './mutations.js'
import { preparePrivateDirectory, readPrivate, writePrivate } from './private-file.js'
import { clean } from './redact.js'
import { requestJson } from './vendor.js'
import type { Selection } from './credentials.js'
import { union } from './alert-evidence.js'
import { windowsAcl } from './windows-acl.js'

type Flags = Map<string, string | boolean>
const value = (flags: Flags, name: string): string | undefined => { const v = flags.get(name); return typeof v === 'string' ? v : undefined }
const invalid = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run download --help') }
const number = (flags: Flags, name: string, max: number): number => {
  const v = value(flags, name)
  if (!v || !/^[1-9]\d*$/.test(v) || !Number.isSafeInteger(Number(v)) || Number(v) > max) return invalid(`${name} must be a positive bounded integer`)
  return Number(v)
}
const hash = (text: string): string => createHash('sha256').update(text).digest('hex')
const record = z.record(z.string(), z.unknown())
const page = z.object({ total: z.number().int().nonnegative(), matches: z.array(record) })
const savedPlan = z.object({ token: z.string().uuid(), binding: z.string(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()

export type ExportDraft = { query: string; queries?: string[]; destination: string; limit: number; maxBytes: number; maxRequests: number; budget: number; fields: string[] }

export function exportDraft(words: string[], flags: Flags): ExportDraft {
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--query-credit-budget', '--max-requests', '--max-bytes', '--limit', '--filename', '--fields', '--execute', '--confirm'].includes(flag)) invalid(`Flag ${flag} is not available for download`)
  const query = words.slice(1).join(' ').trim()
  if (!query || query.length > 4096) invalid('A search query is required')
  if (value(flags, '--allow-operation') !== 'OP-003') throw new ToolError('WRITE_GRANT_REQUIRED', 'Search export requires an exact operation grant', 'Pass --allow-operation OP-003')
  if (flags.has('--execute') !== flags.has('--confirm')) invalid('Execution requires a confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Search exports are disabled', 'Use a writable environment')
  const filename = value(flags, '--filename')
  if (!filename || filename.split(/[\\/]/).includes('..')) return invalid('A safe destination is required')
  const destination = resolve(filename.endsWith('.json.gz') ? filename : `${filename}.json.gz`)
  const fields = (value(flags, '--fields') ?? '').split(',').filter(Boolean)
  if (!fields.every(field => /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/.test(field))) invalid('Invalid field selection')
  const limit = number(flags, '--limit', 1000000); const maxBytes = number(flags, '--max-bytes', 1024 * 1024 * 1024)
  const maxRequests = number(flags, '--max-requests', 1000); const budget = number(flags, '--query-credit-budget', 1000)
  if (maxRequests < 3 || Math.ceil(limit / 100) > budget || Math.ceil(limit / 100) + 2 > maxRequests) invalid('Request and credit bounds must cover the selected limit')
  return { query, destination, limit, maxBytes, maxRequests, budget, fields }
}

export async function alertExportDraft(words: string[], flags: Flags, selection: Selection, key: string): Promise<ExportDraft> {
  if (words.length !== 2) return invalid('Invalid alert download arguments')
  const id = value(flags, '--alert-id')
  if (id && !/^[A-Za-z0-9_-]{1,128}$/.test(id)) return invalid('Invalid alert ID')
  const ordinaryFlags = new Map(flags); ordinaryFlags.delete('--alert-id')
  const draft = exportDraft(['download', 'selected-alert-networks'], ordinaryFlags)
  const alerts = z.array(z.object({ id: z.string(), filters: z.object({ ip: z.array(z.string()) }) })).safeParse(await requestJson(selection.profile.origin, '/shodan/alert/info', key))
  if (!alerts.success) throw new ToolError('INVALID_RESPONSE', 'Invalid alert list', 'Inspect the service response')
  const selected = id ? alerts.data.filter(alert => alert.id === id) : alerts.data
  if (id && !selected.length) throw new ToolError('NOT_FOUND', 'Alert was not found', 'Inspect alert list')
  const queries = union(selected.flatMap(alert => alert.filters.ip)).map(network => `net:${network}`)
  if (!queries.length) throw new ToolError('NOT_FOUND', 'No monitored networks are available', 'Inspect alert list')
  if (draft.maxRequests < draft.budget + queries.length + 2) return invalid('Request bound must cover alert selection, counts, account and search requests')
  return { ...draft, query: queries.join(' '), queries }
}

export async function exportSearch(draft: ExportDraft, flags: Flags, selection: Selection, key: string): Promise<unknown> {
  const root = stateRoot(); const directory = join(root, 'plans'); const signingKey = await planKey(root)
  const binding = hash(JSON.stringify({ draft, selection, credential: hash(key) }))
  if (!flags.has('--execute')) {
    let total = 0
    for (const query of draft.queries ?? [draft.query]) {
      const count = z.object({ total: z.number().int().nonnegative() }).safeParse(await requestJson(selection.profile.origin, '/shodan/host/count', key, { query }))
      if (!count.success) throw new ToolError('INVALID_RESPONSE', 'Invalid count response', 'Inspect the service response')
      total += count.data.total
    }
    const info = z.object({ query_credits: z.number().nonnegative() }).safeParse(await requestJson(selection.profile.origin, '/api-info', key))
    if (!info.success) throw new ToolError('INVALID_RESPONSE', 'Invalid account information', 'Inspect the service response')
    const unsigned = { token: randomUUID(), binding, created: Date.now() }
    const mac = createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex')
    await writePrivate(join(directory, `${unsigned.token}.json`), JSON.stringify({ ...unsigned, mac }))
    return { status: 'preview', token: unsigned.token, operation: 'OP-003', query: draft.query, total, queryCredits: info.data.query_credits, queryCreditBudget: draft.budget, maxRequests: draft.maxRequests, maxBytes: draft.maxBytes, limit: draft.limit, destination: draft.destination, help: 'Repeat with --execute --confirm <token>' }
  }
  const token = value(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return invalid('Invalid confirmation token')
  const planPath = join(directory, `${token}.json`)
  let saved: unknown
  try { saved = JSON.parse(await readPrivate(planPath, true)) } catch { throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview') }
  const plan = savedPlan.safeParse(saved)
  if (!plan.success) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  const { mac, ...unsigned } = plan.data
  const expected = createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest()
  if (!timingSafeEqual(expected, Buffer.from(mac, 'hex')) || unsigned.token !== token || unsigned.binding !== binding || Date.now() - unsigned.created > 900000) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  try { await rename(planPath, join(directory, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'Confirmation was already consumed', 'Create a new preview') }
  const partial = `${draft.destination}.partial`
  await preparePrivateDirectory(dirname(draft.destination))
  for (const path of [draft.destination, partial]) try { await lstat(path); throw new ToolError('DESTINATION_EXISTS', 'Output already exists', 'Choose another destination') } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
  let count = 0; let size = 0; let total = 0; let requests = 0; let finishedQueries = 0; let countedQueries = 0
  async function* rows(): AsyncGenerator<string> {
    for (const query of draft.queries ?? [draft.query]) {
    for (let pageNumber = 1; count < draft.limit && requests < draft.maxRequests - 2 && requests < draft.budget; pageNumber++) {
      requests++
      const response = page.safeParse(await requestJson(selection.profile.origin, '/shodan/host/search', key, { query, page: String(pageNumber), minify: 'false' }))
      if (!response.success) throw new ToolError('INVALID_RESPONSE', 'Invalid search response', 'Inspect the service response')
      if (pageNumber === 1) { total += response.data.total; countedQueries++ }
      if (!response.data.matches.length) { finishedQueries++; break }
      for (const row of response.data.matches) {
        if (count >= draft.limit) break
        const selected = draft.fields.length ? Object.fromEntries(draft.fields.map(field => [field, field.split('.').reduce<unknown>((item, part) => { const parsed = record.safeParse(item); return parsed.success ? parsed.data[part] : undefined }, row) ?? null])) : row
        const line = `${JSON.stringify(clean(selected, key))}\n`
        size += Buffer.byteLength(line)
        if (size > draft.maxBytes) throw new ToolError('LIMIT_REACHED', 'Export exceeds the byte limit', 'Increase the bound or narrow the selection')
        count++; yield line
      }
      if (pageNumber * 100 >= response.data.total) { finishedQueries++; break }
    }
    }
  }
  const file = await open(partial, 'wx', 0o600)
  try {
    if (process.platform === 'win32') windowsAcl(partial, 'restrict', false)
    await pipeline(Readable.from(rows()), createGzip(), file.createWriteStream())
  } finally { await file.close().catch(() => undefined) }
  let savedBytes = 0; const savedHash = createHash('sha256')
  for await (const chunk of createReadStream(partial)) { if (!Buffer.isBuffer(chunk)) throw new Error('Invalid file chunk'); savedBytes += chunk.length; savedHash.update(chunk) }
  if (savedBytes > draft.maxBytes) throw new ToolError('LIMIT_REACHED', 'Compressed export exceeds the byte limit', 'Increase the bound or narrow the selection')
  const complete = finishedQueries === (draft.queries?.length ?? 1) && count >= total
  if (complete) { await link(partial, draft.destination); await unlink(partial) }
  return { path: complete ? draft.destination : partial, count, total: countedQueries === (draft.queries?.length ?? 1) ? total : null, requests, complete, bytes: savedBytes, sha256: savedHash.digest('hex'), uncompressedBytes: size }
}
