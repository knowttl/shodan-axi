import { isIP } from 'node:net'
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import { z } from 'zod'
import { operations, type ReadOperation } from './catalogue.js'
import { ToolError } from './errors.js'
import { clean } from './redact.js'
import { requestJson } from './vendor.js'
import { windowsAcl } from './windows-acl.js'

export type Flags = Map<string, string | boolean>
export type Investigation = { operation: ReadOperation; argument?: string; flags: Flags; maxRequests: number; queryBudget: number; maxPages: number; maxBytes: number; timeout: number }

const commonFlags = ['--json', '--output', '--help', '--config', '--profile', '--max-requests', '--max-bytes', '--timeout']
const value = (flags: Flags, name: string): string | undefined => { const item = flags.get(name); return typeof item === 'string' ? item : undefined }
const numberOption = (flags: Flags, name: string, fallback: number, max: number): number => {
  const input = value(flags, name)
  if (input === undefined) return fallback
  if (!/^\d+$/.test(input) || Number(input) > max) throw new ToolError('INVALID_INPUT', `Invalid ${name}`, 'Supply a non-negative integer within the allowed limit')
  return Number(input)
}
const fail = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run the command with --help for valid selectors and limits') }
const validDomain = (name: string): boolean => name.length <= 253 && name.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))
const sameAddress = (left: string, right: string | undefined): boolean => {
  if (!right) return false
  return isIP(left) === 6 && isIP(right) === 6 ? new URL(`http://[${left}]`).hostname === new URL(`http://[${right}]`).hostname : left === right
}

export function planInvestigation(words: string[], flags: Flags): Investigation | undefined {
  const matches = operations.filter(item => !['OP-039', 'OP-045', 'OP-072'].includes(item.id)).filter(item => {
    const parts = item.command.split(' ')
    return parts.every((part, index) => words[index] === part) && (words.length === parts.length + ('argument' in item ? 1 : 0) || (flags.has('--help') && words.length === parts.length))
  }).sort((a, b) => b.command.length - a.command.length)
  const selected: ReadOperation | undefined = matches[0]
  if (!selected) return undefined
  const operation: ReadOperation = selected.id === 'OP-044' && flags.has('--ipv6') ? operations.find(item => item.id === 'OP-072') ?? selected : selected
  const allowed = [...commonFlags, ...(operation.cost === 'none' ? [] : ['--query-credit-budget', '--allow-operation']),
    ...(operation.cost === 'unknown' ? ['--accept-unknown-cost'] : []), ...(selected.flags ?? [])]
  if (operation.id === 'OP-059' && (flags.has('--config') || flags.has('--profile'))) fail('InternetDB does not use a credential profile')
  for (const flag of flags.keys()) if (!allowed.includes(flag)) fail(`Flag ${flag} is not available for this command`)
  const argument = selected.argument && words.length > selected.command.split(' ').length ? words.at(-1) : undefined
  if (argument !== undefined) {
    if (!argument || argument.length > 4096) fail('Invalid selector')
    if (selected.argument === 'ip' && !isIP(argument)) fail('Expected an IPv4 or IPv6 address')
    if (selected.argument === 'domain' && !validDomain(argument)) fail('Invalid domain')
    if (selected.argument === 'names' && !argument.split(',').every(validDomain)) fail('Invalid hostname list')
    if (selected.argument === 'ips' && !argument.split(',').every(ip => isIP(ip))) fail('Invalid address list')
  }
  const maxRequests = numberOption(flags, '--max-requests', 1, 1000)
  const maxPages = numberOption(flags, '--max-pages', 1, 1000)
  const queryBudget = numberOption(flags, '--query-credit-budget', 0, 1000)
  const maxBytes = numberOption(flags, '--max-bytes', 1024 * 1024, 10 * 1024 * 1024)
  const timeout = numberOption(flags, '--timeout', 30000, 300000)
  if (!maxRequests || !maxPages || !maxBytes || !timeout) fail('Limits must be greater than zero')
  if (!flags.has('--help') && operation.cost !== 'none' && value(flags, '--allow-operation') !== operation.id) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'An exact operation grant is required', `Pass --allow-operation ${operation.id} with an explicit budget`)
  if (!flags.has('--help') && operation.cost !== 'none' && queryBudget < 1) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Query-credit budget is required', 'Pass --query-credit-budget with an allowed credit count')
  if (!flags.has('--help') && operation.cost === 'unknown' && (!flags.has('--accept-unknown-cost') || !flags.has('--max-requests'))) throw new ToolError('CREDIT_BUDGET_REQUIRED', 'Unknown cost requires explicit acceptance and a request cap', 'Pass --accept-unknown-cost and --max-requests')
  if (flags.has('--save') && value(flags, '--filename')) fail('Choose --save or --filename')
  if (flags.has('--color') && flags.has('--no-color')) fail('Choose one color option')
  if (value(flags, '--minify') !== undefined && !['true', 'false'].includes(value(flags, '--minify') ?? '')) fail('Minify must be true or false')
  if (value(flags, '--format') !== undefined && !['pretty', 'tsv'].includes(value(flags, '--format') ?? '')) fail('Format must be pretty or tsv')
  const fields = value(flags, '--fields')
  if (fields !== undefined && !fields.split(',').every(field => /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$/.test(field))) fail('Invalid field selection')
  const facets = value(flags, '--facets')
  if (facets !== undefined && !facets.split(',').every(facet => /^[A-Za-z0-9_.-]+(?::[1-9][0-9]*)?$/.test(facet))) fail('Invalid facet selection')
  const recordType = value(flags, '--type')
  if (recordType !== undefined && !/^[A-Za-z0-9-]+$/.test(recordType)) fail('Invalid DNS record type')
  if (!numberOption(flags, '--page', 1, 1000000)) fail('Page must be greater than zero')
  numberOption(flags, '--offset', 0, 1000000)
  if (value(flags, '--limit') !== '-1' && !numberOption(flags, '--limit', 100, 1000)) fail('Limit must be greater than zero')
  return { operation, ...(argument === undefined ? {} : { argument }), flags, maxRequests, queryBudget, maxPages, maxBytes, timeout }
}

const object = z.record(z.string(), z.unknown())
const banner = z.object({ ip_str: z.string(), port: z.number().int(), transport: z.string(), timestamp: z.string(),
  metadata: z.object({ truncated: z.array(z.string()).optional() }).passthrough().optional() }).passthrough()
const host = z.object({ ip_str: z.string(), ports: z.array(z.number().int()), data: z.array(banner) }).passthrough()
const search = z.object({ total: z.number().int().nonnegative(), matches: z.array(banner) }).passthrough()
const count = z.object({ total: z.number().int().nonnegative(), facets: object.optional() }).passthrough()
const domain = z.object({ domain: z.string(), data: z.array(z.object({ type: z.string(), value: z.string() }).passthrough()), more: z.boolean() }).passthrough()
const tokenized = z.object({ attributes: object, errors: z.array(z.unknown()), string: z.string(), filters: z.array(z.string()) }).passthrough()
const internetdb = z.object({ ip: z.string(), ports: z.array(z.number().int()), cpes: z.array(z.string()), hostnames: z.array(z.string()), tags: z.array(z.string()), vulns: z.array(z.string()) }).passthrough()

function parse<T>(schema: z.ZodType<T>, raw: unknown): T {
  const result = schema.safeParse(raw)
  if (!result.success) throw new ToolError('INVALID_RESPONSE', 'The service returned an invalid response', 'Retry later or inspect service status')
  return result.data
}

function project(item: Record<string, unknown>, fields: string[]): Record<string, unknown> {
  return Object.fromEntries(fields.map(field => {
    let current: unknown = item
    for (const part of field.split('.')) {
      const record = object.safeParse(current)
      current = record.success ? record.data[part] : undefined
    }
    return [field, current ?? null]
  }))
}

async function appendArtifact(filename: string, bytes: Buffer): Promise<{ path: string; appendedBytes: number; appendedSha256: string }> {
  const access = constants.O_RDWR | constants.O_APPEND
  let file: Awaited<ReturnType<typeof open>>
  let created = false
  try {
    file = await open(filename, access | constants.O_CREAT | constants.O_EXCL | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW), process.platform === 'win32' ? undefined : 0o600)
    created = true
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error
    const before = await lstat(filename)
    if (!before.isFile() || before.isSymbolicLink()) throw new ToolError('CONFIG_INSECURE', 'Unsafe output file', 'Choose a private regular file')
    if (process.platform === 'win32') windowsAcl(filename, 'verify', false)
    file = await open(filename, access | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW))
    const opened = await file.stat()
    if (opened.dev !== before.dev || opened.ino !== before.ino) { await file.close(); throw new ToolError('CONFIG_INSECURE', 'Output file changed', 'Retry with a private regular file') }
  }
  try {
    if (process.platform === 'win32') {
      if (created) windowsAcl(filename, 'restrict', false)
      else windowsAcl(filename, 'verify', false)
    }
    const before = await file.stat()
    if (!before.isFile() || (process.platform !== 'win32' && (before.uid !== process.getuid?.() || (before.mode & 0o077) !== 0))) throw new ToolError('CONFIG_INSECURE', 'Unsafe output file', 'Choose a private regular file')
    await file.writeFile(bytes)
    await file.sync()
    const actual = Buffer.alloc(bytes.length)
    const read = await file.read(actual, 0, actual.length, before.size)
    if (read.bytesRead !== bytes.length || !actual.equals(bytes)) throw new ToolError('INVALID_RESPONSE', 'Saved bytes could not be verified', 'Inspect the file before retrying')
  } finally { await file.close() }
  return { path: filename, appendedBytes: bytes.length, appendedSha256: createHash('sha256').update(bytes).digest('hex') }
}

async function save(plan: Investigation, payload: unknown, key: string, destination?: string): Promise<{ path: string; appendedBytes: number; appendedSha256: string } | undefined> {
  let filename = destination ?? value(plan.flags, '--filename') ?? (plan.flags.has('--save') ? `${plan.argument ?? 'results'}.json.gz` : undefined)
  if (!filename) return undefined
  if (!filename.endsWith('.json.gz')) filename += '.json.gz'
  const safe = clean(payload, key)
  const body = Array.isArray(safe) ? safe : [safe]
  const bytes = gzipSync(body.map(row => JSON.stringify(row)).join('\n') + '\n')
  return appendArtifact(filename, bytes)
}

export async function investigate(plan: Investigation, origin: string | undefined, key: string | undefined): Promise<unknown> {
  const { operation, flags, argument } = plan
  const page = numberOption(flags, '--page', 1, 1000000)
  const limit = value(flags, '--limit') === '-1' ? Infinity : numberOption(flags, '--limit', operation.command === 'stats' ? 10 : 100, 1000)
  if (!page || !limit) fail('Page and limit must be greater than zero')
  const query: Record<string, string> = {}
  if (argument !== undefined && ['OP-002', 'OP-003', 'OP-006'].includes(operation.id)) query.query = argument
  if (operation.id === 'OP-041' && argument) query.hostnames = argument
  if (operation.id === 'OP-042' && argument) query.ips = argument
  for (const name of ['history', 'minify', 'type', 'facets']) {
    const item = flags.get(`--${name}`)
    if (item !== undefined) query[name] = String(item)
  }
  if (operation.command === 'stats' && query.facets === undefined) query.facets = 'country,org'
  if (operation.id === 'OP-003' || operation.id === 'OP-040') query.page = String(page)
  if (operation.id === 'OP-040' && query.history === undefined) query.history = 'false'
  const path = operation.path.replace(/\{(?:ip|domain)\}/, encodeURIComponent(argument ?? ''))
  const service = operation.id === 'OP-059' ? 'https://internetdb.shodan.io' : operation.id === 'OP-072' ? 'https://apiv6.shodan.io' : origin
  if (!service) throw new ToolError('AUTH_REQUIRED', 'A credentialed profile is required', 'Configure a profile with an API key reference')
  let requests = 0
  let credits = 0
  const deadline = Date.now() + plan.timeout
  const canDispatch = (cost: boolean): boolean => requests < plan.maxRequests && (!cost || credits < plan.queryBudget) && Date.now() < deadline
  const stopReason = (): string => Date.now() >= deadline ? 'timeout' : requests >= plan.maxRequests ? 'request-limit' : credits >= plan.queryBudget ? 'credit-budget' : 'page-limit'
  const dispatch = async (requestPath: string, parameters: Readonly<Record<string, string>>, cost: boolean): Promise<unknown> => {
    if (!canDispatch(cost)) throw new ToolError('LIMIT_REACHED', 'Request or credit limit reached', 'Increase the appropriate budget to continue')
    requests++
    if (cost) credits++
    try { return await requestJson(service, requestPath, operation.id === 'OP-059' ? undefined : key, parameters, 10 * 1024 * 1024,
      Math.max(1, deadline - Date.now()), operation.id === 'OP-044' || operation.id === 'OP-072', operation.id === 'OP-072' ? 6 : undefined) }
    catch (error) {
      if (cost && error instanceof ToolError && error.code === 'UPSTREAM_ERROR') throw new ToolError(error.code, `${error.message}; credit use is uncertain`, 'Check the service and remaining credit before retrying')
      throw error
    }
  }
  const raw = await dispatch(path, query, operation.cost !== 'none')
  if (operation.id === 'OP-001') {
    const result = parse(host, raw)
    if (!sameAddress(result.ip_str, argument)) throw new ToolError('INVALID_RESPONSE', 'Host response does not match the selected address', 'Retry the selected address')
    const saved = await save(plan, result.data.filter(row => !Object.hasOwn(row, 'placeholder')), key ?? '\u0000')
    const vendorTruncations = [...new Set(result.data.flatMap(row => row.metadata?.truncated ?? []))]
    const format = value(flags, '--format')
    const display = format === 'tsv' ? result.data.map(row => [row.ip_str, row.port, row.transport, row.timestamp].join('\t')).join('\n')
      : format === 'pretty' ? result.data.map(row => `${row.ip_str}:${row.port}/${row.transport} ${row.timestamp}`).join('\n') : undefined
    return { host: result, banners: result.data, historyRequested: flags.has('--history'),
      ...(vendorTruncations.length ? { vendorTruncations, fullHistoricalPayload: false } : {}),
      ...(display === undefined ? {} : { display }), ...(saved ? { saved } : {}) }
  }
  if (operation.id === 'OP-002') {
    const result = parse(count, raw)
    if (operation.command !== 'stats') return result
    const facets = parse(z.record(z.string(), z.array(z.object({ value: z.union([z.string(), z.number()]), count: z.number().int().nonnegative() }).passthrough())), result.facets ?? {})
    const buckets = Object.entries(facets).flatMap(([facet, rows]) => rows.slice(0, limit).map(row => ({ facet, ...row })))
    const filename = value(flags, '--filename')
    let saved
    if (filename) {
      const lines = buckets.map(row => [row.facet, row.value, row.count].map(cell => `"${String(clean(cell, key ?? '\u0000')).replaceAll('"', '""')}"`).join(','))
      const csv = lines.length ? `${lines.join('\n')}\n` : ''
      saved = await appendArtifact(filename, Buffer.from(csv))
    }
    return { total: result.total, facets, buckets, count: buckets.length, ...(saved ? { saved } : {}) }
  }
  if (operation.id === 'OP-003') {
    let result = parse(search, raw)
    const offset = numberOption(flags, '--offset', 0, 1000000)
    if (offset > result.matches.length) throw new ToolError('INVALID_INPUT', 'Offset exceeds the selected page', 'Use a continuation returned by a previous search')
    const firstRows = result.matches.slice(offset)
    const segments = [{ page, offset, rows: firstRows }]
    const rows = [...firstRows]
    let returned = result.matches.length
    const total = result.total
    let currentPage = page
    let pages = 1
    while (result.matches.length && rows.length < limit && rows.length < total && pages < plan.maxPages && canDispatch(true)) {
      currentPage++
      result = parse(search, await dispatch(path, { ...query, page: String(currentPage) }, true))
      segments.push({ page: currentPage, offset: 0, rows: result.matches })
      rows.push(...result.matches)
      returned += result.matches.length
      pages++
    }
    const fields = value(flags, '--fields')?.split(',').filter(Boolean) ?? ['ip_str', 'port', 'hostnames', 'data']
    const truncations: { row: number; field: string; length: number }[] = []
    const items = rows.slice(0, limit).map((item, index) => {
      const projected = project(item, fields)
      if (!flags.has('--full')) for (const field of fields) {
        const current = projected[field]
        if (typeof current === 'string' && current.length > 500) {
          truncations.push({ row: index, field, length: current.length })
          projected[field] = `${current.slice(0, 500)}...`
        }
      }
      return projected
    })
    const separator = value(flags, '--separator')
    const displayFields = fields
    const showDisplay = separator !== undefined || flags.has('--color') || flags.has('--no-color')
    const display = showDisplay ? items.map(selected => {
      const line = displayFields.map(field => {
        const cell = selected[field]
        return cell === null || cell === undefined ? '' : typeof cell === 'string' || typeof cell === 'number' || typeof cell === 'boolean' ? String(cell) : JSON.stringify(cell)
      }).join(separator ?? '\t')
      return flags.has('--color') ? `\u001b[36m${line}\u001b[0m` : line
    }).join('\n') : undefined
    const vendorTruncations = [...new Set(rows.flatMap(row => row.metadata?.truncated ?? []))]
    const complete = page === 1 && offset === 0 && items.length === total && vendorTruncations.length === 0
    let remaining = items.length
    let continuation: { page: number; offset: number } | undefined
    for (const segment of segments) {
      if (remaining < segment.rows.length) { continuation = { page: segment.page, offset: segment.offset + remaining }; break }
      remaining -= segment.rows.length
    }
    const exhaustedFirstPage = page === 1 && currentPage === 1 && offset + items.length >= total
    if (!continuation && result.matches.length && !complete && !exhaustedFirstPage) continuation = { page: currentPage + 1, offset: 0 }
    return { items, count: items.length, returned, total, page, pages, requests, queryCreditEstimate: credits, costKnowledge: 'estimated', complete, ...(display === undefined ? {} : { display }),
      ...(vendorTruncations.length ? { vendorTruncations } : {}),
      ...(truncations.length ? { truncations, help: 'Use --full to include complete text within the byte limit' } : {}),
      stopReason: complete ? 'complete' : vendorTruncations.length && items.length === total ? 'vendor-truncated' : !result.matches.length ? 'empty-page' : items.length < rows.length ? 'limit' : !canDispatch(true) ? stopReason() : 'page-limit',
      ...(continuation ? { continuation } : {}) }
  }
  if (operation.id === 'OP-040') {
    let result = parse(domain, raw)
    if (result.domain.toLowerCase() !== argument?.toLowerCase()) throw new ToolError('INVALID_RESPONSE', 'Domain response does not match the selection', 'Retry the selected domain')
    const offset = numberOption(flags, '--offset', 0, 1000000)
    if (offset > result.data.length) throw new ToolError('INVALID_INPUT', 'Offset exceeds the selected page', 'Use a continuation returned by a previous domain read')
    const firstRecords = result.data.slice(offset)
    const segments = [{ page, offset, rows: firstRecords }]
    const rows = [...firstRecords]
    let currentPage = page
    let pages = 1
    while (result.more && rows.length < limit && pages < plan.maxPages && canDispatch(true)) {
      currentPage++
      result = parse(domain, await dispatch(path, { ...query, page: String(currentPage) }, true))
      if (result.domain.toLowerCase() !== argument?.toLowerCase()) throw new ToolError('INVALID_RESPONSE', 'Domain response does not match the selection', 'Retry the selected domain')
      segments.push({ page: currentPage, offset: 0, rows: result.data })
      rows.push(...result.data)
      pages++
    }
    const records = rows.slice(0, limit)
    let remaining = records.length
    let continuation: { page: number; offset: number } | undefined
    for (const segment of segments) {
      if (remaining < segment.rows.length) { continuation = { page: segment.page, offset: segment.offset + remaining }; break }
      remaining -= segment.rows.length
    }
    if (!continuation && result.more) continuation = { page: currentPage + 1, offset: 0 }
    const details: z.output<typeof host>[] = []
    let detailsComplete = true
    let remainingDetails: string[] = []
    if (flags.has('--details')) {
      const ips = [...new Set(records.filter(record => record.type === 'A' || record.type === 'AAAA').map(record => record.value).filter(address => isIP(address) !== 0))]
      for (const ip of ips) {
        if (!canDispatch(false)) { detailsComplete = false; remainingDetails = ips.slice(details.length); break }
        const detail = parse(host, await dispatch(`/shodan/host/${encodeURIComponent(ip)}`, {}, false))
        if (!sameAddress(detail.ip_str, ip)) throw new ToolError('INVALID_RESPONSE', 'Host response does not match the selected address', 'Retry the selected address')
        details.push(detail)
      }
    }
    const saved = await save(plan, records, key ?? '\u0000')
    const savedHosts = flags.has('--save') && flags.has('--details')
      ? await save(plan, details.flatMap(detail => detail.data.filter(row => !Object.hasOwn(row, 'placeholder'))), key ?? '\u0000', `${argument ?? 'results'}-hosts.json.gz`)
      : undefined
    const complete = page === 1 && offset === 0 && !continuation && detailsComplete
    const envelope = Object.fromEntries(Object.entries(result).filter(([field]) => field !== 'data'))
    return { ...envelope, records, count: records.length, page, pages, requests, queryCreditEstimate: credits, costKnowledge: 'estimated',
      complete, stopReason: complete ? 'complete' : !detailsComplete ? 'request-limit' : records.length < rows.length ? 'limit' : !canDispatch(true) ? stopReason() : 'page-limit',
      details, ...(savedHosts ? { savedHosts } : {}), ...(remainingDetails.length ? { remainingDetails } : {}), ...(continuation ? { continuation } : {}),
      ...(result.more && continuation?.offset === 0 ? { nextPage: continuation.page } : {}), ...(saved ? { saved } : {}) }
  }
  if (operation.id === 'OP-004' || operation.id === 'OP-005') { const items = parse(z.array(z.string()), raw); return { items, count: items.length } }
  if (operation.id === 'OP-007') { const items = parse(z.array(z.number().int()), raw); return { items, count: items.length } }
  if (operation.id === 'OP-006') return parse(tokenized, raw)
  if (operation.id === 'OP-041') {
    const result = parse(z.record(z.string(), z.string().nullable()), raw)
    return Object.fromEntries((argument ?? '').split(',').map(name => [name, result[name] ?? null]))
  }
  if (operation.id === 'OP-042') {
    const result = parse(z.record(z.string(), z.array(z.string())), raw)
    return Object.fromEntries((argument ?? '').split(',').map(ip => [ip, result[ip] ?? null]))
  }
  if (operation.id === 'OP-043') return parse(z.record(z.string(), z.string()), raw)
  if (operation.id === 'OP-044' || operation.id === 'OP-072') {
    const address = parse(z.string(), raw)
    const family = operation.id === 'OP-072' ? 6 : 4
    if (isIP(address) !== family) throw new ToolError('INVALID_RESPONSE', 'Invalid egress address', 'Retry the selected address family')
    return { ip: address, addressFamily: family, attribution: 'egress address of execution location' }
  }
  if (operation.id === 'OP-059') {
    const result = parse(internetdb, raw)
    if (!sameAddress(result.ip, argument)) throw new ToolError('INVALID_RESPONSE', 'Snapshot does not match the selected address', 'Retry the selected address')
    return result
  }
  if (operation.id === 'OP-064') return { ip: argument, score: parse(z.number().min(0).max(1), raw), costKnowledge: 'unknown', contractStatus: 'source-only-unverified' }
  if (operation.id === 'OP-066') return { services: parse(z.record(z.string(), z.string()), raw), costKnowledge: 'unknown', contractStatus: 'source-only-unverified' }
  throw new ToolError('INVALID_INPUT', 'Unsupported operation', 'Run --help for available operations')
}
