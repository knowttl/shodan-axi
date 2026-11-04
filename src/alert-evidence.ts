import { gzipSync } from 'node:zlib'
import ipaddr from 'ipaddr.js'
import { z } from 'zod'
import type { Selection } from './credentials.js'
import { csv, save } from './evidence.js'
import { ToolError } from './errors.js'
import { clean } from './redact.js'
import { requestJson } from './vendor.js'

type Flags = Map<string, string | boolean>
const fail = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Inspect the command arguments') }
const value = (flags: Flags, name: string): string | undefined => { const item = flags.get(name); return typeof item === 'string' ? item : undefined }
const number = (flags: Flags, name: string, fallback: number, max: number): number => {
  const raw = value(flags, name)
  if (raw === undefined) return fallback
  if (!/^[1-9]\d*$/.test(raw) || Number(raw) > max) return fail(`Invalid ${name}`)
  return Number(raw)
}
export function validateAlertEvidence(words: string[], flags: Flags): void {
  const command = words[1]
  const allowed = ['--json', '--output', '--help', '--config', '--profile', '--filename', '--max-requests', ...(command === 'stats' ? ['--facets', '--limit'] : [])]
  for (const flag of flags.keys()) if (!allowed.includes(flag)) fail(`Flag ${flag} is not available for this command`)
  if (words.length !== 2 || !['export', 'stats'].includes(command ?? '')) fail('Invalid alert command')
  number(flags, '--max-requests', 10, 1000)
  if (command === 'stats') {
    number(flags, '--limit', 10, 1000)
    const facets = (value(flags, '--facets') ?? 'port').split(',')
    if (!facets.every(item => /^[A-Za-z0-9_.-]+(?::[1-9]\d*)?$/.test(item))) fail('Invalid facet selection')
  }
}

export function union(networks: string[]): string[] {
  const ranges = networks.map(network => {
    let address: ipaddr.IPv4 | ipaddr.IPv6; let prefix: number
    try { [address, prefix] = network.includes('/') ? ipaddr.parseCIDR(network) : [ipaddr.parse(network), ipaddr.parse(network).kind() === 'ipv4' ? 32 : 128] } catch { return fail('Invalid monitored network') }
    const bits = address.kind() === 'ipv4' ? 32 : 128
    const numeric = address.toByteArray().reduce((total, byte) => (total << 8n) + BigInt(byte), 0n)
    const host = BigInt(bits - prefix); const start = numeric >> host << host
    return { bits, start, end: start + (1n << host) - 1n }
  }).sort((a, b) => a.bits - b.bits || (a.start < b.start ? -1 : a.start > b.start ? 1 : 0))
  const merged: typeof ranges = []
  for (const item of ranges) {
    const prior = merged.at(-1)
    if (prior && prior.bits === item.bits && item.start <= prior.end + 1n) prior.end = item.end > prior.end ? item.end : prior.end
    else merged.push({ ...item })
  }
  const result: string[] = []
  for (const range of merged) {
    let start = range.start
    while (start <= range.end) {
      let hostBits = 0n
      while (hostBits < BigInt(range.bits) && start % (1n << (hostBits + 1n)) === 0n && start + (1n << (hostBits + 1n)) - 1n <= range.end) hostBits++
      const bytes = Array<number>(range.bits / 8).fill(0)
      let current = start
      for (let index = bytes.length - 1; index >= 0; index--) { bytes[index] = Number(current & 255n); current >>= 8n }
      const address = ipaddr.fromByteArray(bytes)
      result.push(`${address.toString()}/${range.bits - Number(hostBits)}`)
      start += 1n << hostBits
    }
  }
  return result
}

const monitor = z.object({ id: z.string(), name: z.string(), filters: z.object({ ip: z.array(z.string()) }), created: z.string().optional(), expiration: z.string().nullable().optional(), triggers: z.record(z.string().regex(/^[A-Za-z0-9_-]+$/), z.object({ ignore: z.array(z.union([z.string(), z.object({ ip: z.string(), port: z.number().int() })])).optional() })).optional(), notifiers: z.array(z.union([z.string(), z.object({ id: z.string(), provider: z.string().optional(), description: z.string().optional() })])).optional() })
const countPage = z.object({ total: z.number().int().nonnegative(), facets: z.record(z.string(), z.array(z.object({ value: z.union([z.string(), z.number()]), count: z.number().int().nonnegative() }))).default({}) })

export async function alertEvidence(words: string[], flags: Flags, selection: Selection, key: string): Promise<unknown> {
  const maxRequests = number(flags, '--max-requests', 10, 1000)
  let requests = 0
  const dispatch = async (path: string, query: Record<string, string> = {}): Promise<unknown> => {
    if (requests >= maxRequests) throw new ToolError('LIMIT_REACHED', 'Request limit reached', 'Increase the request bound')
    requests++
    return requestJson(selection.profile.origin, path, key, query, 10 * 1024 * 1024)
  }
  const parsed = z.array(monitor).safeParse(await dispatch('/shodan/alert/info'))
  if (!parsed.success) throw new ToolError('INVALID_RESPONSE', 'Invalid alert list', 'Inspect the service response')
  if (words[1] === 'export') {
    const filename = value(flags, '--filename') ?? 'shodan-alerts.json.gz'
    const bytes = gzipSync(parsed.data.map(row => JSON.stringify(clean(row, key))).join('\n') + (parsed.data.length ? '\n' : ''))
    return { ...(await save(filename, bytes)), count: parsed.data.length, complete: true }
  }
  const networks = union(parsed.data.flatMap(alert => alert.filters.ip))
  const requested = (value(flags, '--facets') ?? 'port').split(',')
  const limit = number(flags, '--limit', 10, 1000)
  const buckets = new Map<string, { facet: string; value: string | number; count: number }>()
  let total = 0; let complete = true; let continuation: { network: string; page: number } | undefined
  const add = (facet: string, bucket: string | number, count: number): void => {
    const id = JSON.stringify([facet, bucket]); const existing = buckets.get(id)
    if (existing) existing.count += count
    else buckets.set(id, { facet, value: bucket, count })
  }
  for (const network of networks) {
    if (requests >= maxRequests) { complete = false; continuation = { network, page: 1 }; break }
    const response = countPage.safeParse(await dispatch('/shodan/host/count', { query: `net:${network}`, facets: requested.join(',') }))
    if (!response.success) throw new ToolError('INVALID_RESPONSE', 'Invalid count response', 'Inspect the service response')
    total += response.data.total
    for (const [facet, entries] of Object.entries(response.data.facets)) if (requested.some(item => item.split(':')[0] === facet)) for (const entry of entries) add(facet, entry.value, entry.count)
  }
  if (networks.length) complete = false
  const counts = new Map<string, number>()
  const items = [...buckets.values()].sort((a, b) => b.count - a.count).filter(item => {
    const count = counts.get(item.facet) ?? 0
    if (count >= limit) { complete = false; return false }
    counts.set(item.facet, count + 1)
    return true
  }).map(item => {
    const safe = clean(item.value, key)
    return { ...item, value: typeof safe === 'string' || typeof safe === 'number' ? safe : '' }
  })
  const filename = value(flags, '--filename')
  const saved = filename ? await save(complete ? filename : `${filename}.partial`, Buffer.from(['facet,value,count', ...items.map(row => [row.facet, row.value, row.count].map(csv).join(','))].join('\n') + '\n')) : undefined
  return { networks, total, items, count: items.length, aggregation: complete ? 'exact' : 'partial', complete, ...(continuation ? { continuation } : {}), ...(saved ? { saved } : {}) }
}
