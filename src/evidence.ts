import { createHash, randomUUID } from 'node:crypto'
import { lstat, readFile, rename, rm } from 'node:fs/promises'
import { isIP } from 'node:net'
import { dirname, resolve } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import ExcelJS from 'exceljs'
import ipaddr from 'ipaddr.js'
import jpeg from 'jpeg-js'
import { z } from 'zod'
import { ToolError } from './errors.js'
import { preparePrivateDirectory, readPrivateBytes, writePrivate } from './private-file.js'

type Flags = Map<string, string | boolean>
type RecordValue = Record<string, unknown>
const record = z.record(z.string(), z.unknown())
const option = (flags: Flags, key: string): string | undefined => { const entry = flags.get(key); return typeof entry === 'string' ? entry : undefined }
const invalid = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Inspect the file and command arguments') }
const fields = (value: string): string[] => {
  const selected = value.split(',').map(field => field.trim())
  if (!selected.length || !selected.every(field => /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/.test(field))) return invalid('Invalid field selection')
  return selected
}
const field = (value: unknown, path: string): unknown => path.split('.').reduce<unknown>((current, part) => {
  const parsed = record.safeParse(current)
  return parsed.success ? parsed.data[part] : undefined
}, value)

async function records(path: string): Promise<RecordValue[]> {
  const data = await readPrivateBytes(resolve(path), false)
  let bytes: Buffer
  try { bytes = data[0] === 0x1f && data[1] === 0x8b ? gunzipSync(data, { maxOutputLength: 10 * 1024 * 1024 }) : data } catch { return invalid('Invalid or oversized compressed input') }
  let text: string
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch { return invalid('Input is not UTF-8') }
  let raw: unknown
  try { raw = JSON.parse(text) } catch {
    try { raw = text.trim() ? text.trim().split('\n').map((line): unknown => JSON.parse(line)) : [] } catch { return invalid('Invalid JSON or JSONL input') }
  }
  const parsed = z.array(record).max(100000).safeParse(Array.isArray(raw) ? raw : [raw])
  if (!parsed.success) return invalid('Expected JSON records')
  return parsed.data
}

function filters(flags: Flags): ((item: RecordValue) => boolean)[] {
  const raw = option(flags, '--filters')
  const entries: unknown = raw ? JSON.parse(raw) : []
  const selected = z.array(z.string()).parse(entries)
  return selected.map(input => {
    const index = input.indexOf(':')
    if (index < 1 || index === input.length - 1) return invalid('Invalid filter')
    const name = input.slice(0, index); const expected = input.slice(index + 1)
    if (name === 'net') {
      if (!ipaddr.isValidCIDR(expected)) return invalid('Invalid network filter')
      const network = ipaddr.parseCIDR(expected)
      return item => { const ip = field(item, 'ip_str'); return typeof ip === 'string' && ipaddr.isValid(ip) && ipaddr.parse(ip).kind() === network[0].kind() && ipaddr.parse(ip).match(network) }
    }
    fields(name)
    return item => {
      const actual = field(item, name)
      if (Array.isArray(actual)) return actual.some(value => (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') && String(value) === expected)
      if (typeof actual === 'string') return actual.includes(expected)
      return (typeof actual === 'number' || typeof actual === 'boolean') && String(actual) === expected
    }
  })
}

function cell(value: unknown): string {
  if (value === undefined || value === null) return ''
  return Array.isArray(value) ? value.map(cell).join(';') : typeof value === 'object' ? JSON.stringify(value) : typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' ? String(value) : ''
}
export function csv(value: unknown): string {
  const raw = cell(value)
  const text = /^[\s\p{Cc}]*[=+@-]/u.test(raw) || /^[\t\r\n]/.test(raw) ? `'${raw}` : raw
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}
function xml(value: string): string { return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;') }
function locations(rows: RecordValue[]): { ip: string; latitude: number; longitude: number }[] {
  const unique = new Map<string, { ip: string; latitude: number; longitude: number }>()
  for (const row of rows) {
    const ip = row.ip_str; const latitude = field(row, 'location.latitude'); const longitude = field(row, 'location.longitude')
    if (typeof ip === 'string' && isIP(ip) && typeof latitude === 'number' && typeof longitude === 'number' && Number.isFinite(latitude) && Number.isFinite(longitude) && Math.abs(latitude) <= 90 && Math.abs(longitude) <= 180) unique.set(ip, { ip, latitude, longitude })
  }
  return [...unique.values()]
}
function outputPath(path: string): string {
  if (path.split(/[\\/]/).includes('..')) return invalid('Output path cannot contain traversal')
  return resolve(path)
}
export async function save(path: string, bytes: Uint8Array, replace = false): Promise<{ path: string; bytes: number; sha256: string }> {
  const destination = outputPath(path)
  if (!replace) try { await lstat(destination); throw new ToolError('DESTINATION_EXISTS', 'Output already exists', 'Choose another destination') } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
  await writePrivate(destination, bytes)
  const actual = await readFile(destination)
  if (!Buffer.from(bytes).equals(actual)) throw new ToolError('INVALID_RESPONSE', 'Output verification failed', 'Inspect the destination before retrying')
  return { path: destination, bytes: actual.length, sha256: createHash('sha256').update(actual).digest('hex') }
}

export async function evidence(words: string[], flags: Flags): Promise<unknown> {
  const command = words[0]
  const allowed = ['--json', '--output', '--help', '--fields', '--filename', ...(command === 'parse' ? ['--filters', '--separator', '--color', '--no-color'] : [])]
  for (const flag of flags.keys()) if (!allowed.includes(flag)) invalid(`Flag ${flag} is not available for this command`)
  if (flags.has('--help')) return { command, effect: 'local', help: command === 'parse' ? 'parse <file>... [--fields <fields>] [--filters <field:value>] [--separator <text>]' : 'convert <file> <csv|kml|geo.json|xlsx|images> [--fields <fields>] [--filename <path>]' }
  if (command === 'parse') {
    if (words.length < 2) return invalid('At least one input file is required')
    if (flags.has('--color') && flags.has('--no-color')) return invalid('Choose one color option')
    const selected = fields(option(flags, '--fields') ?? 'ip_str,port,hostnames,data')
    const predicates = filters(flags)
    const rows: RecordValue[] = []; let inputBytes = 0
    for (const path of words.slice(1)) for (const row of await records(path)) {
      inputBytes += Buffer.byteLength(JSON.stringify(row))
      if (inputBytes > 10 * 1024 * 1024 || rows.length >= 100000) return invalid('Combined input exceeds the limit')
      if (predicates.every(predicate => predicate(row))) rows.push(row)
    }
    const output = rows.map(row => Object.fromEntries(selected.map(name => [name, field(row, name) ?? null])))
    const separator = option(flags, '--separator') ?? '\t'
    const display = output.map(row => selected.map(name => { const text = cell(row[name]).replace(/[\p{Cc}]/gu, control => control === '\n' ? '\\n' : control === '\r' ? '\\r' : control === '\t' ? '\\t' : `\\u${control.charCodeAt(0).toString(16).padStart(4, '0')}`); return flags.has('--color') ? `\u001b[36m${text}\u001b[0m` : text }).join(separator)).join('\n')
    if (Buffer.byteLength(JSON.stringify(output)) + Buffer.byteLength(display) > 1024 * 1024) return invalid('Parsed output exceeds the limit')
    const filename = option(flags, '--filename')
    let artifact
    if (filename) {
      if (!predicates.length) return invalid('A filter is required when saving parsed records')
      const destination = outputPath(filename.endsWith('.json.gz') ? filename : `${filename}.json.gz`)
      let prior: RecordValue[] = []
      try { prior = await records(destination) } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
      const combined = [...prior, ...rows]
      if (combined.length > 100000) return invalid('Saved output exceeds the limit')
      const text = combined.map(row => JSON.stringify(row)).join('\n') + (combined.length ? '\n' : '')
      if (Buffer.byteLength(text) > 10 * 1024 * 1024) return invalid('Saved output exceeds the limit')
      const bytes = gzipSync(text)
      if (bytes.length > 1024 * 1024) return invalid('Saved output exceeds the limit')
      artifact = await save(destination, bytes, true)
    }
    return { items: output, count: output.length, complete: true, display, ...(artifact ? { saved: artifact } : {}) }
  }
  if (command !== 'convert' || words.length !== 3) return invalid('Expected an input file and output format')
  const input = words[1] ?? ''; const format = words[2] ?? ''
  if (!['csv', 'kml', 'geo.json', 'xlsx', 'images'].includes(format)) return invalid('Unsupported conversion format')
  if (flags.has('--fields') && !['csv', 'xlsx'].includes(format)) return invalid('Selected format does not support fields')
  const rows = await records(input)
  const selected = fields(option(flags, '--fields') ?? 'ip_str,port,hostnames,data')
  const destination = outputPath(option(flags, '--filename') ?? `${input.replace(/(?:\.jsonl?|\.gz)+$/g, '')}.${format}`)
  if (destination === resolve(input)) return invalid('Output cannot replace the input')
  let output: Uint8Array
  if (format === 'csv') output = Buffer.from([selected.map(csv).join(','), ...rows.map(row => selected.map(name => csv(field(row, name))).join(','))].join('\r\n') + '\r\n')
  else if (format === 'geo.json') output = Buffer.from(JSON.stringify({ type: 'FeatureCollection', features: locations(rows).map(place => ({ type: 'Feature', geometry: { type: 'Point', coordinates: [place.longitude, place.latitude] }, properties: { ip: place.ip } })) }))
  else if (format === 'kml') output = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>${locations(rows).map(place => `<Placemark><name>${xml(place.ip)}</name><Point><coordinates>${place.longitude},${place.latitude}</coordinates></Point></Placemark>`).join('')}</Document></kml>`)
  else if (format === 'xlsx') {
    const workbook = new ExcelJS.Workbook(); const raw = workbook.addWorksheet('Raw Data'); const summary = workbook.addWorksheet('Summary')
    raw.addRow(selected); for (const row of rows) raw.addRow(selected.map(name => { const value = field(row, name); return typeof value === 'boolean' || typeof value === 'number' ? value : cell(value) }))
    summary.addRow(['IP', 'Records']); const counts = new Map<string, number>()
    for (const row of rows) if (typeof row.ip_str === 'string' && isIP(row.ip_str)) counts.set(row.ip_str, (counts.get(row.ip_str) ?? 0) + 1)
    for (const [ip, count] of counts) summary.addRow([ip, count])
    output = new Uint8Array(await workbook.xlsx.writeBuffer())
  } else {
    const images = rows.flatMap((row, index) => {
      const encoded = field(row, 'opts.screenshot.data'); const mime = field(row, 'opts.screenshot.mime')
      if (encoded === undefined) return []
      if (typeof encoded !== 'string' || mime !== 'image/jpeg' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) return invalid('Invalid screenshot')
      const bytes = Buffer.from(encoded, 'base64')
      if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes.at(-2) !== 0xff || bytes.at(-1) !== 0xd9) return invalid('Invalid JPEG screenshot')
      try { jpeg.decode(bytes, { useTArray: true, maxResolutionInMP: 10, maxMemoryUsageInMB: 64 }) } catch { return invalid('Invalid JPEG screenshot') }
      return [{ name: `${index + 1}.jpg`, bytes }]
    })
    const temporary = `${destination}.${randomUUID()}.tmp`
    try { await lstat(destination); throw new ToolError('DESTINATION_EXISTS', 'Output already exists', 'Choose another destination') } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
    await preparePrivateDirectory(dirname(destination))
    await preparePrivateDirectory(temporary)
    try {
      for (const image of images) await save(resolve(temporary, image.name), image.bytes)
      await rename(temporary, destination)
    } finally { await rm(temporary, { recursive: true, force: true }) }
    return { format, path: destination, count: images.length, complete: true }
  }
  return { format, ...(await save(destination, output)), count: rows.length, complete: true }
}
