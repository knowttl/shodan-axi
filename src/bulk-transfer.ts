import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { constants, createReadStream } from 'node:fs'
import { lstat, open, link, rename, unlink } from 'node:fs/promises'
import { request } from 'node:https'
import { dirname, join, resolve } from 'node:path'
import { z } from 'zod'
import type { Selection } from './credentials.js'
import { storageOrigins } from './bulk.js'
import { ToolError } from './errors.js'
import { planKey, stateRoot } from './mutations.js'
import { preparePrivateDirectory, readPrivate, writePrivate } from './private-file.js'
import { requestJson } from './vendor.js'
import { windowsAcl } from './windows-acl.js'

type Flags = Map<string, string | boolean>
const option = (flags: Flags, name: string): string | undefined => { const value = flags.get(name); return typeof value === 'string' ? value : undefined }
const bad = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run data download --help') }
const digest = (text: string): string => createHash('sha256').update(text).digest('hex')
const planSchema = z.object({ token: z.string().uuid(), binding: z.string(), created: z.number(), mac: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
const metadataSchema = z.array(z.object({ name: z.string(), size: z.number().int().nonnegative(), sha1: z.string().regex(/^[a-fA-F0-9]{40}$/), url: z.string().url() }))
type Draft = { dataset: string; name: string; destination: string; maxBytes: number; maxRequests: number; mode: 'new' | 'resume' | 'restart' }

export function transferDraft(words: string[], flags: Flags): Draft {
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--allow-operation', '--max-bytes', '--max-requests', '--filename', '--execute', '--confirm', '--resume', '--restart'].includes(flag)) bad(`Flag ${flag} is not available for data download`)
  const dataset = words[2]; const name = words[3]; const filename = option(flags, '--filename'); const maxBytes = option(flags, '--max-bytes'); const maxRequests = option(flags, '--max-requests')
  if (words.length !== 4 || !dataset || !name || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(dataset) || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/.test(name) || !filename || filename.split(/[\\/]/).includes('..')) return bad('Invalid dataset, file name or destination')
  if (!maxBytes || !/^[1-9]\d*$/.test(maxBytes) || !Number.isSafeInteger(Number(maxBytes))) return bad('A positive byte limit is required')
  if (!maxRequests || !/^[1-9]\d*$/.test(maxRequests) || !Number.isSafeInteger(Number(maxRequests)) || Number(maxRequests) > 10000) return bad('A positive bounded request limit is required')
  if (flags.has('--resume') && flags.has('--restart')) return bad('Choose resume or restart')
  if (option(flags, '--allow-operation') !== 'OP-034,OP-035,OP-071') throw new ToolError('WRITE_GRANT_REQUIRED', 'Dataset selection and transfer require separate operation grants', 'Pass --allow-operation OP-034,OP-035,OP-071')
  if (flags.has('--execute') !== flags.has('--confirm')) return bad('Execution requires a confirmation token')
  if (flags.has('--execute') && /^(true|1)$/i.test(process.env.SHODAN_AXI_READ_ONLY ?? '')) throw new ToolError('READ_ONLY', 'Dataset transfers are disabled', 'Use a writable environment')
  return { dataset, name, destination: resolve(filename), maxBytes: Number(maxBytes), maxRequests: Number(maxRequests), mode: flags.has('--resume') ? 'resume' : flags.has('--restart') ? 'restart' : 'new' }
}

function approvedUrl(input: string, approvedOrigins: readonly string[]): URL {
  let url: URL
  try { url = new URL(input) } catch { throw new ToolError('INVALID_RESPONSE', 'Invalid dataset location', 'Inspect dataset metadata') }
  if (url.protocol !== 'https:' || url.username || url.password || !approvedOrigins.includes(url.origin)) throw new ToolError('STORAGE_POLICY_UNAVAILABLE', `Dataset storage host is not reviewed: ${url.hostname}`, 'Review the storage destination policy')
  return url
}

async function range(url: URL, start: number, end: number, total: number, version?: string): Promise<{ bytes: Buffer; etag: string }> {
  return new Promise((resolveRange, reject) => {
    const req = request(url, { headers: { Range: `bytes=${start}-${end}`, ...(version ? { 'If-Match': version } : {}) } }, response => {
      const etag = response.headers.etag
      const rangeHeader = response.headers['content-range']
      if (response.statusCode !== 206 || !etag || etag.startsWith('W/') || (version && etag !== version) || rangeHeader !== `bytes ${start}-${end}/${total}`) { response.destroy(); reject(new ToolError('SOURCE_CHANGED', 'Transfer source or range changed', 'Restart only after explicit approval')); return }
      const chunks: Buffer[] = []; let size = 0
      response.on('data', (chunk: Buffer) => { size += chunk.length; if (size > end - start + 1) req.destroy(); else chunks.push(chunk) })
      response.on('end', () => size === end - start + 1 ? resolveRange({ bytes: Buffer.concat(chunks), etag }) : reject(new ToolError('UPSTREAM_ERROR', 'Incomplete dataset range', 'Inspect the partial transfer')))
      response.on('error', reject)
    })
    req.setTimeout(30000, () => req.destroy())
    req.on('error', () => reject(new ToolError('UPSTREAM_ERROR', 'Dataset transfer failed', 'Inspect the partial transfer')))
    req.end()
  })
}

export async function transfer(draft: Draft, flags: Flags, selection: Selection, key: string, approvedOrigins: readonly string[] = storageOrigins): Promise<unknown> {
  const response = metadataSchema.safeParse(await requestJson(selection.profile.origin, `/shodan/data/${encodeURIComponent(draft.dataset)}`, key))
  if (!response.success) throw new ToolError('INVALID_RESPONSE', 'Invalid dataset file listing', 'Inspect the service response')
  const matches = response.data.filter(item => item.name === draft.name)
  if (matches.length !== 1) throw new ToolError('NOT_FOUND', 'Dataset file is not uniquely available', 'Inspect data list')
  const item = matches[0]
  if (!item || item.size > draft.maxBytes) throw new ToolError('LIMIT_REACHED', 'Dataset exceeds the byte limit', 'Increase the bound or select another file')
  if (Math.ceil(item.size / (1024 * 1024)) + 1 > draft.maxRequests) throw new ToolError('LIMIT_REACHED', 'Dataset exceeds the request limit', 'Increase the request bound')
  const url = approvedUrl(item.url, approvedOrigins)
  const root = stateRoot(); const directory = join(root, 'plans'); const signingKey = await planKey(root)
  const binding = digest(JSON.stringify({ draft, item, selection, credential: digest(key) }))
  if (!flags.has('--execute')) {
    const unsigned = { token: randomUUID(), binding, created: Date.now() }
    await writePrivate(join(directory, `${unsigned.token}.json`), JSON.stringify({ ...unsigned, mac: createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest('hex') }))
    return { status: 'preview', token: unsigned.token, operation: 'OP-071', dataset: draft.dataset, name: draft.name, host: url.hostname, size: item.size, maxBytes: draft.maxBytes, maxRequests: draft.maxRequests, mode: draft.mode, destination: draft.destination, help: 'Repeat with --execute --confirm <token>' }
  }
  const token = option(flags, '--confirm')
  if (!token || !z.string().uuid().safeParse(token).success) return bad('Invalid confirmation token')
  const planPath = join(directory, `${token}.json`)
  let raw: unknown
  try { raw = JSON.parse(await readPrivate(planPath, true)) } catch { throw new ToolError('PLAN_NOT_FOUND', 'Confirmation plan is unavailable', 'Create a new preview') }
  const parsed = planSchema.safeParse(raw)
  if (!parsed.success) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  const { mac, ...unsigned } = parsed.data
  if (!timingSafeEqual(createHmac('sha256', signingKey).update(JSON.stringify(unsigned)).digest(), Buffer.from(mac, 'hex')) || unsigned.token !== token || unsigned.binding !== binding || Date.now() - unsigned.created > 900000) throw new ToolError('PLAN_STALE', 'Confirmation does not match the request', 'Create a new preview')
  try { await rename(planPath, join(directory, `${token}.used`)) } catch { throw new ToolError('PLAN_STALE', 'Confirmation was already consumed', 'Create a new preview') }
  const partial = `${draft.destination}.partial`; const statePath = `${partial}.state`
  await preparePrivateDirectory(dirname(draft.destination))
  try { await lstat(draft.destination); throw new ToolError('DESTINATION_EXISTS', 'Output already exists', 'Choose another destination') } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error }
  const identity = digest(JSON.stringify({ item, dataset: draft.dataset, destination: draft.destination }))
  const stateSchema = z.object({ identity: z.string(), etag: z.string(), offset: z.number().int().positive(), sha256: z.string() }).strict()
  let offset = 0; let etag: string | undefined
  const sha1 = createHash('sha1'); const sha256 = createHash('sha256')
  if (draft.mode === 'restart') { await unlink(partial); await unlink(statePath).catch(() => undefined) }
  if (draft.mode === 'resume') {
    let saved: unknown
    try { saved = JSON.parse(await readPrivate(statePath, true)) } catch { throw new ToolError('PLAN_STALE', 'Transfer state is unavailable', 'Choose an explicit restart') }
    const state = stateSchema.safeParse(saved)
    if (!state.success || state.data.identity !== identity || state.data.offset >= item.size) throw new ToolError('PLAN_STALE', 'Transfer state does not match the selected source', 'Choose an explicit restart')
    const existing = await open(partial, constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW))
    try {
      const stat = await existing.stat()
      if (!stat.isFile() || stat.size !== state.data.offset || (process.platform !== 'win32' && (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0))) throw new ToolError('PLAN_STALE', 'Partial file does not match transfer state', 'Choose an explicit restart')
      if (process.platform === 'win32') windowsAcl(partial, 'verify', false)
      for await (const chunk of existing.createReadStream()) { if (!Buffer.isBuffer(chunk)) throw new Error('Invalid file chunk'); sha1.update(chunk); sha256.update(chunk) }
      if (sha256.copy().digest('hex') !== state.data.sha256) throw new ToolError('PLAN_STALE', 'Partial file checksum changed', 'Choose an explicit restart')
      offset = state.data.offset; etag = state.data.etag
    } finally { await existing.close().catch(() => undefined) }
  }
  const file = await open(partial, draft.mode === 'resume' ? constants.O_WRONLY | constants.O_APPEND | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW) : constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600)
  if (process.platform === 'win32') windowsAcl(partial, draft.mode === 'resume' ? 'verify' : 'restrict', false)
  try {
    for (; offset < item.size;) {
      const result = await range(url, offset, Math.min(offset + 1024 * 1024, item.size) - 1, item.size, etag)
      etag = result.etag; sha1.update(result.bytes); sha256.update(result.bytes); await file.writeFile(result.bytes); await file.sync()
      offset += result.bytes.length
      await writePrivate(statePath, JSON.stringify({ identity, etag, offset, sha256: sha256.copy().digest('hex') }))
    }
    await file.sync()
  } finally { await file.close() }
  if (sha1.digest('hex') !== item.sha1.toLowerCase()) throw new ToolError('INVALID_RESPONSE', 'Dataset checksum does not match metadata', 'Inspect the partial transfer')
  const expectedSha256 = sha256.digest('hex'); const readHash = createHash('sha256'); let bytes = 0
  for await (const chunk of createReadStream(partial)) { if (!Buffer.isBuffer(chunk)) throw new Error('Invalid file chunk'); readHash.update(chunk); bytes += chunk.length }
  if (bytes !== item.size || readHash.digest('hex') !== expectedSha256) throw new ToolError('INVALID_RESPONSE', 'Saved dataset verification failed', 'Inspect the partial transfer')
  await link(partial, draft.destination); await unlink(partial); if (item.size) await unlink(statePath)
  return { path: draft.destination, bytes, sha256: expectedSha256, sha1: item.sha1.toLowerCase(), complete: true }
}
