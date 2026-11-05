import { request } from 'node:https'
import { ToolError } from './errors.js'
import { info, account } from './contracts.js'
import { clean, cleanUpstream } from './redact.js'

export async function requestJson(origin: string, path: string, key: string | undefined, query: Readonly<Record<string, string>> = {}, maxBytes = 10 * 1024 * 1024, timeout = 30000, allowText = false, family?: 4 | 6, mutation?: { method: 'POST' | 'PUT' | 'DELETE'; body?: string; contentType?: string }): Promise<unknown> {
  const url = new URL(path, origin)
  if (key !== undefined) url.searchParams.set('key', key)
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value)
  let timer: ReturnType<typeof setTimeout> | undefined
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const deadline = Date.now() + timeout
    const req = request(url, { method: mutation?.method ?? 'GET', ...(family ? { family } : {}), ...(mutation?.contentType ? { headers: { 'Content-Type': mutation.contentType } } : {}) }, response => {
      if (response.statusCode !== 200) {
        const code = response.statusCode === 404 ? 'NOT_FOUND' : response.statusCode === 429 ? 'RATE_LIMITED' : 'UPSTREAM_ERROR'
        const retry = response.headers['retry-after']
        const retryWait = typeof retry === 'string'
          ? /^\d+$/.test(retry) ? Number(retry) : Math.ceil((Date.parse(retry) - Date.now()) / 1000)
          : NaN
        const retryAfterSeconds = Number.isFinite(retryWait) ? Math.max(0, retryWait) : undefined
        const chunks: Buffer[] = []
        let size = 0
        const fail = (complete = false) => {
          const text = complete ? Buffer.concat(chunks).toString('utf8').trim() : ''
          let reason: unknown = text
          try { const parsed: unknown = JSON.parse(text); reason = parsed && typeof parsed === 'object' && 'error' in parsed ? parsed.error : '' } catch { /* Plain text response. */ }
          const safe = typeof reason === 'string' ? String(cleanUpstream(clean(reason, key || '\u0000'))) : ''
          response.destroy()
          req.destroy()
          reject(new ToolError(code, `Request to ${url.hostname} failed with HTTP ${response.statusCode ?? 0}${safe ? `: ${safe}` : ''}`, 'Check access and retry later', retryAfterSeconds))
        }
        response.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 65536) fail(); else chunks.push(chunk) })
        response.on('end', () => { fail(true) })
        response.on('error', () => { fail() })
        clearTimeout(timer)
        timer = setTimeout(fail, Math.max(0, deadline - Date.now()))
        return
      }
      const chunks: Buffer[] = []
      let size = 0
      response.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > maxBytes) req.destroy(new ToolError('LIMIT_REACHED', 'The service response exceeds the byte limit', 'Narrow the selection'))
        else chunks.push(chunk)
      })
      response.on('end', () => { resolve(Buffer.concat(chunks)) })
      response.on('error', reject)
    })
    timer = setTimeout(() => { req.destroy(new Error('timeout')) }, timeout)
    req.on('error', reject)
    req.end(mutation?.body)
  }).finally(() => { clearTimeout(timer) }).catch((error: unknown) => {
    if (error instanceof ToolError) throw error
    throw new ToolError('UPSTREAM_ERROR', 'Request could not be completed', 'Check connectivity and retry later')
  })
  let raw: unknown
  try { raw = JSON.parse(bytes.toString('utf8')) } catch {
    if (!allowText) throw new ToolError('INVALID_RESPONSE', 'Invalid JSON response', 'Retry later or inspect service status')
    raw = bytes.toString('utf8').trim()
  }
  return raw
}

export async function read(origin: string, path: '/api-info' | '/account/profile', key: string): Promise<unknown> {
  const raw = await requestJson(origin, path, key, {}, 1024 * 1024, 10000)
  const result = (path === '/api-info' ? info : account).safeParse(raw)
  if (!result.success) throw new ToolError('INVALID_RESPONSE', 'Invalid account response', 'Retry later or inspect service status')
  return result.data
}
