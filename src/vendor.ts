import { request } from 'node:https'
import { z } from 'zod'
import { ToolError } from './errors.js'

const info = z.object({ plan: z.string(), query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number(), usage_limits: z.object({ query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number() }).passthrough() }).passthrough()
const account = z.object({ member: z.boolean(), credits: z.number(), display_name: z.string().nullable(), created: z.string() }).passthrough()

export async function requestJson(origin: string, path: string, key: string | undefined, query: Readonly<Record<string, string>> = {}, maxBytes = 10 * 1024 * 1024, timeout = 30000, allowText = false, family?: 4 | 6, mutation?: { method: 'POST' | 'PUT' | 'DELETE'; body?: string; contentType?: string }): Promise<unknown> {
  const url = new URL(path, origin)
  if (key !== undefined) url.searchParams.set('key', key)
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value)
  let timer: ReturnType<typeof setTimeout> | undefined
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const req = request(url, { method: mutation?.method ?? 'GET', ...(family ? { family } : {}), ...(mutation?.contentType ? { headers: { 'Content-Type': mutation.contentType } } : {}) }, response => {
      if (response.statusCode !== 200) {
        response.destroy()
        req.destroy()
        const code = response.statusCode === 404 ? 'NOT_FOUND' : response.statusCode === 429 ? 'RATE_LIMITED' : 'UPSTREAM_ERROR'
        reject(new ToolError(code, `Request failed with HTTP ${response.statusCode ?? 0}`, 'Check access and retry later'))
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
