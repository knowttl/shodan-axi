import { request } from 'node:https'
import { z } from 'zod'
import { ToolError } from './errors.js'

const info = z.object({ plan: z.string(), query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number(), usage_limits: z.object({ query_credits: z.number(), scan_credits: z.number(), monitored_ips: z.number() }).passthrough() }).passthrough()
const account = z.object({ member: z.boolean(), credits: z.number(), display_name: z.string().nullable(), created: z.string() }).passthrough()

export async function read(origin: string, path: '/api-info' | '/account/profile', key: string): Promise<unknown> {
  const url = new URL(path, origin)
  url.searchParams.set('key', key)
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const req = request(url, { method: 'GET', timeout: 10000 }, response => {
      if (response.statusCode !== 200) {
        response.resume()
        reject(new ToolError('UPSTREAM_ERROR', `Account request failed with HTTP ${response.statusCode ?? 0}`, 'Check account access and retry later'))
        return
      }
      const chunks: Buffer[] = []
      let size = 0
      response.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > 1024 * 1024) req.destroy(new Error('response too large'))
        else chunks.push(chunk)
      })
      response.on('end', () => { resolve(Buffer.concat(chunks)) })
      response.on('error', reject)
    })
    req.on('timeout', () => { req.destroy(new Error('timeout')) })
    req.on('error', reject)
    req.end()
  }).catch((error: unknown) => {
    if (error instanceof ToolError) throw error
    throw new ToolError('UPSTREAM_ERROR', 'Account request could not be completed', 'Check connectivity and retry later')
  })
  let raw: unknown
  try { raw = JSON.parse(bytes.toString('utf8')) } catch { throw new ToolError('INVALID_RESPONSE', 'Invalid account response', 'Retry later or inspect service status') }
  const result = (path === '/api-info' ? info : account).safeParse(raw)
  if (!result.success) throw new ToolError('INVALID_RESPONSE', 'Invalid account response', 'Retry later or inspect service status')
  return result.data
}
