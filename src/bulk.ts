import { z } from 'zod'
import { ToolError } from './errors.js'
import { requestJson } from './vendor.js'

type Flags = Map<string, string | boolean>
const datasets = z.array(z.object({ name: z.string(), description: z.string(), scope: z.string().optional() }))
const files = z.array(z.object({ name: z.string(), size: z.number().int().nonnegative(), sha1: z.string().regex(/^[a-fA-F0-9]{40}$/).optional(), timestamp: z.number().optional(), url: z.string().url() }))
const invalid = (message: string): never => { throw new ToolError('INVALID_INPUT', message, 'Run data list --help') }

export function validateDataList(words: string[], flags: Flags): string | undefined {
  for (const flag of flags.keys()) if (!['--json', '--output', '--help', '--config', '--profile', '--dataset'].includes(flag)) invalid(`Flag ${flag} is not available for data list`)
  if (words.length !== 2) invalid('Invalid data list arguments')
  const dataset = flags.get('--dataset')
  if (dataset !== undefined && (typeof dataset !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(dataset) || dataset === '.' || dataset === '..')) invalid('Invalid dataset name')
  return typeof dataset === 'string' ? dataset : undefined
}

export async function listData(origin: string, key: string, dataset: string | undefined): Promise<unknown> {
  const response = await requestJson(origin, dataset ? `/shodan/data/${encodeURIComponent(dataset)}` : '/shodan/data', key)
  if (!dataset) {
    const result = datasets.safeParse(response)
    if (!result.success) throw new ToolError('INVALID_RESPONSE', 'Invalid dataset listing', 'Inspect the service response')
    return { items: result.data, count: result.data.length }
  }
  const result = files.safeParse(response)
  if (!result.success) throw new ToolError('INVALID_RESPONSE', 'Invalid dataset file listing', 'Inspect the service response')
  return { items: result.data.map(item => ({ name: item.name, size: item.size, ...(item.sha1 === undefined ? {} : { sha1: item.sha1 }), ...(item.timestamp === undefined ? {} : { timestamp: item.timestamp }) })), count: result.data.length }
}

// No storage origins have yet been reviewed for production use.
export const storageOrigins: readonly string[] = Object.freeze([])
