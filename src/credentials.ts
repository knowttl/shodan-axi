import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { z } from 'zod'
import { ToolError } from './errors.js'
import { readPrivate, writePrivate } from './private-file.js'

const absolutePath = (path: string): boolean => isAbsolute(path) && (process.platform !== 'win32' || /^[A-Za-z]:[\\/]/.test(path))
const ref = z.union([z.strictObject({ env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/) }), z.strictObject({ file: z.string().refine(absolutePath) })])
const origin = z.string().refine(value => {
  try { const url = new URL(value); return url.protocol === 'https:' && url.origin === value && !url.username && !url.password } catch { return false }
})
const profile = z.discriminatedUnion('auth', [
  z.strictObject({ auth: z.literal('api-key'), origin: origin.default('https://api.shodan.io'), streamOrigin: origin.optional(), apiKey: ref.default({ env: 'SHODAN_AXI_API_KEY' }) }),
  z.strictObject({ auth: z.literal('none'), origin: origin.default('https://api.shodan.io'), streamOrigin: origin.optional() }),
])
const name = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/)
const envelope = z.strictObject({ version: z.literal(1), defaultProfile: name.optional(), profiles: z.record(name, profile) })
type Profile = z.output<typeof profile>
type Envelope = z.output<typeof envelope>
export type Selection = { name: string; source: string; profile: Profile }

function invalid(): never { throw new ToolError('CONFIG_INVALID', 'Invalid profile configuration', 'Use a valid profile with a SecretRef') }

export function configPath(option?: string): string {
  const base = process.platform === 'win32' ? process.env.APPDATA : process.env.XDG_CONFIG_HOME
  const root = base && isAbsolute(base) ? base : process.platform === 'win32' ? join(homedir(), 'AppData', 'Roaming') : join(homedir(), '.config')
  const path = option ?? process.env.SHODAN_AXI_CONFIG ?? join(root, 'shodan-axi', 'config.json')
  if (!absolutePath(path)) invalid()
  return path
}

export async function readConfig(path: string, privateFile = false): Promise<Envelope> {
  let content: string
  try { content = await readPrivate(path, privateFile) } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return { version: 1, profiles: {} }
    throw error
  }
  let data: unknown
  try { data = JSON.parse(content) } catch { invalid() }
  const parsed = envelope.safeParse(data)
  if (!parsed.success) invalid()
  return parsed.data
}

export async function select(path: string, requested?: string): Promise<Selection> {
  const selected = requested ?? process.env.SHODAN_AXI_PROFILE
  if (selected && !name.safeParse(selected).success) invalid()
  if (!selected) {
    const key = process.env.SHODAN_AXI_API_KEY
    const auth = process.env.SHODAN_AXI_AUTH ?? (key ? 'api-key' : undefined)
    const endpoint = process.env.SHODAN_AXI_ORIGIN
    const stream = process.env.SHODAN_AXI_STREAM_ORIGIN
    if (auth || key || endpoint || stream) {
      if (!auth || (auth === 'api-key' && !key) || (auth === 'none' && key)) invalid()
      const result = profile.safeParse({ auth, ...(endpoint ? { origin: endpoint } : {}), ...(stream ? { streamOrigin: stream } : {}), ...(auth === 'api-key' ? { apiKey: { env: 'SHODAN_AXI_API_KEY' } } : {}) })
      if (!result.success) invalid()
      return { name: 'environment', source: 'environment', profile: result.data }
    }
  }
  const config = await readConfig(path)
  const names = Object.keys(config.profiles)
  const chosen = selected ?? config.defaultProfile ?? (names.length === 1 ? names[0] : undefined)
  if (!chosen) throw new ToolError(names.length ? 'PROFILE_AMBIGUOUS' : 'AUTH_REQUIRED', 'No profile selected', 'Configure a profile with an API key reference')
  const value = config.profiles[chosen]
  if (!value) throw new ToolError('PROFILE_NOT_FOUND', 'Selected profile was not found', 'Run profile list to see available profiles')
  return { name: chosen, source: 'file', profile: value }
}

export async function secret(selection: Selection): Promise<string> {
  if (selection.profile.auth !== 'api-key') throw new ToolError('AUTH_REQUIRED', 'This command requires an API key', 'Select an API-key profile')
  const reference = selection.profile.apiKey
  const value = 'env' in reference ? process.env[reference.env] : (await readPrivate(reference.file, true)).replace(/^\uFEFF/, '').trimEnd()
  if (!value) throw new ToolError('AUTH_REQUIRED', 'The API key reference is empty', 'Set the referenced environment variable or protected file')
  return value
}

export async function putProfile(path: string, profileName: string, reference: unknown, makeDefault = false): Promise<void> {
  if (!name.safeParse(profileName).success) invalid()
  const config = await readConfig(path)
  const parsed = profile.safeParse({ ...config.profiles[profileName], auth: 'api-key', apiKey: reference })
  if (!parsed.success) invalid()
  config.profiles[profileName] = parsed.data
  if (makeDefault || !config.defaultProfile) config.defaultProfile = profileName
  await writePrivate(path, `${JSON.stringify(config, null, 2)}\n`)
}
