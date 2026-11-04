import { constants } from 'node:fs'
import { lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { ToolError } from './errors.js'
import { windowsAcl, type WindowsAcl } from './windows-acl.js'

type Options = { platform?: NodeJS.Platform; acl?: WindowsAcl }

function insecure(): never {
  throw new ToolError('CONFIG_INSECURE', 'The configuration or secret file is not private', 'Use an owned, direct path with private permissions')
}

async function direct(path: string, platform: NodeJS.Platform): Promise<void> {
  if (!isAbsolute(path) || (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(path)) || (await lstat(path)).isSymbolicLink()) insecure()
  const actual = await realpath(path)
  if (platform === 'win32' ? actual.toLowerCase() !== resolve(path).toLowerCase() : actual !== resolve(path)) insecure()
}

export async function readPrivateBytes(path: string, secret: boolean, options: Options = {}): Promise<Buffer> {
  const platform = options.platform ?? process.platform
  const acl = options.acl ?? windowsAcl
  await direct(path, platform)
  const before = await lstat(path)
  if (!before.isFile()) insecure()
  if (platform === 'win32') {
    try { acl(path, 'verify', false) } catch { insecure() }
  } else if (before.uid !== process.getuid?.() || (before.mode & (secret ? 0o077 : 0o022)) !== 0) insecure()
  const file = await open(path, constants.O_RDONLY | (platform === 'win32' ? 0 : constants.O_NOFOLLOW))
  try {
    const stat = await file.stat()
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.size > 1024 * 1024) insecure()
    if (platform !== 'win32' && (stat.uid !== process.getuid?.() || (stat.mode & (secret ? 0o077 : 0o022)) !== 0)) insecure()
    const bytes = await file.readFile()
    if (bytes.length > 1024 * 1024) insecure()
    return bytes
  } finally { await file.close() }
}

export async function readPrivate(path: string, secret: boolean, options: Options = {}): Promise<string> {
  return (await readPrivateBytes(path, secret, options)).toString('utf8')
}

export async function preparePrivateDirectory(directory: string, options: Options = {}): Promise<void> {
  const platform = options.platform ?? process.platform
  const acl = options.acl ?? windowsAcl
  if (!isAbsolute(directory) || (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(directory))) insecure()
  const first = await mkdir(directory, platform === 'win32' ? { recursive: true } : { recursive: true, mode: 0o700 })
  await direct(directory, platform)
  const parent = await lstat(directory)
  if (!parent.isDirectory()) insecure()
  if (platform === 'win32' && first) {
    let current = directory
    for (;;) {
      try { acl(current, 'restrict', true) } catch { insecure() }
      if (current.toLowerCase() === first.toLowerCase()) break
      current = dirname(current)
    }
  } else if (platform !== 'win32') {
    if (parent.uid !== process.getuid?.() || (parent.mode & 0o022) !== 0) insecure()
  }
}

export async function writePrivate(path: string, content: string | Uint8Array, options: Options = {}): Promise<void> {
  const platform = options.platform ?? process.platform
  const acl = options.acl ?? windowsAcl
  if (!isAbsolute(path) || (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(path))) insecure()
  const directory = dirname(path)
  await preparePrivateDirectory(directory, options)
  try { await readPrivate(path, false, options) } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error
  }
  const temporary = `${path}.${randomUUID()}.tmp`
  let interrupted = false
  const interrupt = (): void => { interrupted = true }
  process.on('SIGINT', interrupt)
  process.on('SIGTERM', interrupt)
  let file: Awaited<ReturnType<typeof open>> | undefined
  try {
    file = await open(temporary, 'wx', platform === 'win32' ? undefined : 0o600)
    if (platform === 'win32') {
      try { acl(temporary, 'restrict', false) } catch { insecure() }
    }
    await file.writeFile(content)
    await file.sync()
    await file.close()
    for (let attempt = 0; ; attempt++) {
      if (interrupted) throw new ToolError('INTERRUPTED', 'Profile update was interrupted', 'Retry the update')
      try { await rename(temporary, path); break } catch (error) {
        if (platform !== 'win32' || !(error instanceof Error) || !('code' in error) || !['EPERM', 'EBUSY', 'EACCES'].includes(String(error.code)) || attempt === 5) throw error
        await new Promise(resolve => setTimeout(resolve, 25 * 2 ** attempt))
      }
    }
    if (platform !== 'win32') {
      const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY)
      try { await dir.sync() } finally { await dir.close() }
    }
  } finally {
    await file?.close()
    await rm(temporary, { force: true })
    process.removeListener('SIGINT', interrupt)
    process.removeListener('SIGTERM', interrupt)
  }
}

export async function appendPrivate(path: string, content: string): Promise<void> {
  const directory = dirname(path)
  await direct(directory, process.platform)
  const parent = await lstat(directory)
  if (!parent.isDirectory()) insecure()
  if (process.platform === 'win32') windowsAcl(directory, 'verify', true)
  else if (parent.uid !== process.getuid?.() || (parent.mode & 0o077) !== 0) insecure()
  const noFollow = process.platform === 'win32' ? 0 : constants.O_NOFOLLOW
  let file: Awaited<ReturnType<typeof open>>
  let created = false
  let existing: Awaited<ReturnType<typeof lstat>> | undefined
  try { file = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_EXCL | noFollow, 0o600); created = true }
  catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error
    await direct(path, process.platform)
    existing = await lstat(path)
    if (!existing.isFile() || existing.isSymbolicLink()) insecure()
    file = await open(path, constants.O_WRONLY | constants.O_APPEND | noFollow)
  }
  try {
    if (process.platform === 'win32') windowsAcl(path, created ? 'restrict' : 'verify', false)
    const stat = await file.stat()
    if (!stat.isFile() || (existing && (stat.dev !== existing.dev || stat.ino !== existing.ino)) || (process.platform !== 'win32' && (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0))) insecure()
    await file.writeFile(content)
    await file.sync()
  } finally { await file.close() }
  if (created && process.platform !== 'win32') {
    const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY)
    try { await dir.sync() } finally { await dir.close() }
  }
}
