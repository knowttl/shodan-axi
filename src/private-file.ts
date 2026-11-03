import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises'
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

export async function readPrivate(path: string, secret: boolean, options: Options = {}): Promise<string> {
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
    return bytes.toString('utf8')
  } finally { await file.close() }
}

export async function writePrivate(path: string, content: string, options: Options = {}): Promise<void> {
  const platform = options.platform ?? process.platform
  const acl = options.acl ?? windowsAcl
  if (!isAbsolute(path) || (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(path))) insecure()
  const directory = dirname(path)
  const first = await mkdir(directory, platform === 'win32' ? { recursive: true } : { recursive: true, mode: 0o700 })
  await direct(directory, platform)
  const parent = await lstat(directory)
  if (!parent.isDirectory()) insecure()
  if (platform === 'win32') {
    let current = directory
    for (;;) {
      try { acl(current, 'restrict', true) } catch { insecure() }
      if (!first || current.toLowerCase() === first.toLowerCase()) break
      current = dirname(current)
    }
  } else {
    if (parent.uid !== process.getuid?.() || (parent.mode & 0o022) !== 0) insecure()
    await chmod(directory, 0o700)
  }
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
