import { randomUUID } from 'node:crypto'
import { lstat, open, readdir, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { ToolError } from './errors.js'
import { preparePrivateDirectory } from './private-file.js'
import { windowsAcl } from './windows-acl.js'

export class StreamStorage {
  private file: Awaited<ReturnType<typeof open>> | undefined
  private day = ''
  private bytes = 0
  private files: string[] = []
  constructor(private readonly directory: string, private readonly maxFileBytes: number, private readonly retention: number, private readonly level: number) {}

  async write(value: unknown): Promise<void> {
    const data = gzipSync(`${JSON.stringify(value)}\n`, { level: this.level })
    if (data.length > this.maxFileBytes) throw new ToolError('LIMIT_REACHED', 'Stream record exceeds the file limit', 'Increase the file bound')
    const day = new Date().toISOString().slice(0, 10)
    if (!this.file || this.day !== day || this.bytes + data.length > this.maxFileBytes) {
      await this.file?.close()
      await preparePrivateDirectory(this.directory)
      const name = `stream-${day}-${randomUUID()}.jsonl.gz`
      const path = join(this.directory, name)
      this.file = await open(path, 'wx', 0o600)
      if (process.platform === 'win32') windowsAcl(path, 'restrict', false)
      this.files.push(name); this.day = day; this.bytes = 0
      const names = (await readdir(this.directory)).filter(item => /^stream-\d{4}-\d{2}-\d{2}-[0-9a-f-]{36}\.jsonl\.gz$/.test(item))
      const entries = await Promise.all(names.map(async item => ({ name: item, stat: await lstat(join(this.directory, item)) })))
      const existing = entries.filter(item => item.stat.isFile() && (process.platform === 'win32' || item.stat.uid === process.getuid?.())).sort((a, b) => a.stat.mtimeMs - b.stat.mtimeMs).map(item => item.name)
      for (const old of existing.filter(item => !this.files.includes(item)).slice(0, Math.max(0, existing.length - this.retention))) await unlink(join(this.directory, old))
      while (this.files.length > this.retention) { const old = this.files.shift(); if (old) await unlink(join(this.directory, old)) }
    }
    await this.file.writeFile(data); this.bytes += data.length
  }

  async close(): Promise<void> { await this.file?.close(); this.file = undefined }
}
