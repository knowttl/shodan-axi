import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import type { ChildProcessByStdio } from 'node:child_process'
import type { Readable } from 'node:stream'

test('interrupted profile update preserves the previous profile and removes its temporary file', { timeout: 20000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-interrupt-'))
  let child: ChildProcessByStdio<null, Readable, Readable> | undefined
  let socket: WebSocket | undefined
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', root, '--json'], { encoding: 'utf8' }))
    execFileSync('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', root, join(root, packed[0].filename)], { stdio: 'ignore' })
    const packageRoot = join(root, 'node_modules', '@knowttl', 'shodan-axi')
    const source = await readFile(join(packageRoot, 'dist/private-file.js'), 'utf8')
    const line = source.split('\n').findIndex(value => value.includes('await file.sync()'))
    const config = join(root, 'config.json')
    const previous = JSON.stringify({ version: 1, defaultProfile: 'old', profiles: { old: { auth: 'api-key', apiKey: { env: 'OLD_KEY' } } } })
    await writeFile(config, previous, { mode: 0o600 })
    child = spawn(process.execPath, ['--inspect-brk=0', join(packageRoot, 'bin/shodan-axi.js'), 'profile', 'set', 'new', '--env', 'NEW_KEY', '--config', config], {
      stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: undefined, SHODAN_AXI_READ_ONLY: 'true' },
    })
    const closed = once(child, 'close')
    let stderr = ''
    let stdout = ''
    child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk })
    const endpoint = await new Promise<string>((resolve, reject) => {
      child!.stderr.setEncoding('utf8').on('data', chunk => {
        stderr += chunk
        const match = /ws:\/\/[^\s]+/.exec(stderr)
        if (match) resolve(match[0])
      })
      child!.once('error', reject)
      child!.once('exit', () => { reject(new Error(`Debugger did not start: ${stderr}`)) })
    })
    socket = new WebSocket(endpoint)
    await once(socket, 'open')
    let id = 0
    type DebuggerMessage = { id?: number; method?: string; params?: unknown; result?: unknown; error?: { message: string } }
    const replies = new Map<number, (message: DebuggerMessage) => void>()
    const pauses: unknown[] = []
    const waiters: ((value: unknown) => void)[] = []
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data)
      if (message.id && replies.has(message.id)) { replies.get(message.id)!(message); replies.delete(message.id) }
      if (message.method === 'Debugger.paused') {
        const waiter = waiters.shift()
        if (waiter) waiter(message.params)
        else pauses.push(message.params)
      }
    })
    const send = (method: string, params: Record<string, unknown> = {}) => new Promise((resolve, reject) => {
      const current = ++id
      replies.set(current, message => { if (message.error) reject(new Error(message.error.message)); else resolve(message.result) })
      socket!.send(JSON.stringify({ id: current, method, params }))
    })
    const paused = () => pauses.length ? Promise.resolve(pauses.shift()) : new Promise(resolve => waiters.push(resolve))
    await send('Debugger.enable')
    await send('Debugger.setBreakpointByUrl', { lineNumber: line, urlRegex: '/dist/private-file\\.js$' })
    await send('Runtime.runIfWaitingForDebugger')
    await paused()
    await send('Debugger.resume')
    await paused()
    child.kill('SIGTERM')
    await send('Debugger.resume')
    socket.close()
    const [code] = await closed
    assert.equal(code, 1)
    assert.match(stdout, /INTERRUPTED/)
    assert.equal(await readFile(config, 'utf8'), previous)
    assert.deepEqual((await readdir(root)).filter(name => name.startsWith('config.json.') && name.endsWith('.tmp')), [])
  } finally {
    socket?.close()
    if (child?.exitCode === null) child.kill('SIGKILL')
    await rm(root, { recursive: true, force: true })
  }
})
