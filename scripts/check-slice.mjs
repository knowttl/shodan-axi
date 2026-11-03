import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'

const args = process.argv.slice(2)
const options = new Map()
for (let index = 0; index < args.length; index++) {
  const flag = args[index]
  if (!['--id', '--paths', '--offline', '--with-dependencies'].includes(flag) || options.has(flag)) {
    console.error('Invalid or repeated slice option')
    process.exit(2)
  }
  if (flag === '--offline' || flag === '--with-dependencies') options.set(flag, true)
  else options.set(flag, args[++index])
}
const paths = typeof options.get('--paths') === 'string' ? options.get('--paths').split(',') : []
if (options.get('--id') !== 'B1.1' || !options.has('--offline') || !paths.length || new Set(paths).size !== paths.length || paths.some(path => !['native', 'artium'].includes(path))) {
  console.error('Select B1.1, --offline and at least one valid path')
  process.exit(2)
}
const types = spawnSync(process.execPath, ['--test', 'tests/types.test.mjs'], { stdio: 'inherit' })
let passed = types.status === 0 ? 1 : 0
let failed = types.status === 0 ? 0 : 1
let pending = 0
for (const path of paths) {
  const file = path === 'native' ? 'tests/account.test.mjs' : 'tests/artium.test.mjs'
  if (!existsSync(file) || (path === 'artium' && (!process.env.ARTIUM_FIXTURE_ROOT || !process.env.ARTIUM_FIXTURE_MANIFEST))) {
    console.error(`${path}: pending`)
    pending++
    continue
  }
  const result = spawnSync(process.execPath, ['--test', file, ...(path === 'native' ? ['tests/private-file.test.mjs', 'tests/interruption.test.mjs'] : [])], { stdio: 'inherit' })
  if (result.status === 0) passed++
  else failed++
}
console.error(`slice B1.1: passed ${passed}, failed ${failed}, pending ${pending}, skipped 0`)
if (process.platform !== 'win32') console.error('Windows platform verification: pending')
if (failed || pending) process.exit(1)
