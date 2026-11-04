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
const id = options.get('--id')
if (!['B1.1', 'B2.1', 'B2.2', 'B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) || !options.has('--offline') || !paths.length || new Set(paths).size !== paths.length || paths.some(path => !['native', 'artium'].includes(path))) {
  console.error('Select a supported slice, --offline and at least one valid path')
  process.exit(2)
}
const types = spawnSync(process.execPath, ['--test', 'tests/types.test.mjs'], { stdio: 'inherit' })
let passed = types.status === 0 ? 1 : 0
let failed = types.status === 0 ? 0 : 1
let pending = 0
for (const path of paths) {
  const tests = []
  if (id === 'B1.1' || options.has('--with-dependencies')) tests.push(...(path === 'native'
    ? ['tests/account.test.mjs', 'tests/credentials.test.mjs', 'tests/private-file.test.mjs', 'tests/interruption.test.mjs'] : ['tests/artium.test.mjs']))
  if (id === 'B2.1' || (['B2.2', 'B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    const test = path === 'native' ? 'tests/investigation.test.mjs' : 'tests/artium.test.mjs'
    if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B2.2' || (['B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    const test = path === 'native' ? 'tests/history.test.mjs' : 'tests/artium.test.mjs'
    if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.1' || (['B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/monitor-read.test.mjs', 'tests/monitor-write.test.mjs', 'tests/tls.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.2' || (['B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/organization.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.3' || (['B3.4', 'B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/scan.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.4' || (['B4.1', 'B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/geonet.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B4.1' || (['B4.2', 'B5.1'].includes(id) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/evidence.test.mjs', 'tests/alert-evidence.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B4.2' || (id === 'B5.1' && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/bulk.test.mjs', 'tests/bulk-transfer.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B5.1') {
    for (const test of path === 'native' ? ['tests/stream.test.mjs'] : ['tests/artium.test.mjs']) if (!tests.includes(test)) tests.push(test)
  }
  if (!tests.length || tests.some(file => !existsSync(file)) || (path === 'artium' && (!process.env.ARTIUM_FIXTURE_ROOT || !process.env.ARTIUM_FIXTURE_MANIFEST))) {
    console.error(`${path}: pending`)
    pending++
    continue
  }
  const result = spawnSync(process.execPath, ['--test', ...tests], { stdio: 'inherit', env: { ...process.env, SHODAN_TEST_SLICE: id } })
  if (result.status === 0) passed++
  else failed++
}
console.error(`slice ${id}: passed ${passed}, failed ${failed}, pending ${pending}, skipped 0`)
if (process.platform !== 'win32') console.error('Windows platform verification: pending')
if (failed || pending) process.exit(1)
