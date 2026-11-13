import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'

const args = process.argv.slice(2)
const options = new Map<string, string | boolean | undefined>()
for (let index = 0; index < args.length; index++) {
  const flag = args[index]!
  if (!['--id', '--paths', '--offline', '--with-dependencies'].includes(flag) || options.has(flag)) {
    console.error('Invalid or repeated slice option')
    process.exit(2)
  }
  if (flag === '--offline' || flag === '--with-dependencies') options.set(flag, true)
  else options.set(flag, args[++index])
}
const selectedPaths = options.get('--paths')
const paths = typeof selectedPaths === 'string' ? selectedPaths.split(',') : []
const id = options.get('--id')
if (typeof id !== 'string' || !['B1.1', 'B2.1', 'B2.2', 'B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2', 'B6.1'].includes(id) || !options.has('--offline') || !paths.length || new Set(paths).size !== paths.length || paths.some(path => !['native', 'artium'].includes(path))) {
  console.error('Select a supported slice, --offline and at least one valid path')
  process.exit(2)
}
const types = spawnSync(process.execPath, ['--test', 'tests/types.test.ts'], { stdio: 'inherit' })
let passed = types.status === 0 ? 1 : 0
let failed = types.status === 0 ? 0 : 1
let pending = 0
for (const path of paths) {
  const tests: string[] = []
  const dependencyId = id === 'B6.1' && options.has('--with-dependencies') ? 'B5.2' : id
  if (id === 'B6.1' && path === 'native') tests.push('tests/setup.test.ts')
  if (id === 'B1.1' || options.has('--with-dependencies')) tests.push(...(path === 'native'
    ? ['tests/account.test.ts', 'tests/credentials.test.ts', 'tests/private-file.test.ts', 'tests/interruption.test.ts', 'tests/hosted-reads.test.ts'] : ['tests/artium.test.ts']))
  if (id === 'B2.1' || (['B2.2', 'B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    const test = path === 'native' ? 'tests/investigation.test.ts' : 'tests/artium.test.ts'
    if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B2.2' || (['B3.1', 'B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    const test = path === 'native' ? 'tests/history.test.ts' : 'tests/artium.test.ts'
    if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.1' || (['B3.2', 'B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/monitor-read.test.ts', 'tests/monitor-write.test.ts', 'tests/tls.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.2' || (['B3.3', 'B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/organization.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.3' || (['B3.4', 'B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/scan.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B3.4' || (['B4.1', 'B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/geonet.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B4.1' || (['B4.2', 'B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/evidence.test.ts', 'tests/alert-evidence.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B4.2' || (['B5.1', 'B5.2'].includes(dependencyId) && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/bulk.test.ts', 'tests/bulk-transfer.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B5.1' || (dependencyId === 'B5.2' && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/stream.test.ts'] : ['tests/artium.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (id === 'B5.2' || (id === 'B6.1' && options.has('--with-dependencies'))) {
    for (const test of path === 'native' ? ['tests/radar.test.ts', 'tests/hosted-worker.test.ts', 'tests/scan-collect.test.ts'] : ['tests/artium-b5-2.test.ts']) if (!tests.includes(test)) tests.push(test)
  }
  if (!tests.length || tests.some(file => !existsSync(file)) || (path === 'artium' && (!process.env.ARTIUM_FIXTURE_ROOT || !process.env.ARTIUM_FIXTURE_MANIFEST))) {
    console.error(`${path}: pending`)
    pending++
    continue
  }
  const env: NodeJS.ProcessEnv = { ...process.env, SHODAN_TEST_SLICE: id }
  if (id === 'B6.1') delete env.SHODAN_TEST_SLICE
  const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...tests], { stdio: 'inherit', env })
  if (result.status === 0) passed++
  else failed++
}
console.error(`slice ${id}: passed ${passed}, failed ${failed}, pending ${pending}, skipped 0`)
if (process.platform !== 'win32') console.error('Windows platform verification: pending')
if (failed || pending) process.exit(1)
