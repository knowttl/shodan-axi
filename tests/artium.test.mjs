import { execFileSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { verifyArtiumPackage } from './artium-package-fixture.mjs'
import { createTestTls } from './tls-fixture.mjs'

test('hosted reads use the pinned package against an isolated fake service', { timeout: 180000 }, async () => {
  const root = process.env.ARTIUM_FIXTURE_ROOT
  const image = process.env.ARTIUM_TEST_IMAGE ?? 'artium-test-node24'
  if (!root) throw new Error('Set ARTIUM_FIXTURE_ROOT')
  const temporary = await mkdtemp(join(tmpdir(), 'shodan-hosted-fixture-'))
  try {
    const manifest = await verifyArtiumPackage(root, process.env.ARTIUM_FIXTURE_MANIFEST, temporary)
    const tlsDirectory = join(temporary, 'tls')
    await mkdir(tlsDirectory, { mode: 0o755 })
    const { keyFile } = await createTestTls(tlsDirectory, 'DNS:localhost,DNS:api.shodan.io')
    await chmod(keyFile, 0o644)
    const installedPackage = '/tools/node_modules/@knowttl/shodan-axi'
    const containerManifest = { ...manifest, installedPackage, toolExecutable: `${installedPackage}/bin/shodan-axi.js`,
      serverModule: '/artium/dist/src/server/app.js', clientExecutable: '/artium/dist/cli/artium-axi.mjs' }
    const source = fileURLToPath(new URL('../', import.meta.url))
    execFileSync('docker', ['run', '--rm', '--pull', 'never', '--network', 'none', '--user', '65534:65534',
      '--mount', `type=bind,src=${source},dst=/source,readonly`, '--mount', `type=bind,src=${root},dst=/artium,readonly`,
      '--mount', `type=bind,src=${dirname(dirname(manifest.installedPackage))},dst=/tools/node_modules,readonly`,
      '--mount', `type=bind,src=${tlsDirectory},dst=/test-tls,readonly`,
      '--workdir', '/source', '--env', 'ARTIUM_FIXTURE_ROOT=/artium', '--env', 'SHODAN_TEST_SLICE', '--env', `SHODAN_HOSTED_MANIFEST=${JSON.stringify(containerManifest)}`,
      ...(process.env.SHODAN_TEST_SLICE === 'B1.1' ? ['--env', 'ARTIUM_EXPECT_B1_1_READS=1'] : []),
      image, 'node', '--test', 'tests/artium-cases.mjs'], { stdio: 'inherit', timeout: 170000 })
  } finally { await rm(temporary, { recursive: true, force: true }) }
})
