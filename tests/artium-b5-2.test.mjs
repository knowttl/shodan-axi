import { execFileSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { verifyArtiumPackage } from './artium-package-fixture.mjs'

test('hosted sessions, radar and scan collection use the pinned packaged worker', { timeout: 180000 }, async () => {
  const root = process.env.ARTIUM_FIXTURE_ROOT
  const manifestPath = process.env.ARTIUM_FIXTURE_MANIFEST
  const temporary = await mkdtemp(join(tmpdir(), 'shodan-artium-b5-2-'))
  try {
    const manifest = await verifyArtiumPackage(root, manifestPath, temporary)
    execFileSync(join(root, 'node_modules/.bin/vitest'), ['run', '--project', 'integration', '--no-cache', '--configLoader', 'runner', 'test/integration/shodan-sessions.test.ts'], {
      cwd: root, env: { ...process.env, SHODAN_AXI_PACKAGE_DIR: manifest.installedPackage }, stdio: 'inherit', timeout: 170000,
    })
  } finally { await rm(temporary, { recursive: true, force: true }) }
})
