import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'
import { test } from 'node:test'

test('hosted sessions, radar and scan collection use the pinned packaged worker', { timeout: 180000 }, async () => {
  const root = process.env.ARTIUM_FIXTURE_ROOT
  const manifestPath = process.env.ARTIUM_FIXTURE_MANIFEST
  assert.ok(root && isAbsolute(root) && manifestPath && isAbsolute(manifestPath), 'Set absolute Artium fixture root and manifest paths')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  assert.ok(isAbsolute(manifest.tarball) && isAbsolute(manifest.installedPackage))
  assert.equal(createHash('sha256').update(await readFile(manifest.tarball)).digest('hex'), manifest.sha256)
  assert.equal(execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), manifest.artiumRevision)
  assert.equal(execFileSync('git', ['-C', root, 'status', '--porcelain'], { encoding: 'utf8' }).trim(), '')
  execFileSync(join(root, 'node_modules/.bin/vitest'), ['run', '--project', 'integration', '--no-cache', '--configLoader', 'runner', 'test/integration/shodan-sessions.test.ts'], {
    cwd: root, env: { ...process.env, SHODAN_AXI_PACKAGE_DIR: manifest.installedPackage }, stdio: 'inherit', timeout: 170000,
  })
})
