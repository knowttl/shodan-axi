import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, realpath } from 'node:fs/promises'
import { isAbsolute, join, resolve } from 'node:path'

const hash = (value: Buffer) => createHash('sha256').update(value).digest('hex')

async function files(directory: string, prefix = ''): Promise<string[]> {
  const result: string[] = []
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const name = join(prefix, entry.name)
    if (entry.isDirectory()) result.push(...await files(directory, name))
    else if (entry.isFile()) result.push(name)
    else throw new Error('Package contains a non-file entry')
  }
  return result.sort()
}

export async function verifyArtiumPackage(fixtureRoot: string | undefined, manifestPath: string | undefined, temporary: string) {
  assert.ok(fixtureRoot && isAbsolute(fixtureRoot) && manifestPath && isAbsolute(manifestPath), 'Set absolute Artium fixture root and manifest paths')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  for (const key of ['tarball', 'installedPackage', 'serverModule', 'clientExecutable', 'toolExecutable']) {
    assert.ok(isAbsolute(manifest[key]), `Manifest requires an absolute ${key}`)
  }
  assert.equal(hash(await readFile(manifest.tarball)), manifest.sha256)
  assert.equal(execFileSync('git', ['-C', fixtureRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), manifest.artiumRevision)
  assert.equal(execFileSync('git', ['-C', fixtureRoot, 'status', '--porcelain'], { encoding: 'utf8' }).trim(), '', 'Artium fixture source must match its committed revision')
  assert.equal(await realpath(manifest.installedPackage), resolve(manifest.installedPackage), 'Host package must not be a symlink')
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', temporary, '--json'], { encoding: 'utf8' }))
  assert.equal(hash(await readFile(join(temporary, packed[0].filename))), manifest.sha256, 'Current tarball differs from the host package')
  const extracted = join(temporary, 'extract')
  await mkdir(extracted)
  execFileSync('tar', ['-xzf', manifest.tarball, '-C', extracted])
  const packageRoot = join(extracted, 'package')
  const packageFiles = await files(packageRoot)
  assert.deepEqual(await files(manifest.installedPackage), packageFiles)
  for (const file of packageFiles) assert.deepEqual(await readFile(join(packageRoot, file)), await readFile(join(manifest.installedPackage, file)), file)
  assert.equal(await realpath(manifest.toolExecutable), await realpath(join(manifest.installedPackage, 'bin/shodan-axi.js')))
  assert.equal(await realpath(manifest.serverModule), await realpath(join(fixtureRoot, 'dist/src/server/app.js')))
  assert.equal(await realpath(manifest.clientExecutable), await realpath(join(fixtureRoot, 'dist/cli/artium-axi.mjs')))
  const inventory = JSON.parse(await readFile(join(fixtureRoot, 'tools/inventories/shodan-axi.json'), 'utf8'))
  assert.deepEqual(JSON.parse(await readFile(join(fixtureRoot, 'dist/tools/inventories/shodan-axi.json'), 'utf8')), inventory)
  for (const item of inventory.sources) assert.equal(hash(await readFile(join(manifest.installedPackage, item.path))), item.sha256, item.path)
  return manifest
}
