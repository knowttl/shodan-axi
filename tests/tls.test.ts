import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createTestTls } from './tls-fixture.ts'

test('fake TLS certificate is valid before test startup and covers loopback', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shodan-tls-'))
  try {
    const { certFile } = await createTestTls(root, 'IP:127.0.0.1')
    const certificate = new X509Certificate(await readFile(certFile))
    assert.equal(certificate.checkIP('127.0.0.1'), '127.0.0.1')
    assert.ok(Date.parse(certificate.validFrom) <= Date.now() - 86400000)
    assert.ok(Date.parse(certificate.validTo) > Date.now())
  } finally { await rm(root, { recursive: true, force: true }) }
})
