import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFile } from 'node:fs/promises'
import { withInvestigation } from './investigation-fixture.ts'

type Schema = { type?: string; additionalProperties?: boolean | Schema; properties?: Record<string, Schema>; propertyNames?: Schema; items?: Schema; anyOf?: Schema[] }

test('hosted reads drop unknown and credential-like vendor fields', { timeout: 60000 }, async () => {
  await withInvestigation(async ({ run, setMode }) => {
    setMode('hosted-injection')
    for (const args of [
      ['host', '192.0.2.7'], ['count', 'port:443', '--facets', 'port:2'],
      ['stats', 'port:443', '--facets', 'port:2'], ['search', 'tokens', 'port:443'],
      ['dns', 'resolve', 'example.test'], ['dns', 'reverse', '192.0.2.7'],
      ['tools', 'headers'], ['internetdb', 'host', '192.0.2.7'],
      ['query', 'list'], ['query', 'search', 'Synthetic TLS'], ['query', 'tags'],
      ['alert', 'info', 'alert-a'], ['alert', 'list'], ['alert', 'triggers'],
      ['notifier', 'list'], ['notifier', 'providers'], ['notifier', 'get', 'notifier-a'],
      ['org', 'info'], ['scan', 'protocols'], ['scan', 'list'], ['scan', 'status', 'scan-a'],
    ]) {
      const result = await run(args)
      assert.equal(result.code, 0, `${args.join(' ')}: ${result.stdout}`)
      assert.doesNotMatch(result.stdout, /injected-private|unknown_vendor|access_token/, args.join(' '))
    }
    assert.deepEqual((await run(['scan', 'protocols'])).body, { https: 'Synthetic HTTPS module' })
    setMode('bad-protocol')
    assert.equal((await run(['scan', 'protocols'])).body.error, 'INVALID_RESPONSE')
  })
})

test('published hosted read contracts exclude unconstrained object output', async () => {
  const { commands } = JSON.parse(await readFile(new URL('../command-inventory.json', import.meta.url), 'utf8'))
  const inspect = (schema: Schema) => {
    assert.notDeepEqual(schema, {})
    if (schema.type === 'object') {
      assert.notEqual(schema.additionalProperties, true)
      assert.ok(schema.properties || schema.propertyNames)
      for (const child of Object.values(schema.properties ?? {})) inspect(child)
      if (typeof schema.additionalProperties === 'object') inspect(schema.additionalProperties)
    }
    if (schema.items) inspect(schema.items)
    for (const child of schema.anyOf ?? []) inspect(child)
  }
  for (const command of commands.filter((item: { operation?: string; effect: string; cost?: string }) => item.operation && item.effect === 'read' && item.cost !== 'query' && item.cost !== 'unknown')) {
    assert.ok(command.outputSchema, command.command)
    inspect(command.outputSchema)
  }
  const protocols = commands.find((item: { command: string }) => item.command === 'scan protocols').outputSchema
  assert.equal(protocols.additionalProperties, false)
  assert.equal(protocols.properties.https.type, 'string')
  assert.equal(Object.hasOwn(protocols.properties, 'access_token'), false)
})
