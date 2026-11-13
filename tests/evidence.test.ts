import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, mkdir, readFile, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gzipSync, gunzipSync } from 'node:zlib'
import ExcelJS from 'exceljs'
import jpeg from 'jpeg-js'
import { XMLParser } from 'fast-xml-parser'
import { withInvestigation } from './investigation-fixture.ts'

const rows = [
  { ip_str: '192.0.2.7', port: 443, enabled: false, count: 0, location: { latitude: 49, longitude: -123 } },
  { ip_str: '192.0.2.8', port: 80, enabled: true, count: 1, location: { latitude: 50, longitude: -124 } },
]

test('parse applies every filter and preserves false and zero', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run, calls }) => {
    const input = join(root, 'data.json.gz')
    await writeFile(input, gzipSync(rows.map(row => JSON.stringify(row)).join('\n') + '\n'), { mode: 0o600 })
    const saved = join(root, 'filtered.json.gz')
    const result = await run(['parse', input, '--filters', 'net:192.0.2.0/24', '--filters', 'port:443', '--fields', 'ip_str,enabled,count', '--separator', '|', '--filename', saved], { SHODAN_AXI_CONFIG: join(root, 'missing') })
    assert.deepEqual(result.body.items, [{ ip_str: '192.0.2.7', enabled: false, count: 0 }])
    assert.equal(result.body.display, '192.0.2.7|false|0')
    assert.deepEqual(gunzipSync(await readFile(saved)).toString().trim().split('\n').map(line => JSON.parse(line)), [rows[0]])
    assert.equal((await run(['parse', input, '--filters', 'enabled:false', '--filename', saved])).code, 0)
    assert.equal(gunzipSync(await readFile(saved)).toString().trim().split('\n').length, 2)
    assert.equal(calls.length, 0)
  })
})

test('conversions produce readable CSV, KML, GeoJSON, XLSX and JPEG', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'data.json.gz')
    await writeFile(input, gzipSync(rows.map(row => JSON.stringify(row)).join('\n')), { mode: 0o600 })
    for (const format of ['csv', 'kml', 'geo.json']) assert.equal((await run(['convert', input, format])).code, 0)
    assert.equal((await run(['convert', input, 'xlsx', '--fields', 'ip_str,enabled,count'])).code, 0)
    assert.match(await readFile(join(root, 'data.csv'), 'utf8'), /192\.0\.2\.7,443/)
    const kml = new XMLParser().parse(await readFile(join(root, 'data.kml'), 'utf8'))
    assert.equal(kml.kml.Document.Placemark.length, 2)
    const geo = JSON.parse(await readFile(join(root, 'data.geo.json'), 'utf8'))
    assert.deepEqual(geo.features.map((item: { properties: { ip: string } }) => item.properties.ip), ['192.0.2.7', '192.0.2.8'])
    const workbook = new ExcelJS.Workbook()
    await workbook.xlsx.readFile(join(root, 'data.xlsx'))
    assert.deepEqual(workbook.worksheets.map(sheet => sheet.name), ['Raw Data', 'Summary'])
    assert.equal(workbook.getWorksheet('Raw Data')!.rowCount, 3)
    assert.equal(workbook.getWorksheet('Raw Data')!.getRow(2).getCell(2).value, false)
    assert.equal(workbook.getWorksheet('Raw Data')!.getRow(2).getCell(3).value, 0)
    const image = jpeg.encode({ data: Buffer.alloc(16, 255), width: 2, height: 2 }).data
    const imageInput = join(root, 'screenshot.json')
    await writeFile(imageInput, JSON.stringify({ ...rows[0], opts: { screenshot: { mime: 'image/jpeg', data: image.toString('base64') } } }), { mode: 0o600 })
    const imageDestination = join(root, 'exports', 'screenshots')
    assert.equal((await run(['convert', imageInput, 'images', '--filename', imageDestination])).code, 0)
    const output = await readFile(join(imageDestination, '1.jpg'))
    assert.deepEqual(output, image)
    assert.equal(jpeg.decode(output).width, 2)
  })
})

test('image conversion rejects indirect and writable parents', { timeout: 30000, skip: process.platform === 'win32' }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'empty.json')
    await writeFile(input, '[]', { mode: 0o600 })
    const parent = join(root, 'exports')
    await mkdir(parent, { mode: 0o700 })
    const linked = join(root, 'linked')
    await symlink(parent, linked)
    assert.equal((await run(['convert', input, 'images', '--filename', join(linked, 'screenshots')])).body.error, 'CONFIG_INSECURE')
    await chmod(parent, 0o777)
    assert.equal((await run(['convert', input, 'images', '--filename', join(parent, 'screenshots')])).body.error, 'CONFIG_INSECURE')
    await assert.rejects(readFile(join(parent, 'screenshots')), { code: 'ENOENT' })
  })
})

test('parse rejects oversized compressed saves without replacing prior evidence', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'large.json.gz')
    const data = createHash('shake256', { outputLength: 700 * 1024 }).update('saved evidence fixture').digest('base64')
    await writeFile(input, gzipSync(JSON.stringify({ ip_str: '192.0.2.7', data }) + '\n'), { mode: 0o600 })
    const saved = join(root, 'filtered.json.gz')
    const args = ['--filters', 'ip_str:192.0.2.7', '--fields', 'ip_str', '--filename', saved]
    assert.equal((await run(['parse', input, ...args])).code, 0)
    const prior = await readFile(saved)
    assert.equal((await run(['parse', input, ...args])).body.error, 'INVALID_INPUT')
    assert.deepEqual(await readFile(saved), prior)
    assert.equal((await run(['parse', saved, '--fields', 'ip_str'])).code, 0)
    const fresh = join(root, 'combined.json.gz')
    assert.equal((await run(['parse', input, input, '--filters', 'ip_str:192.0.2.7', '--fields', 'ip_str', '--filename', fresh])).body.error, 'INVALID_INPUT')
    await assert.rejects(readFile(fresh), { code: 'ENOENT' })
  })
})

test('CSV conversion encodes formula cells as literal text', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'formulas.json')
    await writeFile(input, JSON.stringify([{ data: '=1+2', hostnames: ['@SUM(1)'] }, { data: ' +1', hostnames: ['-1'] }, { data: '\t=1', hostnames: ['safe,"quoted"'] }]), { mode: 0o600 })
    assert.equal((await run(['convert', input, 'csv', '--fields', 'data,hostnames'])).code, 0)
    assert.equal(await readFile(join(root, 'formulas.csv'), 'utf8'), 'data,hostnames\r\n\'=1+2,\'@SUM(1)\r\n\' +1,\'-1\r\n\'\t=1,"safe,""quoted"""\r\n')
  })
})

test('parse bounds appended record counts and preserves readable evidence at the limit', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'records.json.gz')
    const remaining = join(root, 'remaining.json.gz')
    await writeFile(input, gzipSync('{"a":1}\n'.repeat(60000)), { mode: 0o600 })
    await writeFile(remaining, gzipSync('{"a":1}\n'.repeat(40000)), { mode: 0o600 })
    const saved = join(root, 'filtered.json.gz')
    const flags = ['--filters', 'a:1', '--fields', 'a', '--filename', saved]
    assert.equal((await run(['parse', input, ...flags])).code, 0)
    const prior = await readFile(saved)
    assert.equal((await run(['parse', input, ...flags])).body.error, 'INVALID_INPUT')
    assert.deepEqual(await readFile(saved), prior)
    assert.equal((await run(['parse', remaining, ...flags])).code, 0)
    const reopened = await run(['parse', saved, '--fields', 'a'])
    assert.equal(reopened.code, 0)
    assert.equal(reopened.body.count, 100000)
    assert.equal((await run(['convert', saved, 'csv', '--fields', 'a'])).code, 0)
  })
})

test('parse counts JSONL separators in fresh and appended decompressed limits', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'records.json.gz')
    const row = JSON.stringify({ a: 1, data: 'x'.repeat(93) })
    assert.equal(Buffer.byteLength(row), 110)
    await writeFile(input, gzipSync(`${row}\n`.repeat(47500)), { mode: 0o600 })
    const saved = join(root, 'filtered.json.gz')
    const flags = ['--filters', 'a:1', '--fields', 'a', '--filename', saved]
    assert.equal((await run(['parse', input, input, ...flags])).body.error, 'INVALID_INPUT')
    await assert.rejects(readFile(saved), { code: 'ENOENT' })
    assert.equal((await run(['parse', input, ...flags])).code, 0)
    const prior = await readFile(saved)
    assert.equal((await run(['parse', input, ...flags])).body.error, 'INVALID_INPUT')
    assert.deepEqual(await readFile(saved), prior)
    const reopened = await run(['parse', saved, '--fields', 'a'])
    assert.equal(reopened.code, 0)
    assert.equal(reopened.body.count, 47500)
  })
})

test('parse escapes banner terminal controls before applying color', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'controls.json')
    const data = '\u001b[2J\u001b[H\u009b2J\b\u0000\n\r\t'
    await writeFile(input, JSON.stringify({ data, hostnames: ['\u001b[H'] }), { mode: 0o600 })
    const plain = await run(['parse', input, '--fields', 'data,hostnames', '--no-color'])
    assert.equal(plain.body.display, '\\u001b[2J\\u001b[H\\u009b2J\\u0008\\u0000\\n\\r\\t\t\\u001b[H')
    assert.equal(plain.body.items[0].data, data)
    const colored = await run(['parse', input, '--fields', 'data', '--color'])
    assert.equal(colored.body.display, '\u001b[36m\\u001b[2J\\u001b[H\\u009b2J\\u0008\\u0000\\n\\r\\t\u001b[0m')
  })
})

test('malformed input cannot leave an output artifact', { timeout: 30000 }, async () => {
  await withInvestigation(async ({ root, run }) => {
    const input = join(root, 'bad.json')
    await writeFile(input, '{invalid', { mode: 0o600 })
    const result = await run(['convert', input, 'csv'])
    assert.equal(result.body.error, 'INVALID_INPUT')
    await assert.rejects(readFile(join(root, 'bad.csv')), { code: 'ENOENT' })
    const bomb = join(root, 'large.json.gz')
    await writeFile(bomb, gzipSync(Buffer.alloc(10 * 1024 * 1024 + 1, 65)), { mode: 0o600 })
    assert.equal((await run(['convert', bomb, 'csv'])).body.error, 'INVALID_INPUT')
    await assert.rejects(readFile(join(root, 'large.csv')), { code: 'ENOENT' })
    const good = join(root, 'good.json')
    await writeFile(good, JSON.stringify(rows), { mode: 0o600 })
    assert.equal((await run(['convert', good, 'csv', '--filename', '../escape.csv'])).body.error, 'INVALID_INPUT')
  })
})
