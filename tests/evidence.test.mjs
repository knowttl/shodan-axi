import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { gzipSync, gunzipSync } from 'node:zlib'
import ExcelJS from 'exceljs'
import jpeg from 'jpeg-js'
import { XMLParser } from 'fast-xml-parser'
import { withInvestigation } from './investigation-fixture.mjs'

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
    assert.deepEqual(geo.features.map(item => item.properties.ip), ['192.0.2.7', '192.0.2.8'])
    const workbook = new ExcelJS.Workbook()
    await workbook.xlsx.readFile(join(root, 'data.xlsx'))
    assert.deepEqual(workbook.worksheets.map(sheet => sheet.name), ['Raw Data', 'Summary'])
    assert.equal(workbook.getWorksheet('Raw Data').rowCount, 3)
    assert.equal(workbook.getWorksheet('Raw Data').getRow(2).getCell(2).value, false)
    assert.equal(workbook.getWorksheet('Raw Data').getRow(2).getCell(3).value, 0)
    const image = jpeg.encode({ data: Buffer.alloc(16, 255), width: 2, height: 2 }).data
    const imageInput = join(root, 'screenshot.json')
    await writeFile(imageInput, JSON.stringify({ ...rows[0], opts: { screenshot: { mime: 'image/jpeg', data: image.toString('base64') } } }), { mode: 0o600 })
    assert.equal((await run(['convert', imageInput, 'images'])).code, 0)
    const output = await readFile(join(root, 'screenshot.images', '1.jpg'))
    assert.deepEqual(output, image)
    assert.equal(jpeg.decode(output).width, 2)
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
