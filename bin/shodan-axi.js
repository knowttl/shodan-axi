#!/usr/bin/env node
import { VERSION } from '../dist/version.js'

if (process.argv.length === 3 && ['version', '--version', '-v', '-V'].includes(process.argv[2])) {
  process.stdout.write(`${VERSION}\n`)
} else {
  const { main } = await import('../dist/cli.js')
  await main(process.argv.slice(2))
}
