import assert from 'node:assert/strict'
import { test } from 'node:test'
import ts from 'typescript'
import { ESLint } from 'eslint'
import tseslint from 'typescript-eslint'

const config = ts.readConfigFile('tsconfig.json', ts.sys.readFile)
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, '.', { noEmit: true, rootDir: '.' })

for (const [name, errors] of [['valid', false], ['type001', true], ['type002', true], ['type005', true]]) {
  test(`${name} satisfies the compiler boundary`, () => {
    const program = ts.createProgram([`tests/canaries/${name}.ts`], parsed.options)
    const diagnostics = ts.getPreEmitDiagnostics(program)
    assert.equal(diagnostics.length > 0, errors, ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: value => value, getCurrentDirectory: ts.sys.getCurrentDirectory, getNewLine: () => '\n',
    }))
  })
}

test('type004 rejects unsafe types, assertions and suppressions', async () => {
  const eslint = new ESLint({ overrideConfigFile: true, overrideConfig: {
    files: ['**/*.ts'], languageOptions: { parser: tseslint.parser, parserOptions: { project: './tests/canaries/tsconfig.json' } },
    plugins: { '@typescript-eslint': tseslint.plugin },
    rules: { '@typescript-eslint/no-explicit-any': 'error', '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error', '@typescript-eslint/no-unsafe-call': 'error', '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/consistent-type-assertions': ['error', { assertionStyle: 'never' }],
      '@typescript-eslint/ban-ts-comment': 'error' },
  } })
  const [valid] = await eslint.lintFiles(['tests/canaries/valid.ts'])
  const [invalid] = await eslint.lintFiles(['tests/canaries/type004.ts'])
  assert.equal(valid.errorCount, 0)
  for (const rule of ['no-explicit-any', 'no-unsafe-assignment', 'no-unsafe-member-access', 'no-unsafe-call', 'no-unsafe-return', 'consistent-type-assertions', 'ban-ts-comment']) {
    assert.ok(invalid.messages.some(message => message.ruleId === `@typescript-eslint/${rule}`), rule)
  }
})
