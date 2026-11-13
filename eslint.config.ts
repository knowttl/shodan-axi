import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**', 'bin/**', 'scripts/**', 'tests/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  { files: ['src/**/*.ts'], languageOptions: { parserOptions: { project: './tsconfig.json' } },
    rules: { '@typescript-eslint/consistent-type-assertions': ['error', { assertionStyle: 'never' }], '@typescript-eslint/ban-ts-comment': 'error' } },
)
