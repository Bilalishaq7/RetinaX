// ESLint flat config for RetinaX vanilla frontend (no build step).
// Covers browser scripts (website/app.js), UMD components
// (website/utils.js, website/components/*.js) and node:test files.
const browserGlobals = {
  window: 'readonly',
  document: 'readonly',
  navigator: 'readonly',
  location: 'readonly',
  history: 'readonly',
  localStorage: 'readonly',
  sessionStorage: 'readonly',
  fetch: 'readonly',
  alert: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  requestAnimationFrame: 'readonly',
  cancelAnimationFrame: 'readonly',
  customElements: 'readonly',
  HTMLElement: 'readonly',
  CustomEvent: 'readonly',
  Event: 'readonly',
  Node: 'readonly',
  Element: 'readonly',
  FormData: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  Intl: 'readonly',
  console: 'readonly',
  self: 'readonly',
  globalThis: 'readonly',
  // Third-party libs loaded via CDN script tags in website/index.html
  AOS: 'readonly',
  gsap: 'readonly',
  // UMD wrapper identifiers
  define: 'readonly',
};

const nodeGlobals = {
  module: 'writable',
  exports: 'writable',
  require: 'readonly',
  process: 'readonly',
  __dirname: 'readonly',
  __filename: 'readonly',
  global: 'writable',
};

export default [
  {
    ignores: ['node_modules/**', 'target/**', '.git/**', 'website/assets/**'],
  },
  {
    files: ['website/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...browserGlobals, ...nodeGlobals },
    },
    rules: {
      'no-undef': 'error',
      'no-unused-vars': [
        'error',
        { args: 'none', caughtErrors: 'none', varsIgnorePattern: '^_', argsIgnorePattern: '^_' },
      ],
      'no-redeclare': 'error',
    },
  },
  {
    // Test files use side-effect construction (e.g. `const pc = new PatientCard(...)`)
    // to assert no-throw rendering; do not flag unused test locals.
    files: ['website/**/*.test.js'],
    rules: {
      'no-unused-vars': 'off',
    },
  },
];
