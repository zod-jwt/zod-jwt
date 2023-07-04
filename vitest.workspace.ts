import { defineWorkspace } from 'vitest/config';

// defineWorkspace provides a nice type hinting DX
export default defineWorkspace([
  'packages/*/vitest.config.ts',
  {
    test: {
      include: ['packages/core/**/*.spec.ts'],
      name: 'core',
      environment: 'node',
    },
  },
]);
