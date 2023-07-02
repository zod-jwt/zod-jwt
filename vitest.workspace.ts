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
  {
    test: {
      include: ['packages/providers/jwt-local-es-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-local-es-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-local-hs-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-local-hs-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-local-ps-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-local-ps-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-local-rs-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-local-rs-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-kms-es-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-kms-es-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-kms-hs-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-kms-hs-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-kms-ps-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-kms-ps-provider',
      environment: 'node',
    },
  },
  {
    test: {
      include: ['packages/providers/jwt-kms-hs-provider/**/*.spec.ts'],
      alias: {
        '@zod-jwt/core': 'packages/core/src',
      },
      name: 'jwt-kms-rs-provider',
      environment: 'node',
    },
  },
]);
