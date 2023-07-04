# KmsEsProvider

The `KmsEsProvider` lets you sign, verify, and decode JWTs with the `ES256`, `ES384`, and `ES512` algorithms.

---

## Getting Started

#### 1. Create you AWS KMS Key

1. Log into the AWS KMS Console
2. Select `Asymmetric` for the `Key type`
3. Select `Sign and Verify` for the `Key usage`
4. Select `ECC_NIST_P256`, `ECC_NIST_P384`, or `ECC_NIST_P521` for the `Key spec`

### 2. Install

`zod`, `@aws-sdk/client-kms` and `@aws-sdk/types` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/zod-jwt @aws-sdk/client-kms @aws-sdk/types
```

```bash
npm i zod @zod-jwt/zod-jwt @aws-sdk/client-kms @aws-sdk/types
```

```bash
yarn add zod @zod-jwt/zod-jwt @aws-sdk/client-kms @aws-sdk/types
```

### 3. Create your provider

```ts
import { KmsEsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new KmsEsProvider({
  algorithms: ['ES256', 'ES384', 'ES512'],
  credentials: {
    region: process.env.AWS_REGION as string,
    account: process.env.AWS_ACCOUNT as string,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
      kms: {
        ES256: {
          keyAlias: 'MY_ALIAS', // or { keyId: 'mrk-abcd...' }
        },
      },
    },
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for signing, verifying, and decoding tokens.
