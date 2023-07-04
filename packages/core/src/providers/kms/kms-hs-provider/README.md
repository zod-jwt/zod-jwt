# KmsHsProvider

The `KmsHsProvider` lets you sign, verify, and decode JWTs with the `HS256`, `HS384`, and `HS512` algorithms.

---

## Getting Started

#### 1. Create you AWS KMS Key

1. Log into the AWS KMS Console
2. Select `Symmetric` for the `Key type`
3. Select `Generate and verify MAC` for the `Key usage`
4. Select `HMAC_256`, `HMAC_384`, or `HMAC_512` for the `Key spec`

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
import { KmsHsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new KmsHsProvider({
  algorithms: ['HS256', 'HS384', 'HS512'],
  credentials: {
    region: process.env.AWS_REGION as string,
    account: process.env.AWS_ACCOUNT as string,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
      kms: {
        HS256: {
          keyAlias: 'MY_ALIAS', // or { keyId: 'mrk-abcd...' }
        },
      },
    },
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for signing, verifying, and decoding tokens.
