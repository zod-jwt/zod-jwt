# KmsRsProvider

The `KmsRsProvider` lets you sign, verify, and decode JWTs with the `RS256`, `RS384`, and `RS512` algorithms.

---

## Getting Started

#### 1. Create you AWS KMS Key

1. Log into the AWS KMS Console
2. Select `Asymmetric` for the `Key type`
3. Select `Sign and verify` for the `Key usage`
4. Select `RSA_2048`, `RSA_3072`, or `RSA_4096` for the `Key spec`

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
import { KmsRsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new KmsRsProvider({
  algorithms: ['RS256', 'RS384', 'RS512'],
  credentials: {
    region: process.env.AWS_REGION as string,
    account: process.env.AWS_ACCOUNT as string,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
      kms: {
        keyAlias: 'MY_ALIAS', // or { keyId: 'mrk-abcd...' }
      },
    },
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for the more advanced options for signing and decoding tokens.
