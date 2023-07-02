# @jwt-zod/jwt-kms-rs-provider

The `@jwt-zod/jwt-kms-rs-provider` lets you sign, verify, and decode JWTs with the `RS256`, `RS384`, and `RS512` algorithms.

---

## Getting Started

#### 1. Create you AWS KMS Key

1. Log into the AWS KMS Console
2. Select `Asymmetric` for the `Key type`
3. Select `Sign and verify` for the `Key usage`
4. Select `RSA_2048`, `RSA_3072`, or `RSA_4096` for the `Key spec`

### 2. Install

`zod`, `@aws-sdk/client-kms` and `@zod-jwt/core` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/core @zod-jwt/jwt-kms-rs-provider
```

```bash
npm i zod @zod-jwt/core @zod-jwt/jwt-kms-rs-provider
```

```bash
yarn add zod @zod-jwt/core @zod-jwt/jwt-kms-rs-provider
```

### 3. Create your provider and start signing and verifying tokens

```ts
// provider.ts
import { JwtKmsRsProvider } from '@zod-jwt/jwt-kms-rs-provider';
import { z } from 'zod';

export const provider = new JwtKmsRsProvider({
  algorithms: ['RS256', 'RS384', 'RS512'],
  credentials: {
    region: process.env.AWS_REGION as string,
    account: process.env.AWS_ACCOUNT as string,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
      kms: {
        keyAlias: 'MY_ALIAS' // or { keyId: 'mrk-abcd...' }
      }
    },
  },
  publicClaimsSchema: z.object({
    iss: z.literal('auth.example.com'),
    aud: z.literal('example.com'),
    sub: z.string(),
  }),
  privateClaimsSchema: z.object({
    firstName: z.string(),
    lastName: z.string(),
  }),
});

const token = await provider.sign({
  algorithm: 'RS256',
  publicClaims: {
    iss: 'auth.example.com',
    aud: 'example.com',
    sub: 'user_1234'
  },
  privateClaims: {
    firstName: 'John',
    lastName: 'Doe',
  },
});

const const { header, privateClaims, publicClaims } = await provider.verify({
  token,
});
```

Please refer back to the main [@zod-jwt docs](../../../README.md) for the more advanced options for signing and decoding tokens.
