# @jwt-zod/jwt-kms-hs-provider

The `@jwt-zod/jwt-kms-hs-provider` lets you sign, verify, and decode JWTs with the `HS256`, `HS384`, and `HS512` algorithms.

---

## Getting Started

#### 1. Create you AWS KMS Key

1. Log into the AWS KMS Console
2. Select `Symmetric` for the `Key type`
3. Select `Generate and verify MAC` for the `Key usage`
4. Select `HMAC_256`, `HMAC_384`, or `HMAC_512` for the `Key spec`

### 2. Install

`zod`, `@aws-sdk/client-kms` and `@zod-jwt/core` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/core @zod-jwt/jwt-kms-hs-provider
```

```bash
npm i zod @zod-jwt/core @zod-jwt/jwt-kms-hs-provider
```

```bash
yarn add zod @zod-jwt/core @zod-jwt/jwt-kms-hs-provider
```

### 3. Create your provider and start signing and verifying tokens

```ts
// provider.ts
import { JwtKmsHsProvider } from '@zod-jwt/jwt-kms-hs-provider';
import { z } from 'zod';

export const provider = new JwtKmsHsProvider({
  algorithms: ['HS256', 'HS384', 'HS512'],
  credentials: {
    region: process.env.AWS_REGION as string,
    account: process.env.AWS_ACCOUNT as string,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
      kms: {
        HS256: {
          keyAlias: 'MY_ALIAS' // or { keyId: 'mrk-abcd...' }
        }
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
  algorithm: 'HS256',
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
