# @jwt-zod/jwt-local-hs-provider

The `@jwt-zod/jwt-local-hs-provider` lets you sign, verify, and decode JWTs with the `HS256`, `HS384`, and `HS512` algorithms.

---

## Getting Started

#### 1. Create you Credentials

`@jwt-zod` is secure by default and prevents you from creating insecure JWTs. The below `openssl` commands can be used to create secure credentials. If you want to use other commands to generate your keys you can. Internally this provider checks that the following conditions of your secret are met. If the below conditions are not met an error will be thrown. Additionally, you must explicitly set the encoding.

| Algorithm | Minimum Secret Length |
| :-------: | :-------------------: |
|  `HS256`  |      `32 Bytes`       |
|  `HS384`  |      `48 Bytes`       |
|  `HS512`  |      `64 Bytes`       |

Note:

- If you create a 64 byte length secret you will be able to sign will `HS512`, `HS384`, and `HS256`
- If you create a 48 byte length secret you will be able to sign will `HS512` and `HS384`
- If you create a 32 byte length secret you will be able to sign will only `HS256`

```bash
# Make sure your openssl version is up to date
sudo apt update
sudo apt upgrade openssl

# For HS256
openssl rand -base64 32
openssl rand -hex 32

# For HS384
openssl rand -base64 48
openssl rand -hex 48

# For HS512
openssl rand -base64 64
openssl rand -hex 64

```

### 2. Install

`zod` and `@zod-jwt/core` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/core @zod-jwt/jwt-local-hs-provider
```

```bash
npm i zod @zod-jwt/core @zod-jwt/jwt-local-hs-provider
```

```bash
yarn add zod @zod-jwt/core @zod-jwt/jwt-local-hs-provider
```

### 3. Create your provider and start signing and verifying tokens

```ts
// provider.ts
import { JwtLocalHsProvider } from '@zod-jwt/jwt-local-hs-provider';
import { z } from 'zod';

export const provider = new JwtLocalHsProvider({
  algorithms: ['HS256'],
  credentials: {
    HS256: {
      secret: process.env.JWT_HS_SECRET as string,
      encoding: 'hex',
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
