# @jwt-zod/jwt-local-es-provider

The `@jwt-zod/jwt-local-es-provider` lets you sign, verify, and decode JWTs with the `ES256`, `ES384`, and `ES512` algorithms.

---

## Getting Started

#### 1. Create you Credentials

`@jwt-zod` is secure by default and prevents you from creating insecure JWTs. The below `openssl` commands can be used to create secure credentials. If you want to use other commands to generate your keys you can. Internally this provider checks that the following conditions of your public key and private key using the node `cypto` library. If the below conditions are not met an error will be thrown.

| Algorithm | Key Type |    Curve     |
| :-------: | :------: | :----------: |
|  `ES256`  |   `ec`   | `prime256v1` |
|  `ES384`  |   `ec`   | `secp384r1`  |
|  `ES512`  |   `ec`   | `secp521r1`  |

```bash
# Make sure your openssl version is up to date
sudo apt update
sudo apt upgrade openssl

# For ES256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es_256_private.pem
openssl pkey -in es_256_private.pem -pubout -out es_256_public.pem

# For ES384
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out es_384_private.pem
openssl pkey -in es_384_private.pem -pubout -out es_384_public.pem

# For ES512 (Yes, curve is 521, not 512)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out es_512_private.pem
openssl pkey -in es_512_private.pem -pubout -out es_512_public.pem

```

### 2. Install

`zod` and `@zod-jwt/core` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/core @zod-jwt/jwt-local-es-provider
```

```bash
npm i zod @zod-jwt/core @zod-jwt/jwt-local-es-provider
```

```bash
yarn add zod @zod-jwt/core @zod-jwt/jwt-local-es-provider
```

### 3. Create your provider and start signing and verifying tokens

```ts
// provider.ts
import { JwtLocalEsProvider } from '@zod-jwt/jwt-local-es-provider';
import { z } from 'zod';

export const provider = new JwtLocalEsProvider({
  algorithms: ['ES256'],
  credentials: {
    ES256: {
      publicKey: process.env.PUBLIC_KEY as string,
      privateKey: process.env.PRIVATE_KEY as string,
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
  algorithm: 'ES256',
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

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for the more advanced options for signing and decoding tokens.
