# @jwt-zod/jwt-local-ps-provider

The `@jwt-zod/jwt-local-ps-provider` lets you sign, verify, and decode JWTs with the `PS256`, `PS384`, and `PS512` algorithms.

---

## Getting Started

#### 1. Create you Credentials

`@jwt-zod` is secure by default and prevents you from creating insecure JWTs. The below `openssl` commands can be used to create secure credentials. If you want to use other commands to generate your keys you can. Internally this provider checks that the following conditions of your public key and private key using the node `cypto` library. If the below conditions are not met an error will be thrown.

| Algorithm | Key Type  | Minimum Modulus Length | Minimum Salt Length | hashAlgorithm & mgf1HashAlgorithm |
| :-------: | :-------: | :--------------------: | :-----------------: | :-------------------------------: |
|  `PS256`  | `rsa-pss` |         `2048`         |        `32`         |             `sha256`              |
|  `PS384`  | `rsa-pss` |         `3072`         |        `48`         |             `sha384`              |
|  `PS512`  | `rsa-pss` |         `4096`         |        `64`         |             `sha512`              |

Note:

- The `PS` based algorithms require a different set of private and public keys for each algorithm you want to use. As a result you need to provide a set of credentials for each algorithm you want to use.

```bash
# Make sure your openssl version is up to date
sudo apt update
sudo apt upgrade openssl

# For PS256
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out ps_256_private.pem
openssl rsa -pubout -in ps_256_private.pem -out ps_256_public.pem

# For PS384
openssl genpkey -algorithm RSA-PSS -out ps_384_private.pem -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:48
openssl rsa -pubout -in ps_384_private.pem -out ps_384_public.pem

# For PS512
openssl genpkey -algorithm RSA-PSS -out ps_512_private.pem -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_pss_keygen_md:sha512 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:64
openssl rsa -pubout -in ps_512_private.pem -out ps_512_public.pem
```

### 2. Install

`zod` and `@zod-jwt/core` are peer dependencies to this package and you must install all three in order to get started.

```bash
pnpm i zod @zod-jwt/core @zod-jwt/jwt-local-ps-provider
```

```bash
npm i zod @zod-jwt/core @zod-jwt/jwt-local-ps-provider
```

```bash
yarn add zod @zod-jwt/core @zod-jwt/jwt-local-ps-provider
```

### 3. Create your provider and start signing and verifying tokens

In the below example we create a provider that will sign and verify JWTs that meet the following criteria:

```ts
// provider.ts
import { JwtLocalPsProvider } from '@zod-jwt/jwt-local-ps-provider';
import { z } from 'zod';

export const provider = new JwtLocalPsProvider({
  algorithms: ['PS256'],
  credentials: {
    PS256: {
      publicKey: process.env.PUBLIC_KEY as string,
      privateKey: process.env.PRIVATE_KEY as string, // Optional for calls to verify(); Required for calls to sign();
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
  algorithm: 'PS256',
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
