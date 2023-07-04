# LocalEsProvider

The `LocalEsProvider` lets you sign, verify, and decode JWTs with the `ES256`, `ES384`, and `ES512` algorithms.

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

# For ES512
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out es_512_private.pem
openssl pkey -in es_512_private.pem -pubout -out es_512_public.pem

```

### 2. Install

`zod` is a peer dependency to this package and you must install both `zod` and `@zod-jwt/zod-jwt` in order to get started.

```bash
pnpm i zod @zod-jwt/zod-jwt
```

```bash
npm i zod @zod-jwt/zod-jwt
```

```bash
yarn add zod @zod-jwt/zod-jwt
```

### 3. Create your provider

```ts
import { LocalEsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new LocalEsProvider({
  algorithms: ['ES256'],
  providerName: 'ES',
  credentials: {
    ES256: {
      publicKey: process.env.PUBLIC_KEY as string,
      privateKey: process.env.PRIVATE_KEY as string, // Optional for calls to verify(); Required for calls to sign();
    },
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for signing, verifying, and decoding tokens.
