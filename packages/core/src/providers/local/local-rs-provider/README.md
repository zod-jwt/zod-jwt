# LocalRsProvider

The `LocalRsProvider` lets you sign, verify, and decode JWTs with the `RS256`, `RS384`, and `RS512` algorithms.

---

## Getting Started

#### 1. Create you Credentials

`@jwt-zod` is secure by default and prevents you from creating insecure JWTs. The below `openssl` commands can be used to create secure credentials. If you want to use other commands to generate your keys you can. Internally this provider checks that the following conditions of your public key and private key using the node `cypto` library. If the below conditions are not met an error will be thrown.

| Algorithm | Key Type | Minimum Modulus Length |
| :-------: | :------: | :--------------------: |
|  `RS256`  |  `rsa`   |         `2048`         |
|  `RS384`  |  `rsa`   |         `3072`         |
|  `RS512`  |  `rsa`   |         `4096`         |

```bash
# Make sure your openssl version is up to date
sudo apt update
sudo apt upgrade openssl

# For RS256
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rs_256_private.pem
openssl pkey -in rs_256_private.pem -pubout -out rs_256_public.pem

# For RS384
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rs_384_private.pem
openssl pkey -in rs_384_private.pem -pubout -out rs_384_public.pem

# For RS512
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rs_512_private.pem
openssl pkey -in rs_512_private.pem -pubout -out rs_512_public.pem
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

### 3. Create your provider and start signing and verifying tokens

```ts
import { LocalRsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new LocalRsProvider({
  algorithms: ['RS256', 'RS384', 'RS512'],
  credentials: {
    publicKey: process.env.RSA_PUBLIC_KEY as string,
    privateKey: process.env.RSA_PRIVATE_KEY as string, // Optional for calls to verify(); Required for calls to sign();
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for signing, verifying, and decoding tokens.
