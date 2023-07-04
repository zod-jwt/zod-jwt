# LocalHsProvider

The `LocalHsProvider` lets you sign, verify, and decode JWTs with the `HS256`, `HS384`, and `HS512` algorithms.

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
import { LocalHsProvider } from '@zod-jwt/zod-jwt/providers';

export const provider = new LocalHsProvider({
  providerName: 'hs',
  algorithms: ['HS256'],
  credentials: {
    secret: process.env.JWT_HS_SECRET as string,
    encoding: 'hex',
  },
});
```

Please refer back to the main [@zod-jwt docs](https://github.com/zod-jwt/zod-jwt) for signing, verifying, and decoding tokens.
