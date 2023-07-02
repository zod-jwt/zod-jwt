# @zod-jwt

This library is an opinionated JWT library focused on:

- **Type Safety** - Bring your <a href="https://github.com/colinhacks/zod">Zod</a> schema, and we will validate every token you sign, verify, and decode.
- **Security** - Secure by default and no escape hatches for providing insecure credentials. We provide directions on how to generate secure credentials for every type of algorithm.
- **Ease of Use** - Simple and well documented API for signing, verifying, and decoding JWTs.

## Getting Started

**1. Determine which algorithm(s) you want to use:**

- **Symmetric Algorithms**
  - Algorithms:
    - `HS256`
    - `HS384`
    - `HS512`
  - Uses a single `secret` to sign and verify tokens
  - Good for simple apps where the signing and verifying of tokens is performed by the same application
  - You **_must not_** expose the `secret` to any other application to remain secure
- **Asymmetric Algorithms**

  - Algorithms:

    - `RS256`
    - `RS384`
    - `RS512`
    - `PS256`
    - `PS384`
    - `PS512`
    - `ES256`
    - `ES384`
    - `ES512`

  - Uses a `privateKey` to sign tokens
  - Uses a `publicKey` to verify tokens
  - Good for microservices where one service signs a token and another service consumes a token
  - You **_must not_** expose the `privateKey` to any other application to remain secure
  - You **_can_** expose the `publicKey` to any other application so that other application can verify tokens

**2. Select how you want to sign and verify tokens (Provider Types):**

- **Local Providers**
  - Bring your own credentials. You are in full control of you credentials providing higher flexibility but also higher operational risk.
  - Directions on how to generate secure credentials are included in the docs of each of the individual providers.
  - This library enforces minimum security standards based on the algorithm. If you attempt to create a provider with invalid credentials it will throw an error.
- **<a href="https://aws.amazon.com/kms/">AWS KMS</a> Providers**
  - Uses AWS Key Management Service to sign and verify tokens.
  - You need to provide your KMS `keyId` or `keyAlias`.
  - Every time you sign or verify a token, a call to AWS KMS will be made to verify the signature.
  - By using AWS KMS you simplify your application environment config and reduce the risk of exposing your `secret` or `privateKey`.

---

This table has links to the individual providers. You should read the docs on the specific provider you want to use to learn how to install, setup credentials, and instantiate your provider and then come back to this page to read the docs on signing, verifying, and decoding tokens.
| Algorithm Type | Supported Algorithms | Local Provider | AWS KMS Provider |
| :---------------- | :---------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :---|
| `HS` (Symmetric) | `HS256` </br> `HS384` </br> `HS512` | <a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-local-hs-provider/README.md">@zod-jwt/jwt-local-hs-provider</a>|<a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-kms-hs-provider/README.md">@zod-jwt/jwt-kms-hs-provider</a> |
| `RS` (Asymmetric) | `RS256` </br> `RS384` </br> `RS512` | <a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-local-rs-provider/README.md">@zod-jwt/jwt-local-rs-provider</a>|<a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-kms-rs-provider/README.md">@zod-jwt/jwt-kms-rs-provider</a> |
| `PS` (Asymmetric) | `PS256` </br> `PS384` </br> `PS512` | <a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-local-ps-provider/README.md">@zod-jwt/jwt-local-ps-provider</a>|<a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-kms-ps-provider/README.md">@zod-jwt/jwt-kms-ps-provider</a> |
| `ES` (Asymmetric) | `ES256` </br> `ES384` </br> `ES512` | <a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-local-es-provider/README.md">@zod-jwt/jwt-local-es-provider</a>|<a href="https://github.com/zod-jwt/zod-jwt/blob/main/packages/providers/jwt-kms-es-provider/README.md">@zod-jwt/jwt-kms-es-provider</a> |

---

### Using a Provider

_For example purposes, this page will use the `JwtLocalRsProvider`, however all providers have the same API when it comes to signing, verifying, and decoding tokens._

#### Simple Example

```ts
import { z } from 'zod';
import { JwtLocalRsProvider } from '@zod-jwt/jwt-local-rs-provider';

const provider = new JwtLocalRsProvider({
  algorithms: ['RS256'],
  credentials: {
    publicKey: process.env.PUBLIC_KEY as string,
    privateKey: process.env.PRIVATE_KEY as string,
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
    sub: 'user_1234',
  },
  privateClaims: {
    firstName: 'John',
    lastName: 'Doe',
  },
});

const { header, privateClaims, publicClaims } = await provider.verify({
  token,
});
```

In this example we have created and verified a token requiring that:

- The `iss` public claim must be equal to `auth.example.com`
- The `aud` public claim must be equal to `example.com`
- The `sub` public claim must be a string
- The `firstName` private claim must be a string
- The `lastName` private claim must be a string

By default the following claims are also set:

- The `iat` public claim is equal to the date that the call to `sign()` was made
- The `nbf` public claim is equal to the date that the call to `sign()` was made
- The `exp` public claim is equal to the date that the call to `sign()` was made plus 15 minutes

---

### Sign Options

##### Setting the `timestamp`

The `timestamp` property sets the signing time for the token and affects the time set in the `iat`, `exp`, and `nbf` claims. In the below example we are overriding the `timestamp`. As a result the `iat` and `nbf` claims will be equal to 1/1/2023 @ 9:00 AM while the `exp` claim will be equal to 1/1/2023 @ 9:15 AM. The `timestamp` can be used in conjunction with the relative offsets in the next example.

```ts
const token = await provider.sign({
  algorithm: 'RS256',
  publicClaims: {
    iss: 'auth.example.com',
    aud: 'example.com',
    sub: 'user_1234',
  },
  privateClaims: {
    firstName: 'John',
    lastName: 'Doe',
  },
  timestamp: new Date('January 1, 2023 9:00:00'), // <-- manually set the timestamp
});
```

##### Setting the offsets

The `iat`, `exp`, and `nbf` claims can be adjusted to suit your needs. You need to provide a relative offset in milliseconds. Since JWTs work in seconds and not milliseconds you should provide a value which is a multiple of 1000. You can provide a number or a string. If you provide a string, it will be parsed by the <a href="https://github.com/vercel/ms">ms</a> package. This can also be used in conjunction with the `timestamp`.

In this example, we back date the `nbf` claim by 1 second and set the `exp` claim to 10 minutes from now.

```ts
// number example
const token = await provider.sign({
  algorithm: 'RS256',
  publicClaims: {
    iss: 'auth.example.com',
    aud: 'example.com',
    sub: 'user_1234',
    nbf: -1000, // <-- back date by 1 minute
    exp: 1000 * 60 * 10, // <-- set the exp to 10 minutes from now
  },
  privateClaims: {
    firstName: 'John',
    lastName: 'Doe',
  },
});

// string example
const token = await provider.sign({
  algorithm: 'RS256',
  publicClaims: {
    iss: 'auth.example.com',
    aud: 'example.com',
    sub: 'user_1234',
    nbf: '-1 second', // <-- back date by 1 minute
    exp: '10 minutes', // <-- set the exp to 10 minutes from now
  },
  privateClaims: {
    firstName: 'John',
    lastName: 'Doe',
  },
});
```

---

### Verify Options

##### Setting the `timestamp`

If you set the `timestamp` when verifying a token the `nbf` and `exp` claims will be validated as of that time.

```ts
const { header, privateClaims, publicClaims } = await provider.verify({
  token,
  timestamp: new Date('January 1, 2023 9:00:00'), // <-- manually set the timestamp
});
```

##### Setting the `clockSkew`

If you set the `clockSkew` when verifying a token the `nbf` and `exp` claims will allow for normally invalid values. Since JWTs work in seconds and not milliseconds you should provide a value which is a multiple of 1000. You can provide a number or a string. If you provide a string, it will be parsed by the <a href="https://github.com/vercel/ms">ms</a> package. This can be used in conjunction with the `timestamp`.

Validation will pass when:

- The `nbf` claim is after `timestamp` - `clockSkew`
- The `exp` claim is after `timestamp` + `clockSkew`

Note: the `timestamp` is automatically set for you but you can override it if you need to.

```ts
// number example
const { header, privateClaims, publicClaims } = await provider.verify({
  token,
  clockSkew: 1000 * 10, // <-- allow invalid tokens a grace period for up to 10 seconds
});

// string example
const { header, privateClaims, publicClaims } = await provider.verify({
  token,
  clockSkew: '10 seconds', // <-- allow invalid tokens a grace period for up to 10 seconds
});
```

##### Claim Validation

Sometimes claims cannot be validated by a library because they are domain specific to a particular application. We provide a `validate` hook into the `verify` function so additional checks can be made. If you return `false` a `JwtTokenClaimError` will be thrown. If you return `true` the promise will resolve. This callback is called right before resolving the promise meaning that all other claim validation has passed.

In this hypothetical example we make sure that the user has not been banned after their original token was created. If you are implementing a token blacklist you can use this callback to check against the blacklist.

```ts
const { header, privateClaims, publicClaims } = await provider.verify({
  token,
  validate: async ({ header, publicClaims, privateClaims }) => {
    const userId = publicClaims.sub;
    const user = await db.users.getById(userId);
    return !user.banned;
  },
});
```

---

### Decode Options

The API for decoding a token is a subset of `verify()`. Since decoding does not check the `exp` and `nbf` claims, the `timestamp` and `clockSkew` properties are not provided. A call to `decode()` will however validate against your `publicClaimsSchema` and `privateClaimsSchema`.

---

### Catching Errors

All errors thrown by the providers will be extended from the abstract class `JwtError`. This error will never be thrown directly but its subclasses will be. You should catch them like this:

```ts
// Note: this list of errors is not comprehensive
import {
  JwtError,
  JwtProviderBadConfigError,
  JwtProviderInvalidKeyMaterialError,
  JwtTokenClaimError,
  JwtTokenInvalidSignatureError,
  JwtTokenMalformedError,
  JwtUnknownError,
} from '@zod-jwt/core/errors';

try {
  // sign, decode, verify
} catch (e) {
  if (e instanceof JwtError) {
    if (e instanceof JwtTokenClaimError) {
      // do something
    } else if (e instanceof JwtTokenInvalidSignatureError) {
      // do something
    } else if (e instanceof JwtTokenMalformedError) {
      // do something
    } else {
      // do something
    }
  } else {
    // if this library threw an error
    // and wasn't an instanceof a JwtError,
    // open an issue
  }
}
```

## Schema

There are a handful of schemas relating to JWTs included in the `@zod-jwt/core` package. If you are authoring your own provider or want to perform validation in your own application you can import the schema like this:

```ts
import { JwtAlgorithmsRsSchema } from '@zod-jwt/core/schema';

const myVar: JwtAlgorithmsRsSchema = 'RS256'; // or 'RS384', or 'RS512'

const zodParseResult = JwtAlgorithmsRsSchema.parse('PS256'); // this will throw
```

Note: The types and `zod` schemas have the same name.
