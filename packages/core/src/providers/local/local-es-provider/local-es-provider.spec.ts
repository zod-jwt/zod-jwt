import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
import { JwtProviderBadConfigError } from '../../../errors/index.js';
import { Jwt } from '../../../jwt/jwt.js';
import { JwtAlgorithmsESSchema } from '../../../schema/index.js';
import { getTestCredentials } from '../../../tests/test-helper-get-credentials.js';
import { LocalEsProvider } from '../../index.js';

function createProvider(algorithms: JwtAlgorithmsESSchema[], credentials: JwtAlgorithmsESSchema) {
  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new LocalEsProvider({
    algorithms,
    credentials: {
      ...(credentials === 'ES256'
        ? {
            ES256: {
              publicKey,
              privateKey,
            },
          }
        : credentials === 'ES384'
        ? {
            ES384: {
              publicKey,
              privateKey,
            },
          }
        : {
            ES512: {
              publicKey,
              privateKey,
            },
          }),
    },
    providerName: 'test',
  });

  const jwt = new Jwt({
    providers: [provider],
  });

  const schema = z.object({
    publicClaims: z.object({}),
    privateClaims: z.object({}),
  });

  return {
    jwt,
    schema,
    data: {
      publicClaims: {},
      privateClaims: {},
    },
    provider,
    privateKey,
    publicKey,
  };
}

describe('JwtEsProvider', () => {
  it('should exist', () => {
    expect(LocalEsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(LocalEsProvider.prototype as any, '_validatePublicKey');

    createProvider(['ES256'], 'ES256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(LocalEsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['ES256'], 'ES256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['ES256', 'ES384', 'ES512'] satisfies JwtAlgorithmsESSchema[])('%s should create and validate a token', async (algorithm) => {
    const { jwt, schema, data } = createProvider([algorithm], algorithm);

    const token = await jwt.sign({
      algorithm,
      schema,
      data,
      provider: 'test',
    });

    const verified = await jwt.verify({
      token,
      provider: 'test',
      schema,
      timestamp: new Date(),
    });

    expect(verified).toBeTruthy();
  });

  describe.each([
    {
      credentials: 'ES256',
      badAlgs: ['ES384', 'ES512'],
    },
    {
      credentials: 'ES384',
      badAlgs: ['ES256', 'ES512'],
    },
    {
      credentials: 'ES512',
      badAlgs: ['ES256', 'ES384'],
    },
  ] satisfies { credentials: JwtAlgorithmsESSchema; badAlgs: JwtAlgorithmsESSchema[] }[])(
    '$credentials cannot be used to sign other ES algorithms',
    ({ credentials, badAlgs }) => {
      badAlgs.forEach((algorithm) => {
        test(`Provider should throw when ${credentials} credentials are provided to algorithm ${algorithm}`, () => {
          expect(() => {
            const { jwt, schema, data } = createProvider(badAlgs, credentials);
            jwt.sign({
              algorithm,
              provider: 'test',
              data,
              schema,
            });
          }).toThrow(JwtProviderBadConfigError);
        });
      });
    }
  );

  test.each([{ algorithm: 'ES256' }, { algorithm: 'ES384' }, { algorithm: 'ES512' }] satisfies { algorithm: JwtAlgorithmsESSchema }[])(
    'Probabilistic algorithm $algorithm should generate a different signature each time',
    async ({ algorithm }) => {
      const { provider, data, jwt, schema } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token1 = await jwt.sign({
        provider: 'test',
        algorithm,
        schema,
        data,
        timestamp,
      });
      const token2 = await jwt.sign({
        provider: 'test',
        algorithm,
        schema,
        data,
        timestamp,
      });

      expect(token1).not.toEqual(token2);
    }
  );

  test.each([{ algorithm: 'ES256' }, { algorithm: 'ES384' }, { algorithm: 'ES512' }] satisfies { algorithm: JwtAlgorithmsESSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { jwt, data, schema, provider, publicKey } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token = await jwt.sign({
        algorithm,
        provider: 'test',
        data,
        schema,
        timestamp,
      });

      const decoded = await jwt.decode({
        token,
        provider: 'test',
        schema,
      });

      verify(token, publicKey, { algorithms: [algorithm], clockTimestamp: Math.floor(timestamp.getTime() / 1000), complete: true }, (error, jwt) => {
        expect(error).toBeNull();
        expect(jwt).toBeTruthy();
        expect(jwt?.header.alg).toEqual(decoded.header.alg);
        expect(jwt?.header.typ).toEqual(decoded.header.typ);
        expect(jwt?.signature).toEqual(decoded.signature);
      });
    }
  );
});
