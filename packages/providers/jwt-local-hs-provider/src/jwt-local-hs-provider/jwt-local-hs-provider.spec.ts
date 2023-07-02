import { JwtAlgorithmsHSSchema, JwtProviderInvalidKeyMaterialError } from '@zod-jwt/core';
import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { getTestCredentials } from '../../../../core/src/tests/test-helper-get-credentials.js';
import { JwtLocalHsProvider } from '../index.js';

function createProvider(algorithms: JwtAlgorithmsHSSchema[], credentials: JwtAlgorithmsHSSchema) {
  const { secret } = getTestCredentials(credentials, 'valid', 'hex');
  const provider = new JwtLocalHsProvider({
    algorithms,
    credentials: {
      secret,
      encoding: 'hex',
    },
    privateClaimsSchema: z.object({}),
    publicClaimsSchema: z.object({}),
  });
  return {
    provider,
    secret,
  };
}

describe('JwtLocalHsProvider', () => {
  it('should exist', () => {
    expect(JwtLocalHsProvider).toBeTruthy();
  });

  it('should validate the secret', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(JwtLocalHsProvider.prototype as any, '_validateSecretKey');

    createProvider(['HS256'], 'HS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtAlgorithmsHSSchema[])('%s should create and validate a token', async (algorithm) => {
    const { provider } = createProvider([algorithm], algorithm);

    const token = await provider.sign({
      algorithm,
      publicClaims: {},
      privateClaims: {},
    });

    const verified = await provider.verify({
      token,
    });

    expect(verified).toBeTruthy();
  });

  describe.each([
    {
      credentials: 'HS256',
      badAlgs: ['HS384', 'HS512'],
    },
    {
      credentials: 'HS384',
      badAlgs: ['HS512'],
    },
  ] satisfies { credentials: JwtAlgorithmsHSSchema; badAlgs: JwtAlgorithmsHSSchema[] }[])(
    '$credentials cannot create a provider that requires higher bit credentials',
    ({ credentials, badAlgs }) => {
      badAlgs.forEach((algorithm) => {
        test(`Provider should throw when ${credentials} credentials are provided to higher bit algorithm ${algorithm}`, () => {
          expect(() => {
            createProvider(badAlgs, credentials);
          }).toThrow(JwtProviderInvalidKeyMaterialError);
        });
      });
    }
  );

  describe.each([
    { credentials: 'HS512', algorithms: ['HS256', 'HS384'] },
    { credentials: 'HS384', algorithms: ['HS256'] },
  ] satisfies { credentials: JwtAlgorithmsHSSchema; algorithms: JwtAlgorithmsHSSchema[] }[])(
    '$credentials can sign and verify lower bit algorithms',
    ({ credentials, algorithms }) => {
      algorithms.forEach(async (algorithm) => {
        test(`${credentials} can sign and verify lower bit algorithm ${algorithm}`, async () => {
          const { provider } = createProvider([algorithm], credentials);
          const token = await provider.sign({
            algorithm,
            privateClaims: {},
            publicClaims: {},
          });

          const res = await provider.verify({
            token,
          });

          expect(res).toBeTruthy();
        });
      });
    }
  );

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { provider } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token1 = await provider.sign({
        algorithm,
        privateClaims: {},
        publicClaims: {},
        timestamp,
      });
      const token2 = await provider.sign({
        algorithm,
        privateClaims: {},
        publicClaims: {},
        timestamp,
      });

      expect(token1).toEqual(token2);
    }
  );

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { provider, secret } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token = await provider.sign({
        algorithm,
        privateClaims: {},
        publicClaims: {},
        timestamp,
      });

      const decoded = await provider.decode({
        token,
      });

      verify(
        token,
        Buffer.from(secret, 'hex'),
        { algorithms: [algorithm], clockTimestamp: Math.floor(timestamp.getTime() / 1000), complete: true },
        (error, jwt) => {
          expect(error).toBeNull();
          expect(jwt).toBeTruthy();
          expect(jwt?.header.alg).toEqual(decoded.header.alg);
          expect(jwt?.header.typ).toEqual(decoded.header.typ);
          expect(jwt?.signature).toEqual(decoded.signature);
        }
      );
    }
  );
});
