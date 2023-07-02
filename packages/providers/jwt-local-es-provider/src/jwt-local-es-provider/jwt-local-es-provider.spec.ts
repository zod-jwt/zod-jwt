import { JwtAlgorithmsESSchema, JwtProviderBadConfigError } from '@zod-jwt/core';
import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { getTestCredentials } from '../../../../core/src/tests/test-helper-get-credentials.js';
import { JwtLocalEsProvider } from '../index.js';

function createProvider(algorithms: JwtAlgorithmsESSchema[], credentials: JwtAlgorithmsESSchema) {
  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new JwtLocalEsProvider({
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
    privateClaimsSchema: z.object({}),
    publicClaimsSchema: z.object({}),
  });
  return {
    provider,
    privateKey,
    publicKey,
  };
}

describe('JwtEsProvider', () => {
  it('should exist', () => {
    expect(JwtLocalEsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(JwtLocalEsProvider.prototype as any, '_validatePublicKey');

    createProvider(['ES256'], 'ES256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(JwtLocalEsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['ES256'], 'ES256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['ES256', 'ES384', 'ES512'] satisfies JwtAlgorithmsESSchema[])('%s should create and validate a token', async (algorithm) => {
    const { provider } = createProvider([algorithm], algorithm);

    const token = await provider.sign({
      algorithm,
      publicClaims: {},
      privateClaims: {},
    });

    const verified = await provider.verify({
      token,
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
            createProvider(badAlgs, credentials).provider.sign({
              algorithm,
              privateClaims: {},
              publicClaims: {},
            });
          }).toThrow(JwtProviderBadConfigError);
        });
      });
    }
  );

  test.each([{ algorithm: 'ES256' }, { algorithm: 'ES384' }, { algorithm: 'ES512' }] satisfies { algorithm: JwtAlgorithmsESSchema }[])(
    'Probabilistic algorithm $algorithm should generate a different signature each time',
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

      expect(token1).not.toEqual(token2);
    }
  );

  test.each([{ algorithm: 'ES256' }, { algorithm: 'ES384' }, { algorithm: 'ES512' }] satisfies { algorithm: JwtAlgorithmsESSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { provider, publicKey } = createProvider([algorithm], algorithm);

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
