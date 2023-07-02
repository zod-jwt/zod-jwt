import { JwtAlgorithmsPSSchema, JwtProviderBadConfigError } from '@zod-jwt/core';
import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { getTestCredentials } from '../../../../core/src/tests/test-helper-get-credentials.js';
import { JwtLocalPsProvider } from '../index.js';

function createProvider(algorithms: JwtAlgorithmsPSSchema[], credentials: JwtAlgorithmsPSSchema) {
  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new JwtLocalPsProvider({
    algorithms,
    credentials: {
      ...(credentials === 'PS256'
        ? {
            PS256: {
              publicKey,
              privateKey,
            },
          }
        : credentials === 'PS384'
        ? {
            PS384: {
              publicKey,
              privateKey,
            },
          }
        : {
            PS512: {
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

describe('JwtPsProvider', () => {
  it('should exist', () => {
    expect(JwtLocalPsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(JwtLocalPsProvider.prototype as any, '_validatePublicKey');

    createProvider(['PS256'], 'PS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(JwtLocalPsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['PS256'], 'PS256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['PS256', 'PS384', 'PS512'] satisfies JwtAlgorithmsPSSchema[])('%s should create and validate a token', async (algorithm) => {
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
      credentials: 'PS256',
      badAlgs: ['PS384', 'PS512'],
    },
    {
      credentials: 'PS384',
      badAlgs: ['PS256', 'PS512'],
    },
    {
      credentials: 'PS512',
      badAlgs: ['PS256', 'PS384'],
    },
  ] satisfies { credentials: JwtAlgorithmsPSSchema; badAlgs: JwtAlgorithmsPSSchema[] }[])(
    '$credentials cannot be used to sign other PS algorithms',
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

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
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

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
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
