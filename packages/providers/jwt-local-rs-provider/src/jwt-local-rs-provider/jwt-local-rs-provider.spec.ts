import { JwtAlgorithmsRSSchema } from '@zod-jwt/core';
import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { getTestCredentials } from '../../../../core/src/tests/test-helper-get-credentials.js';
import { JwtLocalRsProvider } from '../index.js';

function createProvider(algorithms: JwtAlgorithmsRSSchema[], credentials: JwtAlgorithmsRSSchema) {
  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new JwtLocalRsProvider({
    algorithms,
    credentials: {
      publicKey,
      privateKey,
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

describe('JwtRsProvider', () => {
  it('should exist', () => {
    expect(JwtLocalRsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(JwtLocalRsProvider.prototype as any, '_validatePublicKey');

    createProvider(['RS256'], 'RS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(JwtLocalRsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['RS256'], 'RS256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['RS256', 'RS384', 'RS512'] satisfies JwtAlgorithmsRSSchema[])('%s should create and validate a token', async (algorithm) => {
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

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
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

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
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
