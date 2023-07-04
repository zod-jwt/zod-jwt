import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
import { JwtAlgorithmsRSSchema } from '../../../schema/index.js';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { Jwt } from '../../../jwt/jwt.js';
import { getTestCredentials } from '../../../tests/test-helper-get-credentials.js';
import { LocalRsProvider } from '../../index.js';

function createProvider(algorithms: JwtAlgorithmsRSSchema[], credentials: JwtAlgorithmsRSSchema) {
  const schema = z.object({
    publicClaims: z.object({}),
    privateClaims: z.object({}),
  });

  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new LocalRsProvider({
    algorithms,
    credentials: {
      publicKey,
      privateKey,
    },
    providerName: 'test',
  });

  const jwt = new Jwt({
    providers: [provider],
  });

  return {
    provider,
    privateKey,
    publicKey,
    schema,
    jwt,
    data: { privateClaims: {}, publicClaims: {} },
  };
}

describe('JwtRsProvider', () => {
  it('should exist', () => {
    expect(LocalRsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(LocalRsProvider.prototype as any, '_validatePublicKey');

    createProvider(['RS256'], 'RS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(LocalRsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['RS256'], 'RS256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['RS256', 'RS384', 'RS512'] satisfies JwtAlgorithmsRSSchema[])('%s should create and validate a token', async (algorithm) => {
    const { jwt, schema, data } = createProvider([algorithm], algorithm);

    const token = await jwt.sign({
      provider: 'test',
      algorithm,
      schema,
      data,
    });

    const verified = await jwt.verify({
      provider: 'test',
      schema,
      token,
    });

    expect(verified).toBeTruthy();
  });

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { jwt, schema, data } = createProvider([algorithm], algorithm);

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

      expect(token1).toEqual(token2);
    }
  );

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { jwt, data, schema, publicKey } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token = await jwt.sign({
        provider: 'test',
        algorithm,
        schema,
        data,
        timestamp,
      });

      const decoded = await jwt.decode({
        provider: 'test',
        token,
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
