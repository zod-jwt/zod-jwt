import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { JwtProviderInvalidKeyMaterialError } from '../../../errors/index.js';
import { Jwt } from '../../../jwt/jwt.js';
import { JwtAlgorithmsHSSchema } from '../../../schema/index.js';
import { getTestCredentials } from '../../../tests/test-helper-get-credentials.js';
import { LocalHsProvider } from '../../index.js';

function createProvider(algorithms: JwtAlgorithmsHSSchema[], credentials: JwtAlgorithmsHSSchema) {
  const { secret } = getTestCredentials(credentials, 'valid', 'hex');
  const provider = new LocalHsProvider({
    algorithms,
    credentials: {
      secret,
      encoding: 'hex',
    },
    providerName: 'test',
  });
  const jwt = new Jwt({
    providers: [provider],
  });
  const schema = z.object({
    privateClaims: z.object({}),
    publicClaims: z.object({}),
  });
  const data = {
    privateClaims: {},
    publicClaims: {},
  };
  return {
    jwt,
    schema,
    data,
    provider,
    secret,
  };
}

describe('JwtLocalHsProvider', () => {
  it('should exist', () => {
    expect(LocalHsProvider).toBeTruthy();
  });

  it('should validate the secret', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(LocalHsProvider.prototype as any, '_validateSecretKey');

    createProvider(['HS256'], 'HS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtAlgorithmsHSSchema[])('%s should create and validate a token', async (algorithm) => {
    const { jwt, data, schema } = createProvider([algorithm], algorithm);

    const token = await jwt.sign({
      algorithm,
      data,
      schema,
      provider: 'test',
    });

    const verified = await jwt.verify({
      token,
      provider: 'test',
      schema,
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
          const { jwt, data, schema } = createProvider([algorithm], credentials);
          const token = await jwt.sign({
            provider: 'test',
            algorithm,
            data,
            schema,
          });

          const res = await jwt.verify({
            token,
            provider: 'test',
            schema,
          });

          expect(res).toBeTruthy();
        });
      });
    }
  );

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { jwt, schema, data } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token1 = await jwt.sign({
        algorithm,
        schema,
        data,
        provider: 'test',
        timestamp,
      });
      const token2 = await jwt.sign({
        algorithm,
        data,
        schema,
        provider: 'test',
        timestamp,
      });

      expect(token1).toEqual(token2);
    }
  );

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { provider, secret, jwt, schema, data } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token = await jwt.sign({
        algorithm,
        data,
        schema,
        provider: 'test',
        timestamp,
      });

      const decoded = await jwt.decode({
        token,
        provider: 'test',
        schema,
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
