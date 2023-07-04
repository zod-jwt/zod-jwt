import { verify } from 'jsonwebtoken';
import { describe, expect, it, test, vitest } from 'vitest';
import { z } from 'zod';
// eslint-disable-next-line @nx/enforce-module-boundaries
import { JwtProviderBadConfigError } from '../../../errors/index.js';
import { Jwt } from '../../../jwt/jwt.js';
import { JwtAlgorithmsPSSchema } from '../../../schema/index.js';
import { getTestCredentials } from '../../../tests/test-helper-get-credentials.js';
import { LocalPsProvider } from '../../index.js';

function createProvider(algorithms: JwtAlgorithmsPSSchema[], credentials: JwtAlgorithmsPSSchema) {
  const { privateKey, publicKey } = getTestCredentials(credentials);
  const provider = new LocalPsProvider({
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
    privateKey,
    publicKey,
  };
}

describe('JwtPsProvider', () => {
  it('should exist', () => {
    expect(LocalPsProvider).toBeTruthy();
  });

  it('should validate the publicKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePublicKey = vitest.spyOn(LocalPsProvider.prototype as any, '_validatePublicKey');

    createProvider(['PS256'], 'PS256');

    expect(validatePublicKey).toHaveBeenCalledTimes(1);
  });

  it('should validate the privateKey', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const validatePrivateKey = vitest.spyOn(LocalPsProvider.prototype as any, '_validatePrivateKey');

    createProvider(['PS256'], 'PS256');

    expect(validatePrivateKey).toHaveBeenCalledTimes(1);
  });

  test.each(['PS256', 'PS384', 'PS512'] satisfies JwtAlgorithmsPSSchema[])('%s should create and validate a token', async (algorithm) => {
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
            createProvider(badAlgs, credentials);
          }).toThrow(JwtProviderBadConfigError);
        });
      });
    }
  );

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
    'Probabilistic algorithm $algorithm should generate a different signature each time',
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
        schema,
        data,
        provider: 'test',
        timestamp,
      });

      expect(token1).not.toEqual(token2);
    }
  );

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { jwt, schema, data, publicKey } = createProvider([algorithm], algorithm);

      const timestamp = new Date();

      const token = await jwt.sign({
        algorithm,
        schema,
        data,
        provider: 'test',
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
