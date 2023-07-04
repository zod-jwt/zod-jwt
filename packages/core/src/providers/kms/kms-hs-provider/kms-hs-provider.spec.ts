import { config } from 'dotenv';
import path from 'path';
import { describe, expect, it, test } from 'vitest';
import { z } from 'zod';
import { Jwt } from '../../../jwt/jwt.js';
import { JwtAlgorithmsHSSchema } from '../../../schema/index.js';
import { KmsHsProvider } from '../../index.js';

const { parsed } = config({
  path: path.resolve(__dirname, '../../../../../../.env'),
});
async function createProvider(algorithms: JwtAlgorithmsHSSchema[]) {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const region = parsed!.AWS_REGION as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const accessKeyId = parsed!.AWS_ACCESS_KEY_ID as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const secretAccessKey = parsed!.AWS_SECRET_ACCESS_KEY as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const account = parsed!.AWS_ACCOUNT_ID as string;

  const provider = new KmsHsProvider({
    algorithms,
    credentials: {
      account,
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      kms: {
        HS256: {
          keyAlias: 'TEST_HS256',
        },
        HS384: {
          keyAlias: 'TEST_HS384',
        },
        HS512: {
          keyAlias: 'TEST_HS512',
        },
      },
    },
    providerName: 'test',
  });
  const schema = z.object({
    privateClaims: z.object({}),
    publicClaims: z.object({}),
  });
  const data = {
    privateClaims: {},
    publicClaims: {},
  };
  const jwt = new Jwt({
    providers: [provider],
  });
  return {
    jwt,
    schema,
    data,
    provider,
  };
}

describe('JwtHsProvider', () => {
  it('should exist', () => {
    expect(KmsHsProvider).toBeTruthy();
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtAlgorithmsHSSchema[])('%s should create and validate a token', async (algorithm) => {
    const { jwt, schema, data } = await createProvider([algorithm]);

    const token = await jwt.sign({
      algorithm,
      schema,
      data,
      provider: 'test',
    });

    const verified = await jwt.verify({
      token,
      schema,
      provider: 'test',
    });

    expect(verified).toBeTruthy();
  });

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { jwt, schema, data, provider } = await createProvider([algorithm]);

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

  // cannot test against jsonwebtoken because symmetric algorithm and KMS doesn't give you access to the private key
});
