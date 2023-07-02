import { JwtAlgorithmsHSSchema } from '@zod-jwt/core';
import { config } from 'dotenv';
import path from 'path';
import { describe, expect, it, test } from 'vitest';
import { z } from 'zod';
import { JwtKmsHsProvider } from '../index.js';

const { parsed } = config({
  path: path.resolve(__dirname, '../../../../../.env'),
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

  const provider = new JwtKmsHsProvider({
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
    privateClaimsSchema: z.object({}),
    publicClaimsSchema: z.object({}),
  });
  return {
    provider,
  };
}

describe('JwtHsProvider', () => {
  it('should exist', () => {
    expect(JwtKmsHsProvider).toBeTruthy();
  });

  test.each(['HS256', 'HS384', 'HS512'] satisfies JwtAlgorithmsHSSchema[])('%s should create and validate a token', async (algorithm) => {
    const { provider } = await createProvider([algorithm]);

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

  test.each([{ algorithm: 'HS256' }, { algorithm: 'HS384' }, { algorithm: 'HS512' }] satisfies { algorithm: JwtAlgorithmsHSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { provider } = await createProvider([algorithm]);

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

  // cannot test against jsonwebtoken because symmetric algorithm and KMS doesn't give you access to the private key
});
