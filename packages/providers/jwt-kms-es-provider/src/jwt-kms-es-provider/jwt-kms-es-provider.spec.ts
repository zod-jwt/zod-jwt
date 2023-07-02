import { GetPublicKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { JwtAlgorithmsESSchema } from '@zod-jwt/core';
import { config } from 'dotenv';
import { verify } from 'jsonwebtoken';
import path from 'path';
import { describe, expect, it, test } from 'vitest';
import { z } from 'zod';
import { JwtKmsEsProvider } from '../index.js';

const { parsed } = config({
  path: path.resolve(__dirname, '../../../../../.env'),
});
async function createProvider(algorithms: JwtAlgorithmsESSchema[], credentials: JwtAlgorithmsESSchema) {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const region = parsed!.AWS_REGION as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const accessKeyId = parsed!.AWS_ACCESS_KEY_ID as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const secretAccessKey = parsed!.AWS_SECRET_ACCESS_KEY as string;
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const account = parsed!.AWS_ACCOUNT_ID as string;

  const client = new KMSClient({
    region,
    credentials: {
      accessKeyId,
      secretAccessKey,
    },
  });

  const { PublicKey } = await client.send(
    new GetPublicKeyCommand({
      KeyId: `arn:aws:kms:${region}:${account}:alias/TEST_${credentials}`,
    })
  );

  const publicKey = Buffer.from(PublicKey as Uint8Array).toString('base64');

  const provider = new JwtKmsEsProvider({
    algorithms,
    credentials: {
      account,
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      kms: {
        ES256: {
          keyAlias: 'TEST_ES256',
        },
        ES384: {
          keyAlias: 'TEST_ES384',
        },
        ES512: {
          keyAlias: 'TEST_ES512',
        },
      },
    },
    privateClaimsSchema: z.object({}),
    publicClaimsSchema: z.object({}),
  });
  return {
    provider,
    publicKey,
  };
}

describe('JwtEsProvider', () => {
  it('should exist', () => {
    expect(JwtKmsEsProvider).toBeTruthy();
  });

  test.each(['ES256', 'ES384', 'ES512'] satisfies JwtAlgorithmsESSchema[])('%s should create and validate a token', async (algorithm) => {
    const { provider } = await createProvider([algorithm], algorithm);

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

  test.each([{ algorithm: 'ES256' }, { algorithm: 'ES384' }, { algorithm: 'ES512' }] satisfies { algorithm: JwtAlgorithmsESSchema }[])(
    'Probabilistic algorithm $algorithm should generate a different token each time',
    async ({ algorithm }) => {
      const { provider } = await createProvider([algorithm], algorithm);

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
      const { provider, publicKey } = await createProvider([algorithm], algorithm);

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

      const key = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;

      verify(token, key, { algorithms: [algorithm], clockTimestamp: Math.floor(timestamp.getTime() / 1000), complete: true }, (error, jwt) => {
        expect(error).toBeNull();
        expect(jwt).toBeTruthy();
        expect(jwt?.header.alg).toEqual(decoded.header.alg);
        expect(jwt?.header.typ).toEqual(decoded.header.typ);
        expect(jwt?.signature).toEqual(decoded.signature);
      });
    }
  );
});
