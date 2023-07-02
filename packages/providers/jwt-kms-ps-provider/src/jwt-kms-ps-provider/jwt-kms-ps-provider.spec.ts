import { GetPublicKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { JwtAlgorithmsPSSchema } from '@zod-jwt/core';
import { config } from 'dotenv';
import { verify } from 'jsonwebtoken';
import path from 'path';
import { describe, expect, it, test } from 'vitest';
import { z } from 'zod';
import { JwtKmsPsProvider } from '../index.js';

const { parsed } = config({
  path: path.resolve(__dirname, '../../../../../.env'),
});
async function createProvider(algorithms: JwtAlgorithmsPSSchema[]) {
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
      KeyId: `arn:aws:kms:${region}:${account}:alias/TEST_RSA_2048`,
    })
  );

  const publicKey = Buffer.from(PublicKey as Uint8Array).toString('base64');

  const provider = new JwtKmsPsProvider({
    algorithms,
    credentials: {
      account,
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      kms: {
        keyAlias: 'TEST_RSA_2048',
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

describe('JwtPsProvider', () => {
  it('should exist', () => {
    expect(JwtKmsPsProvider).toBeTruthy();
  });

  test.each(['PS256', 'PS384', 'PS512'] satisfies JwtAlgorithmsPSSchema[])('%s should create and validate a token', async (algorithm) => {
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

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
    'Probabilistic algorithm $algorithm should generate a different token each time',
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

      expect(token1).not.toEqual(token2);
    }
  );

  test.each([{ algorithm: 'PS256' }, { algorithm: 'PS384' }, { algorithm: 'PS512' }] satisfies { algorithm: JwtAlgorithmsPSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { provider, publicKey } = await createProvider([algorithm]);

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
