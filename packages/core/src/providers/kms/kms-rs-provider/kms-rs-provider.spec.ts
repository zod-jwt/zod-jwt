import { GetPublicKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { config } from 'dotenv';
import { verify } from 'jsonwebtoken';
import path from 'path';
import { describe, expect, it, test } from 'vitest';
import { z } from 'zod';
import { Jwt } from '../../../jwt/jwt.js';
import { JwtAlgorithmsRSSchema } from '../../../schema/index.js';
import { KmsRsProvider } from '../../index.js';

const { parsed } = config({
  path: path.resolve(__dirname, '../../../../../../.env'),
});
async function createProvider(algorithms: JwtAlgorithmsRSSchema[]) {
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

  const provider = new KmsRsProvider({
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
    publicKey,
  };
}

describe('JwtRsProvider', () => {
  it('should exist', () => {
    expect(KmsRsProvider).toBeTruthy();
  });

  test.each(['RS256', 'RS384', 'RS512'] satisfies JwtAlgorithmsRSSchema[])('%s should create and validate a token', async (algorithm) => {
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

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
    'Deterministic algorithm $algorithm should generate the same token each time',
    async ({ algorithm }) => {
      const { jwt, data, schema } = await createProvider([algorithm]);

      const timestamp = new Date();

      const token1 = await jwt.sign({
        algorithm,
        data,
        provider: 'test',
        schema,
        timestamp,
      });
      const token2 = await jwt.sign({
        algorithm,
        data,
        provider: 'test',
        schema,
        timestamp,
      });

      expect(token1).toEqual(token2);
    }
  );

  test.each([{ algorithm: 'RS256' }, { algorithm: 'RS384' }, { algorithm: 'RS512' }] satisfies { algorithm: JwtAlgorithmsRSSchema }[])(
    '$algorithm is compatible with jsonwebtoken',
    async ({ algorithm }) => {
      const { jwt, schema, data, publicKey } = await createProvider([algorithm]);

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
