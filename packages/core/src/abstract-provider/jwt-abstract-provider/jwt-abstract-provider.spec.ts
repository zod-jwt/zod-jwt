import ms from 'ms';
import { afterEach, describe, expect, it, test, vi } from 'vitest';
import { z } from 'zod';
import { JwtTokenClaimError, JwtTokenInvalidSignatureError } from '../../errors/index.js';
import { Jwt } from '../../jwt/jwt.js';
import { Base64UrlEncoded, JwtHeaderSchema } from '../../schema/index.js';
import { JwtProviderSignArgs, JwtProviderVerifyArgs } from '../jwt-abstract-provider-types/abstract-jwt-types.js';
import { JwtAbstractProvider, JwtProviderConstructorArgs } from './jwt-abstract-provider.js';

export type JwtMockProviderConfig = Omit<JwtProviderConstructorArgs<'test', 'RS256', 'RS256'>, 'algorithms' | 'providerName'>;

export class JwtMockProvider extends JwtAbstractProvider<'test', 'RS256', 'RS256'> {
  constructor(private config: JwtMockProviderConfig) {
    super({
      supportedAlgorithms: ['RS256'],
      algorithms: ['RS256'],
      providerName: 'test',
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async _generateSignature(args: JwtProviderSignArgs<'RS256'>) {
    return `test_signature` as Base64UrlEncoded;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async _verifySignature(args: JwtProviderVerifyArgs<'RS256'>) {
    return args.signature === `test_signature`;
  }
}

function createProvider() {
  const provider = new JwtMockProvider({});
  const jwt = new Jwt({ providers: [provider] });
  const schema = z.object({
    publicClaims: z.object({}),
    privateClaims: z.object({}),
  });
  const data = {
    privateClaims: {},
    publicClaims: {},
  };
  return {
    provider,
    jwt,
    schema,
    data,
  };
}

// These tests validate the behavior of the abstract class
// A fake provider is used to run the tests against
describe('JwtAbstractProvider', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('can create a token with no schemas', async () => {
    const { jwt, schema, data } = createProvider();
    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      data,
      schema,
    });
    expect(token).toBeTruthy();
  });

  test.each(['nbf', 'exp', 'iat'] as const)('should set the %s claim by default', async (claim) => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      schema,
      data,
      provider: 'test',
    });

    const { publicClaims } = await jwt.decode({
      token,
      provider: 'test',
      schema,
    });
    expect(publicClaims[claim]).toBeTypeOf('number');
  });

  test.each(['iss', 'sub', 'jti', 'aud'] as const)('should not set the %s claim by default', async (claim) => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      data,
      schema,
    });

    const { publicClaims } = await jwt.decode({
      token,
      provider: 'test',
      schema,
    });

    expect((publicClaims as Record<string, unknown>)[claim]).toBeUndefined();
  });

  test('nbf claim should equal iat claim by default', async () => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      schema,
      data,
    });

    const { publicClaims } = await jwt.decode({
      token,
      provider: 'test',
      schema,
    });

    expect(publicClaims.nbf).toEqual(publicClaims.iat);
  });

  test('exp claim should be set 15 minutes ahead by default', async () => {
    const { jwt, schema, data } = createProvider();

    const timestamp = new Date();

    const expectedExp = Math.floor((timestamp.getTime() + 60000 * 15) / 1000);

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      schema,
      data,
      timestamp,
    });

    const { publicClaims } = await jwt.decode({
      token,
      provider: 'test',
      schema,
    });

    expect(publicClaims.exp).toEqual(expectedExp);
  });

  test.each([
    {
      claim: 'nbf' as const,
      type: 'string',
      value: '-1 minute',
    },
    {
      claim: 'exp' as const,
      type: 'string',
      value: '10 minutes',
    },
    {
      claim: 'iat' as const,
      type: 'string',
      value: '-2 minutes',
    },
    {
      claim: 'nbf' as const,
      type: 'number',
      value: 60000 * -1,
    },
    {
      claim: 'exp' as const,
      type: 'number',
      value: 60000 * 10,
    },
    {
      claim: 'iat' as const,
      type: 'number',
      value: 60000 * -2,
    },
  ] satisfies ({ claim: string; type: 'string'; value: string } | { claim: string; type: 'number'; value: number })[])(
    'can manually set the $claim with a $type',
    async ({ claim, value }) => {
      const { jwt, schema, data } = createProvider();
      const timestamp = new Date();

      const expectedValue =
        typeof value === 'string'
          ? // prettier-ignore
            Math.floor(((timestamp.getTime() + ms(value)) / 1000 ) )
          : Math.floor((timestamp.getTime() + value) / 1000);

      const token = await jwt.sign({
        algorithm: 'RS256',
        provider: 'test',
        schema,
        data: {
          privateClaims: {},
          publicClaims: {
            [claim]: value,
          },
        },
        timestamp,
      });

      const { publicClaims } = await jwt.decode({
        token,
        provider: 'test',
        schema,
      });

      expect(publicClaims[claim]).toEqual(expectedValue);
    }
  );

  test.each(['iss', 'sub', 'aud', 'jti'] as const)(
    'token creation fails when user input deviates from publicClaimsSchema: %s claim',
    async (claim) => {
      const { jwt } = createProvider();

      await expect(async () => {
        return jwt.sign({
          algorithm: 'RS256',
          provider: 'test',
          data: {
            privateClaims: {},
            publicClaims: {},
          },
          schema: z.object({
            privateClaims: z.object({}),
            publicClaims: z.object({
              [claim]: z.string(),
            }),
          }),
        });
      }).rejects.toThrowError(JwtTokenClaimError);
    }
  );

  it('token creation fails when user input deviates from privateClaimsSchema', async () => {
    const { jwt, schema, data } = createProvider();

    await expect(async () => {
      return jwt.sign({
        algorithm: 'RS256',
        provider: 'test',
        schema: z.object({
          privateClaims: z.object({ test: z.literal('test') }),
          publicClaims: z.object({}),
        }),
        data: {
          publicClaims: {},
          // @ts-expect-error bad input
          privateClaims: {},
        },
      });
    }).rejects.toThrowError(JwtTokenClaimError);
  });

  test('token validation fails when exp is in the past', async () => {
    const { jwt, schema, data } = createProvider();

    const timestamp = new Date();

    const token = await jwt.sign({
      algorithm: 'RS256',
      schema,
      data: {
        publicClaims: {
          exp: -2000,
        },
        privateClaims: {},
      },
      provider: 'test',
      timestamp,
    });

    await expect(
      jwt.verify({
        token,
        provider: 'test',
        schema,
        clockSkew: 0,
        timestamp,
      })
    ).rejects.toThrowError(JwtTokenClaimError);
  });

  test('token validation fails when nbf is in the future', async () => {
    const { jwt, schema, data } = createProvider();

    const timestamp = new Date();

    const token = await jwt.sign({
      algorithm: 'RS256',
      data: {
        privateClaims: {},
        publicClaims: {
          nbf: 2000,
        },
      },
      provider: 'test',
      schema,
      timestamp,
    });

    await expect(
      jwt.verify({
        token,
        clockSkew: 0,
        provider: 'test',
        schema,
        timestamp,
      })
    ).rejects.toThrowError(JwtTokenClaimError);
  });

  test('clockSkew allows normally invalid nbf and exp claims', async () => {
    const { jwt, schema, data } = createProvider();
    const timestamp = new Date();
    const jwtTime = Math.floor(timestamp.getTime() / 1000);

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      data: {
        publicClaims: {
          exp: -1000,
          nbf: 1000,
        },
        privateClaims: {},
      },
      schema,
      timestamp,
    });

    await expect(
      jwt.verify({
        token,
        provider: 'test',
        schema,
        timestamp,
      })
    ).rejects.toThrow(JwtTokenClaimError);

    const { publicClaims } = await jwt.verify({
      clockSkew: 1000,
      token,
      provider: 'test',
      schema,
      timestamp,
    });

    expect(publicClaims.exp).lessThan(jwtTime);
    expect(publicClaims.nbf).greaterThan(jwtTime);
  });

  test('validate callback should be called with valid data when verifying a token', async () => {
    const validate = vi.fn(
      (args: {
        privateClaims: { test: 'test' };
        publicClaims: {
          iat: number;
          exp: number;
          nbf: number;
        };
        header: JwtHeaderSchema<'RS256'>;
      }) => {
        expect(args.privateClaims.test).toEqual('test');
        expect(args.publicClaims.iat).toBeTypeOf('number');
        expect(args.publicClaims.exp).toBeTypeOf('number');
        expect(args.publicClaims.nbf).toBeTypeOf('number');
        expect(args.header.alg).toEqual('RS256');
        expect(args.header.typ).toEqual('JWT');
        return true;
      }
    );

    const { jwt } = createProvider();

    const schema = z.object({
      publicClaims: z.object({}),
      privateClaims: z.object({
        test: z.literal('test'),
      }),
    });

    const token = await jwt.sign({
      algorithm: 'RS256',
      schema,
      data: {
        privateClaims: {
          test: 'test',
        },
        publicClaims: {},
      },
      provider: 'test',
    });

    await jwt.verify({
      token,
      provider: 'test',
      schema,
      validate: async (args) => {
        return validate(args);
      },
    });

    expect(validate).toHaveBeenCalledOnce();
  });

  test('validate callback should throw an error when false is returned', async () => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      data,
      schema,
      provider: 'test',
    });

    await expect(
      jwt.verify({
        token,
        provider: 'test',
        schema,
        validate: async () => {
          return false;
        },
      })
    ).rejects.toThrow(JwtTokenClaimError);
  });

  test('validate callback should not throw an error when true is returned', async () => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      schema,
      data,
    });

    await expect(
      jwt.verify({
        token,
        provider: 'test',
        schema,
        validate: async () => {
          return true;
        },
      })
    ).resolves.toBeTruthy();
  });

  test('should return a token with a valid signature', async () => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      schema,
      data,
    });

    await expect(
      jwt.verify({
        token,
        provider: 'test',
        schema,
      })
    ).resolves.toBeTruthy();
  });

  test('should reject a token with an invalid signature', async () => {
    const { jwt, schema, data } = createProvider();

    const token = await jwt.sign({
      algorithm: 'RS256',
      provider: 'test',
      schema,
      data,
    });

    await expect(
      jwt.verify({
        token: `${token}a`,
        provider: 'test',
        schema,
      })
    ).rejects.toThrow(JwtTokenInvalidSignatureError);
  });
});
