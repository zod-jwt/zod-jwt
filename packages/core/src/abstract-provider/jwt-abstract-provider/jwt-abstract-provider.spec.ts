import ms from 'ms';
import { afterEach, describe, expect, it, test, vi } from 'vitest';
import { z } from 'zod';
import { JwtTokenClaimError, JwtTokenInvalidSignatureError } from '../../errors/index.js';
import { Base64UrlEncoded, JwtAudienceClaim, JwtHeaderSchema, JwtIssuerClaim, JwtJtiClaim, JwtSubjectClaim } from '../../schema/index.js';
import { JwtProviderSignArgs, JwtProviderVerifyArgs } from '../jwt-abstract-provider-types/abstract-jwt-types.js';
import { JwtAbstractProvider, JwtProviderConstructorArgs } from './jwt-abstract-provider.js';

export type JwtMockProviderConfig<
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = Omit<
  JwtProviderConstructorArgs<'RS256', 'RS256', PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>,
  'algorithms' | 'providerName'
>;

export class JwtMockProvider<
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<'RS256', 'RS256', PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  constructor(private config: JwtMockProviderConfig<PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['RS256'],
      algorithms: ['RS256'],
      privateClaimsSchema: config.privateClaimsSchema,
      publicClaimsSchema: config.publicClaimsSchema,
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

// These tests validate the behavior of the abstract class
// A fake provider is used to run the tests against
describe('JwtAbstractProvider', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('can create a token with no schemas', async () => {
    const provider = new JwtMockProvider({});
    const token = await provider.sign({ algorithm: 'RS256', privateClaims: {}, publicClaims: {} });
    expect(token).toBeTruthy();
  });

  it('can create a token with only the publicClaimsSchema', async () => {
    const provider = new JwtMockProvider({
      publicClaimsSchema: z.object({
        aud: z.literal('test'),
      }),
    });
    const token = await provider.sign({ algorithm: 'RS256', privateClaims: {}, publicClaims: { aud: 'test' } });
    expect(token).toBeTruthy();
    const verified = await provider.verify({ token });
    expect(verified).toBeTruthy();
  });

  it('can create a token with only the privateClaimsSchema', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({
        test: z.literal('test'),
      }),
    });
    const token = await provider.sign({ algorithm: 'RS256', privateClaims: { test: 'test' }, publicClaims: {} });
    expect(token).toBeTruthy();
    const verified = await provider.verify({ token });
    expect(verified).toBeTruthy();
  });

  test.each(['nbf', 'exp', 'iat'] as const)('should set the %s claim by default', async (claim) => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
    });

    const { publicClaims } = await provider.decode({
      token,
    });
    expect(publicClaims[claim]).toBeTypeOf('number');
  });

  test.each(['iss', 'sub', 'jti', 'aud'] as const)('should not set the %s claim by default', async (claim) => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
    });

    const { publicClaims } = await provider.decode({
      token,
    });

    expect(publicClaims[claim]).toBeUndefined();
  });

  test('nbf claim should equal iat claim by default', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
    });

    const { publicClaims } = await provider.decode({
      token,
    });

    expect(publicClaims.nbf).toEqual(publicClaims.iat);
  });

  test('exp claim should be set 15 minutes ahead by default', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const timestamp = new Date();

    const expectedExp = Math.floor((timestamp.getTime() + 60000 * 15) / 1000);

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
      timestamp,
    });

    const { publicClaims } = await provider.decode({
      token,
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
      const provider = new JwtMockProvider({
        privateClaimsSchema: z.object({}),
        publicClaimsSchema: z.object({}),
      });

      const timestamp = new Date();

      const expectedValue =
        typeof value === 'string'
          ? // prettier-ignore
            Math.floor(((timestamp.getTime() + ms(value)) / 1000 ) )
          : Math.floor((timestamp.getTime() + value) / 1000);

      const token = await provider.sign({
        algorithm: 'RS256',
        privateClaims: {},
        publicClaims: {
          [claim]: value,
        },
        timestamp,
      });

      const { publicClaims } = await provider.decode({
        token,
      });

      expect(publicClaims[claim]).toEqual(expectedValue);
    }
  );

  test('aud, jti, sub, and iss claims should be set when provided by the user', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({
        iss: z.string(),
        sub: z.string(),
        aud: z.string(),
        jti: z.string(),
      }),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {
        aud: 'audience',
        jti: 'jti',
        iss: 'issuer',
        sub: 'subject',
      },
    });

    const { publicClaims } = await provider.decode({
      token,
    });

    expect(publicClaims.aud).toEqual('audience');
    expect(publicClaims.jti).toEqual('jti');
    expect(publicClaims.iss).toEqual('issuer');
    expect(publicClaims.sub).toEqual('subject');
  });

  test.each(['iss', 'sub', 'aud', 'jti'] as const)(
    'token creation fails when user input deviates from publicClaimsSchema: %s claim',
    async (claim) => {
      const provider = new JwtMockProvider({
        privateClaimsSchema: z.object({}),
        publicClaimsSchema: z.object({
          [claim]: z.string(),
        }),
      });

      await expect(async () => {
        return provider.sign({
          algorithm: 'RS256',
          privateClaims: {},
          publicClaims: {},
        });
      }).rejects.toThrowError(JwtTokenClaimError);
    }
  );

  it('token creation fails when user input deviates from privateClaimsSchema', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({
        userId: z.string(),
      }),
      publicClaimsSchema: z.object({}),
    });

    await expect(async () => {
      return provider.sign({
        algorithm: 'RS256',
        // @ts-expect-error test
        privateClaims: {},
        publicClaims: {},
      });
    }).rejects.toThrowError(JwtTokenClaimError);
  });

  test('token validation fails when exp is in the past', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const timestamp = new Date();

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {
        exp: -2000,
      },
      timestamp,
    });

    await expect(
      provider.verify({
        token,
        clockSkew: 0,
        timestamp,
      })
    ).rejects.toThrowError(JwtTokenClaimError);
  });

  test('token validation fails when nbf is in the future', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const timestamp = new Date();

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {
        nbf: 2000,
      },
      timestamp,
    });

    await expect(
      provider.verify({
        token,
        clockSkew: 0,
        timestamp,
      })
    ).rejects.toThrowError(JwtTokenClaimError);
  });

  test('clockSkew allows normally invalid nbf and exp claims', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const timestamp = new Date();
    const jwtTime = Math.floor(timestamp.getTime() / 1000);

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {
        exp: -1000,
        nbf: 1000,
      },
      timestamp,
    });

    await expect(
      provider.verify({
        token,
        timestamp,
      })
    ).rejects.toThrow(JwtTokenClaimError);

    const { publicClaims } = await provider.verify({
      clockSkew: 1000,
      token,
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

    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({
        test: z.literal('test'),
      }),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {
        test: 'test',
      },
      publicClaims: {},
    });

    await provider.verify({
      token,
      validate: async (args) => {
        return validate(args);
      },
    });

    expect(validate).toHaveBeenCalledOnce();
  });

  test('validate callback should throw an error when false is returned', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
    });

    await expect(
      provider.verify({
        token,
        validate: async () => {
          return false;
        },
      })
    ).rejects.toThrow(JwtTokenClaimError);
  });

  test('validate callback should not throw an error when true is returned', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({}),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {},
      publicClaims: {},
    });

    await expect(
      provider.verify({
        token,
        validate: async () => {
          return true;
        },
      })
    ).resolves.toBeTruthy();
  });

  test('should return a token with a valid signature', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({
        test: z.literal('test'),
      }),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {
        test: 'test',
      },
      publicClaims: {},
    });

    await expect(
      provider.verify({
        token,
      })
    ).resolves.toBeTruthy();
  });

  test('should reject a token with an invalid signature', async () => {
    const provider = new JwtMockProvider({
      privateClaimsSchema: z.object({
        test: z.literal('test'),
      }),
      publicClaimsSchema: z.object({}),
    });

    const token = await provider.sign({
      algorithm: 'RS256',
      privateClaims: {
        test: 'test',
      },
      publicClaims: {},
    });

    await expect(
      provider.verify({
        token: `${token}a`,
      })
    ).rejects.toThrow(JwtTokenInvalidSignatureError);
  });
});
