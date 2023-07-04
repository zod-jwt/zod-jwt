import ms from 'ms';
import { ZodError, ZodObject, ZodTypeAny, z } from 'zod';
import { JwtAbstractProvider, JwtProviderSignArgs, JwtProviderVerifyArgs } from '../abstract-provider/index.js';
import { JwtProviderBadConfigError, JwtTokenClaimError, JwtTokenInvalidSignatureError } from '../errors/index.js';
import {
  Base64UrlEncoded,
  JwtAlgorithmsRSSchema,
  JwtAudienceClaim,
  JwtHeaderSchema,
  JwtIssuerClaim,
  JwtJtiClaim,
  JwtSubjectClaim,
} from '../schema/index.js';
import { constructHeaderPayload, constructPublicClaims, decodeJwt, toBase64, toBase64Url } from '../util/index.js';

class Test<ProviderName extends string, EnabledAlgorithms extends JwtAlgorithmsRSSchema> extends JwtAbstractProvider<
  ProviderName,
  JwtAlgorithmsRSSchema,
  EnabledAlgorithms
> {
  constructor(config: { providerName: ProviderName; algorithms: EnabledAlgorithms[] }) {
    super({
      algorithms: config.algorithms,
      supportedAlgorithms: ['RS256', 'RS384', 'RS512'],
      providerName: config.providerName,
    });
  }
  public override async _generateSignature(args: JwtProviderSignArgs): Promise<Base64UrlEncoded> {
    return '' as Base64UrlEncoded;
  }
  public override async _verifySignature(args: JwtProviderVerifyArgs): Promise<boolean> {
    return true;
  }
}

export class Jwt<ProviderNames extends string, Providers extends JwtAbstractProvider<ProviderNames>> {
  constructor(private config: { providers: Providers[] }) {}

  private getProvider(providerName: ProviderNames) {
    const [provider] = this.config.providers.filter((p) => p.providerName === providerName);
    if (!provider) {
      throw new JwtProviderBadConfigError({
        message: `Attempted to get provider ${providerName}, but it does not exist`,
      });
    }
    return provider;
  }

  public async sign<
    ProviderName extends Providers['providerName'],
    Provider extends Extract<Providers, { providerName: ProviderName }>,
    IssuerClaim extends JwtIssuerClaim,
    SubjectClaim extends JwtSubjectClaim,
    AudienceClaim extends JwtAudienceClaim,
    JtiClaim extends JwtJtiClaim,
    PrivateClaimsSchema extends ZodTypeAny,
    PublicClaimsInputSchema extends ZodObject<{
      /**
       * Issuer
       */
      iss?: IssuerClaim;
      /**
       * Subject
       */
      sub?: SubjectClaim;
      /**
       * Audience
       */
      aud?: AudienceClaim;
      /**
       * JTI
       */
      jti?: JtiClaim;
    }>
  >(args: {
    timestamp?: Date;
    data: {
      privateClaims: z.infer<PrivateClaimsSchema>;
      publicClaims: z.infer<PublicClaimsInputSchema> & {
        /**
         *
         * ---
         *
         * Explicitly set the `iat` (Issued At) claim
         *
         * ---
         *
         * This library does not validate the `iat` claim but relies on validating the `nbf` and `exp` claims to
         * ensure the token is valid from a date and time perspective. If you need to validate the `iat` claim you can
         * use the `validate` callback on the `verify()` function.
         *
         * ---
         *
         * * If you provide neither the `iat` prop nor the `timestamp` prop, the resulting value will be equal to the time you call this function.
         * * If you provide both the `iat` prop and the `timestamp` prop, the resulting value will be equal to the `timestamp` plus the `iat` value.
         * * If you provide the `iat` prop but not the `timestamp` prop, the resulting value will be equal to the the time you call this function plus the `iat` value.
         * * If you provide the `timestamp` prop but not the `iat` prop, the resulting value will be equal to the `timestamp` prop.
         *
         * ---
         *
         * If you are using this, provide one of the following:
         * 1. The relative time in milliseconds as a number
         * 2. The relative time as a string (this will be translated using {@link https://github.com/vercel/ms vercel/ms})
         *
         * ---
         *
         * Can be used in conjunction with the `timestamp`
         *
         * ---
         * Example:
         * ```ts
         * // back date by 1 minute
         * const iat = 60000 * -1; // 1 minute ago
         * // or
         * const iat = '-1 minute';
         * ```
         */
        iat?: number;
        /**
         *
         * ---
         *
         * Explicitly set the `nbf` (Not Before) claim
         *
         * ---
         *
         * If a token is presented with an `nbf` value before the `timestamp`, a call to `verify()` will fail.
         *
         * ---
         *
         * * If you provide neither the `nbf` prop nor the `timestamp` prop, the resulting value will be equal to the time you call this function.
         * * If you provide both the `nbf` prop and the `timestamp` prop, the resulting value will be equal to the `timestamp` plus the `nbf` value.
         * * If you provide the `nbf` prop but not the `timestamp` prop, the resulting value will be equal to the the time you call this function plus the `nbf` value.
         * * If you provide the `timestamp` prop but not the `nbf` prop, the resulting value will be equal to the `timestamp` prop.
         *
         * ---
         *
         * If you are using this, provide one of the following:
         * 1. The relative time in milliseconds as a number
         * 2. The relative time as a string (this will be translated using {@link https://github.com/vercel/ms vercel/ms})
         *
         * ---
         *
         * Can be used in conjunction with the `timestamp`
         *
         * ---
         *
         * Example:
         * ```ts
         * // back date by 1 minute
         * const nbf = 60000 * -1; // 1 minute ago
         * // or
         * const nbf = '-1 minute';
         * ```
         */
        nbf?: number;

        /**
         *
         * ---
         *
         * Explicitly set the `exp` (ExpiresAt) claim
         *
         * ---
         *
         * If a token is presented with an `exp` value after the `timestamp`, a call to `verify()` will fail.
         *
         * ---
         *
         * * If you provide neither the `exp` prop nor the `timestamp` prop, the resulting value will be equal to the time you call this function plus 15 minutes.
         * * If you provide both the `exp` prop and the `timestamp` prop, the resulting value will be equal to the `timestamp` plus the `exp` value.
         * * If you provide the `exp` prop but not the `timestamp` prop, the resulting value will be equal to the the time you call this function plus the `exp` value.
         * * If you provide the `timestamp` prop but not the `exp` prop, the resulting value will be equal to the `timestamp` prop plus 15 minutes.
         *
         * ---
         *
         * If you are using this, provide one of the following:
         * 1. The relative time in milliseconds as a number
         * 2. The relative time as a string (this will be translated using {@link https://github.com/vercel/ms vercel/ms})
         *
         * ---
         *
         * Can be used in conjunction with the `timestamp`
         *
         * ---
         *
         * Example:
         * ```ts
         * const exp = 60000 * 15; // 15 minutes
         * // or
         * const exp = '15 minutes';
         * ```
         */
        exp?: number | string;
      };
    };
    schema: ZodObject<{
      privateClaims: PrivateClaimsSchema;
      publicClaims: PublicClaimsInputSchema;
    }>;
    provider: ProviderName;
    algorithm: Provider['enabledAlgorithms'][number];
  }) {
    const {
      algorithm,
      data: {
        // prettier-ignore
        privateClaims: providedPrivateClaims,
        publicClaims: providedPublicClaims,
      },
      schema,
      timestamp,
      provider,
    } = args;

    const _provider = this.getProvider(provider);

    // verify alg is enabled
    _provider._verifyAlgorithmIsEnabled(algorithm);

    // construct the header
    const header = _provider._constructHeader(algorithm);

    // construct the publicClaims portion of the payload
    const publicClaims = this._constructPublicClaims({
      publicClaims: providedPublicClaims as any,
      constructionDate: timestamp,
    });

    // validate the public claims provided by user and the auto generated ones
    const publicClaimsData = await this._validateSchema({
      schema: schema.shape.publicClaims.extend({
        iat: z.number(),
        exp: z.number(),
        nbf: z.number(),
      }),
      data: publicClaims as any,
      errorMessage: `Invalid Public Claims`,
    });

    // convert the header and payload into [base64UrlHeader].[base64UrlPayload]
    const headerPayload = this._constructHeaderPayload({
      header,
      payload: {
        ...(await Promise.all([
          // prettier-ignore
          this._validateSchema<PrivateClaimsSchema>({
            schema: args.schema.shape.privateClaims,
            data: providedPrivateClaims,
            errorMessage: `Invalid Private Claims`
          }),
          Promise.resolve(publicClaimsData),
        ]).then(([privateClaims, publicClaims]) => ({
          ...privateClaims,
          ...publicClaims,
        }))),
      },
    });

    // generate the signature from the provider
    const signature = await this.getProvider(args.provider)._generateSignature({
      algorithm: header.alg,
      headerPayload,
    });

    // return the [base64UrlHeader].[base64UrlPayload].[base64UrlSignature]
    return `${headerPayload}.${signature}` as Base64UrlEncoded;
  }

  /**
   *
   * Decodes the JWT and parses the payload according to the `publicClaimsSchema` and the `privateClaimsSchema`
   *
   * ---
   *
   * WARNING: This does not validate the signature or any claims. The returned data should not be trusted.
   *
   * ---
   * Validation succeeds when:
   * 1. The JWT is well formed (a string with 3 sections and the header and payload able to be parsed to JSON )
   * 2. The contents of the payload satisfies a call privateClaimsSchema.parse()
   * 3. The contents of the payload satisfies a call publicClaimsSchema.parse()
   */
  public async decode<
    ProviderName extends Providers['providerName'],
    Provider extends Extract<Providers, { providerName: ProviderName }>,
    IssuerClaim extends JwtIssuerClaim,
    SubjectClaim extends JwtSubjectClaim,
    AudienceClaim extends JwtAudienceClaim,
    JtiClaim extends JwtJtiClaim,
    PrivateClaimsSchema extends ZodTypeAny,
    PublicClaimsInputSchema extends ZodObject<{
      /**
       * Issuer
       */
      iss?: IssuerClaim;
      /**
       * Subject
       */
      sub?: SubjectClaim;
      /**
       * Audience
       */
      aud?: AudienceClaim;
      /**
       * JTI
       */
      jti?: JtiClaim;
    }>
  >(args: {
    token: string;
    provider: ProviderName;
    schema: ZodObject<{
      privateClaims: PrivateClaimsSchema;
      publicClaims: PublicClaimsInputSchema;
    }>;
    /**
     * Use this function to perform any additional validation
     */
    validate?: (args: {
      publicClaims: z.infer<PublicClaimsInputSchema & { iat: number; exp: number; nbf: number }>;
      privateClaims: z.infer<PrivateClaimsSchema>;
      header: JwtHeaderSchema<Provider['enabledAlgorithms'][number]>;
    }) => Promise<boolean>;
  }) {
    const { token, validate, provider, schema } = args;
    const { header, payload, headerPayload, signature } = this._decodeJwt(token);

    const privateClaimsParsed = await this._validateSchema({
      data: payload,
      schema: schema.shape.privateClaims,
      errorMessage: `Invalid Private Claims`,
    });
    const publicClaimsParsed = await this._validateSchema({
      data: payload as any,
      schema: schema.shape.publicClaims.extend({
        iat: z.number(),
        exp: z.number(),
        nbf: z.number().optional(),
      }),
      errorMessage: `Invalid Public Claims`,
    });
    const headerParsed = this.getProvider(provider)._validateHeaderSchema(header);

    if (validate) {
      const res = await validate({
        publicClaims: publicClaimsParsed,
        privateClaims: privateClaimsParsed,
        header: headerParsed,
      });
      if (res === false) {
        throw new JwtTokenClaimError({
          message: `Claim validation failed via the custom validate function`,
          zodError: new ZodError([
            {
              code: 'custom',
              message: `User validation`,
              path: ['n/a'],
            },
          ]),
        });
      }
    }
    return {
      publicClaims: publicClaimsParsed as z.infer<PublicClaimsInputSchema> & { iat: number; exp: number; nbf: number },
      privateClaims: privateClaimsParsed as z.infer<PrivateClaimsSchema>,
      header: headerParsed,
      headerPayload,
      signature,
    };
  }

  /**
   *
   * Verifies a JWT and parses both the `publicClaims` and the `privateClaims`
   *
   * ---
   *
   * Order of operations:
   * 1. Decodes the JWT
   * 2. Parses the header and the payload
   * 3. Verifies the header prop `typ` is equal to `JWT`
   * 4. Verifies the header prop `alg` is one of the values you provided to `algorithms` when instantiating your provider
   * 5. Verifies the signature of the header and payload
   * 6. Make a call to zod to parse the payload through the `publicClaimsSchema` (always) and the `privateClaimsSchema` (if provided)
   * 7. Verifies the `exp` claim exists and is after the `timestamp` (with `clockSkew` adjustments if provided)
   * 8. If the `nbf` claim is on the token, it verifies that the `nbf` claim is before the `timestamp` (with `clockSkew` adjustments if provided)
   * 9. Calls the `validate` callback with the values from the payload
   *
   * ---
   *
   */
  public async verify<
    ProviderName extends Providers['providerName'],
    Provider extends Extract<Providers, { providerName: ProviderName }>,
    IssuerClaim extends JwtIssuerClaim,
    SubjectClaim extends JwtSubjectClaim,
    AudienceClaim extends JwtAudienceClaim,
    JtiClaim extends JwtJtiClaim,
    PrivateClaimsSchema extends ZodTypeAny,
    PublicClaimsInputSchema extends ZodObject<{
      /**
       * Issuer
       */
      iss?: IssuerClaim;
      /**
       * Subject
       */
      sub?: SubjectClaim;
      /**
       * Audience
       */
      aud?: AudienceClaim;
      /**
       * JTI
       */
      jti?: JtiClaim;
    }>
  >(args: {
    provider: ProviderName;
    token: string;
    /**
     * Time in milliseconds to adjust when validating the `exp` and `nbf` claims.
     *
     * ---
     *
     * * When `clockSkew` is positive, the `exp` claim will be adjusted forward before comparing to the `timestamp`.
     * * When `clockSkew` is positive, the `nbf` claim will be adjusted backward before comparing to the `timestamp`.
     *
     * ---
     *
     * * When `clockSkew` is negative, the `exp` claim will be adjusted backward before comparing to the `timestamp`.
     * * When `clockSkew` is negative, the `nbf` claim will be adjusted forward before comparing to the `timestamp`.
     * ---
     *
     * If you provide a string the function will parse it through {@link https://github.com/vercel/ms vercel/ms}
     *
     * ---
     *
     * Can be used in conjunction with `timestamp`
     *
     * ---
     *
     * Example:
     * ```ts
     * const clockSkew = '15 seconds';
     * // or
     * const clockSkew = 1000 * 15; // 15 seconds
     * ```
     */
    clockSkew?: number | string;
    /**
     * If you would like to explicity set the `timestamp` you can do so here.
     *
     * ---
     *
     * You should provide a date you would like to validate this token against
     *
     * ---
     *
     * The default `timestamp` is generated with a call to `new Date()` when this function is invoked.
     *
     * ---
     *
     * The `timestamp` is used to validate the `nbf` and `exp` claims.
     *
     * ---
     *
     * Can be used in conjunction with `clockSkew`
     */
    timestamp?: Date;
    schema: ZodObject<{
      privateClaims: PrivateClaimsSchema;
      publicClaims: PublicClaimsInputSchema;
    }>;
    /**
     * Use this function to perform any additional validation
     *
     * ---
     *
     * This function is called after all validation has passed
     */
    validate?: (args: {
      publicClaims: z.infer<PublicClaimsInputSchema> & { iat: number; exp: number; nbf: number };
      privateClaims: z.infer<PrivateClaimsSchema>;
      header: JwtHeaderSchema<Provider['enabledAlgorithms'][number]>;
    }) => Promise<boolean>;
  }) {
    const { validate, clockSkew: clockSkewOverride, token, timestamp: timestampOverride, schema, provider } = args;

    const { header, headerPayload, payload, signature } = this._decodeJwt(token);

    const _provider = this.getProvider(provider);
    const headerParsed = _provider._validateHeaderSchema(header);
    _provider._verifyAlgorithmIsEnabled(headerParsed.alg);

    const isValid = await _provider._verifySignature({
      algorithm: headerParsed.alg,
      headerPayload,
      signature,
    });

    if (!isValid) {
      throw new JwtTokenInvalidSignatureError({
        message: `JWT has an invalid signature`,
      });
    }

    // parse public and private claims
    const privateClaimsParsed = await this._validateSchema({
      schema: schema.shape.privateClaims,
      data: payload,
      errorMessage: `Invalid Private Claims`,
    });

    const publicClaimsParsed = await this._validateSchema({
      schema: schema.shape.publicClaims.extend({
        iat: z.number(),
        exp: z.number(),
        nbf: z.number().optional(),
      }),
      data: payload as any,
      errorMessage: `Invalid Public Claims`,
    });

    // validate iat, exp, nbf
    this._validateTimeBasedPublicClaims({
      timestampOverride,
      clockSkewOverride,
      parsedClaims: publicClaimsParsed,
    });

    if (validate) {
      const res = await validate({
        header: headerParsed,
        privateClaims: privateClaimsParsed || {},
        publicClaims: publicClaimsParsed,
      });
      if (res !== true) {
        throw new JwtTokenClaimError({
          message: `Claim validation failed via the custom validate function`,
          zodError: new ZodError([
            {
              code: 'custom',
              message: `User validation`,
              path: ['n/a'],
            },
          ]),
        });
      }
    }

    return {
      header: headerParsed,
      privateClaims: privateClaimsParsed as z.infer<PrivateClaimsSchema>,
      publicClaims: publicClaimsParsed as z.infer<PublicClaimsInputSchema> & { exp: number; iat: number; nbf: number },
    };
  }

  protected _validateTimeBasedPublicClaims({
    timestampOverride,
    clockSkewOverride,
    parsedClaims,
  }: {
    timestampOverride?: Date;
    clockSkewOverride?: string | number;
    /**
     * Should be from the JWT
     */
    parsedClaims: {
      nbf?: number;
      exp?: number;
      iat?: number;
    };
  }) {
    const clockSkew =
      typeof clockSkewOverride === 'string'
        ? Math.floor(ms(clockSkewOverride) / 1000)
        : typeof clockSkewOverride === 'number'
        ? Math.floor(clockSkewOverride / 1000)
        : 0;

    const timestamp = timestampOverride
      ? // prettier-ignore
        Math.floor(timestampOverride.getTime() / 1000)
      : Math.floor(new Date().getTime() / 1000);

    let schema = z.object({
      iat: z.number({
        invalid_type_error: `The 'iat' claim must be a number`,
        required_error: `The 'iat' claim is required`,
      }),
      exp: z
        .number({
          invalid_type_error: `The 'exp' claim must be a number`,
          required_error: `The 'exp' claim is required`,
        })
        .refine(
          (exp) => {
            return exp >= timestamp - clockSkew;
          },
          (exp) => ({
            message: `The 'exp' claim should be after ${timestamp - clockSkew} but received ${exp}`,
          })
        ),
      nbf: z
        .number({
          invalid_type_error: `The 'nbf' claim must be a number`,
          required_error: `The 'nbf' claim is required`,
        })
        .optional()
        .refine(
          (nbf) => {
            if (typeof nbf === 'number') {
              return nbf <= timestamp + clockSkew;
            } else {
              return true;
            }
          },
          (nbf) => ({
            message: `The 'nbf' claim should be before ${timestamp + clockSkew} but received ${nbf}`,
          })
        ),
    });

    const test = schema.safeParse(parsedClaims);

    if (!test.success) {
      throw new JwtTokenClaimError({
        message: `PublicClaims validation failed`,
        zodError: test.error,
      });
    }

    return true as const;
  }

  /**
   * Validates a zod schema
   */
  protected async _validateSchema<Schema extends ZodTypeAny>(args: { schema: Schema; data: z.infer<Schema>; errorMessage: string }) {
    const test = await args.schema.safeParseAsync(args.data);
    if (!test.success) {
      throw new JwtTokenClaimError({
        message: args.errorMessage,
        zodError: test.error,
      });
    }
    return test.data;
  }

  // util helpers
  protected _toBase64 = toBase64;
  protected _toBase64Url = toBase64Url;
  protected _constructHeaderPayload = constructHeaderPayload;
  protected _decodeJwt = decodeJwt;
  protected _constructPublicClaims = constructPublicClaims;
}
