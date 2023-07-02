import ms from 'ms';
import { ZodError, ZodObject, ZodTypeAny, z } from 'zod';
import { JwtProviderBadConfigError, JwtTokenClaimError, JwtTokenInvalidSignatureError, JwtTokenMalformedError } from '../../errors/index.js';
import {
  Base64UrlEncoded,
  IJSON,
  JwtAlgorithmsSchema,
  JwtAsymmetricAlgorithmsSchema,
  JwtAudienceClaim,
  JwtExpiresAtClaim,
  JwtHeaderSchema,
  JwtIssuedAtClaim,
  JwtIssuerClaim,
  JwtJtiClaim,
  JwtNotBeforeClaim,
  JwtSecretEncodingSchema,
  JwtSubjectClaim,
  JwtSymmetricAlgorithmsSchema,
} from '../../schema/index.js';
import {
  constructHeaderPayload,
  constructPublicClaims,
  decodeJwt,
  toBase64,
  toBase64Url,
  validatePrivateKeyMaterial,
  validatePublicKeyMaterial,
  validateSecretMaterial,
} from '../../util/index.js';
import {
  JwtProviderSignArgs,
  JwtProviderSignResponse,
  JwtProviderVerifyArgs,
  JwtProviderVerifyResponse,
} from '../jwt-abstract-provider-types/abstract-jwt-types.js';

/**
 * If you are authoring your own provider, your input props should extend this object
 */
export type JwtProviderConstructorArgs<
  SupportedAlgorithms extends JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = Omit<
  JwtAbstractProviderConstructorArgs<SupportedAlgorithms, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>,
  'supportedAlgorithms'
>;

export type JwtAbstractProviderConstructorArgs<
  SupportedAlgorithms extends JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = {
  /**
   * ---
   *
   * Provider Authors:
   *
   * You need to provide a list of supported algorithms when creating your provider.
   *
   * You should not expose this to the consumer.
   *
   * ---
   *
   * This enables intellisense to work correctly and prevents consumers from passing an invalid provider/algorithm mismatch.
   */
  readonly supportedAlgorithms: SupportedAlgorithms[];
  algorithms: EnabledAlgorithms[];
  /**
   * Private claims are the claims that you or a 3rd party (Github, Facebook, Google, etc.) define.
   * They usually include identifying information about the respective user.
   * In the context of authentication it may include user data such as their firstName and lastName.
   * If you are creating your own tokens you should not include sensitive information in the private claims.
   */
  privateClaimsSchema?: PrivateClaimsSchema;
  /**
   * Public claims are the claims that are defined by {@link https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 RFC7519}
   *
   * ---
   *
   * Although the RFC says all claims are optional, it is recommended to check the `iss`, `aud`, and `sub` claims
   * when verifying JWTs.
   *
   * ---
   *
   * The 1st party providers included in this library automatically set the `exp`, `nbf`, `iat` claims when signing tokens.
   *
   * ---
   *
   * Using the `publicClaimsSchema` you can make sure you also set the `iss`, `aud`, and `sub` claims for every token. These
   * claims are domain specific and cannot be automatically set for you. This library does however give you the ability to generate
   * tokens that validate against this schema.
   *
   * ---
   *
   * Example:
   * ```ts
   * const providerConfig = {
   *    publicClaimsSchema: z.object({
   *      iss: z.literal('api.my-site.com'),
   *      aud: z.literal('frontend.my-site.com'),
   *      sub: z.string() // usually a user_id
   *    })
   * }
   * ```
   */
  publicClaimsSchema?: ZodObject<{
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
  }>;
};

/**
 * Build your own provider by extending this class
 *
 * All claim validation is handled by the `Jwt` class and your provider does not need to implement this feature.
 *
 * You only need to provide the following:
 * 1. An implementation of `verifySignature()`
 * 2. An implementation of `generateSignature()`
 * 3. An array of `supportedAlgorithms` in the constructor (readonly set by the provider)
 * 4. An array of `enabledAlgorithms` in the constructor (provided by the user at runtime)
 *
 * Your constructor should take in some sort of credentials so that your verify and sign functions have access to them
 *
 * You should verify that the credentials provided by the user are valid within the context of the algorithms you are implementing.
 * This abstract class has a few functions that checks to make sure that minimum security standards are enforced.
 * For symmetric algorithms, the `secret` should be validated by calling `validateSecretKey`.
 * For asymmetric algorithms the `publicKey` should be validated by calling `validatePublicKey`.
 * For asymmetric algorithms the `privateKey` should be validated by calling `validatePrivateKey` if the `privateKey` is provided.
 * For asymmetric algorithms the `privateKey` and `publicKey` should be compared to make sure they match if the `privateKey` is provided.
 */
export abstract class JwtAbstractProvider<
  SupportedAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema,
  EnabledAlgorithms extends SupportedAlgorithms = SupportedAlgorithms,
  PrivateClaimsSchema extends z.AnyZodObject = z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim,
  PublicClaimsSchema extends ZodObject<{
    aud: AudienceClaim;
    sub: SubjectClaim;
    iss: IssuerClaim;
    jti: JtiClaim;
    nbf: JwtNotBeforeClaim;
    iat: JwtIssuedAtClaim;
    exp: JwtExpiresAtClaim;
  }> = ZodObject<{
    aud: AudienceClaim;
    sub: SubjectClaim;
    iss: IssuerClaim;
    jti: JtiClaim;
    nbf: JwtNotBeforeClaim;
    iat: JwtIssuedAtClaim;
    exp: JwtExpiresAtClaim;
  }>
> {
  private _publicClaimsSchema: PublicClaimsSchema;
  constructor(
    private readonly args: JwtAbstractProviderConstructorArgs<
      SupportedAlgorithms,
      EnabledAlgorithms,
      PrivateClaimsSchema,
      IssuerClaim,
      SubjectClaim,
      AudienceClaim,
      JtiClaim
    >
  ) {
    let _schema = z.object({
      nbf: z.number(),
      iat: z.number(),
      exp: z.number(),
    });
    if (this.args.publicClaimsSchema?.shape.aud) {
      _schema = _schema.extend({
        aud: this.args.publicClaimsSchema?.shape.aud,
      });
    }
    if (this.args.publicClaimsSchema?.shape.iss) {
      _schema = _schema.extend({
        iss: this.args.publicClaimsSchema?.shape.iss,
      });
    }
    if (this.args.publicClaimsSchema?.shape.sub) {
      _schema = _schema.extend({
        sub: this.args.publicClaimsSchema?.shape.sub,
      });
    }
    if (this.args.publicClaimsSchema?.shape.jti) {
      _schema = _schema.extend({
        jti: this.args.publicClaimsSchema?.shape.jti,
      });
    }

    this._publicClaimsSchema = _schema as unknown as PublicClaimsSchema;

    this.args.algorithms.forEach((algorithm) => {
      if (this.args.supportedAlgorithms.indexOf(algorithm) === -1) {
        throw new JwtProviderBadConfigError({
          message: `An unsupported algorithm ${algorithm} was supplied. The supported algorithms are: ${this.args.supportedAlgorithms.join(', ')}`,
        });
      }
    });
  }

  /**
   * ---
   *
   * If you are creating your own provider you need to implement your signature verification strategy here.
   *
   * ---
   *
   * You will only receive an algorithm that was defined in your `supportedAlgorithms`. Additionally,
   * you will only receive an algorithm that was enabled by the end user via the `algorithms` props when
   * instantiating your provider.
   *
   * ---
   *
   * You can reject signature verification two ways:
   * * Return false - this will automatically throw `JwtTokenInvalidSignatureError` for you
   * * Throw `JwtTokenInvalidSignatureError` to customize the message
   *
   * ---
   *
   * **Claim validation is not the responsibility of this function**
   */
  protected abstract _verifySignature(args: JwtProviderVerifyArgs): Promise<JwtProviderVerifyResponse>;

  /**
   * If you are creating your own provider you need to implement your signing strategy here.
   *
   * You will only receive an algorithm that was defined in your `supportedAlgorithms`.
   *
   * You should really never throw in here unless your are making api calls to a service like KMS. (Validation and configuration should be implemented in the constructor)
   *
   * If you do need to throw an error when using a service like KMS you should throw a `JwtProviderServiceExceptionError`.
   *
   * **Claim validation is not the responsibility of the provider**
   */
  protected abstract _generateSignature(args: JwtProviderSignArgs): Promise<JwtProviderSignResponse>;

  public async sign(args: {
    algorithm: EnabledAlgorithms;
    publicClaims: Omit<z.infer<PublicClaimsSchema>, 'iat' | 'exp' | 'nbf'> & {
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
    /**
     * ---
     *
     * Use the base time to set the timestamp for signing a token.
     *
     * ---
     *
     * By default the `timestamp` is created by calling `new Date()` whenever sign is called
     *
     * ---
     *
     * Can be used in conjunction with setting relative offsets for the `iat`, `nbf`, and `exp` claims in the `publicClaims` property.
     *
     * ---
     *
     * If the `timestamp` is set and you do not provide any relative offsets to the `iat`, `nbf`, and `exp` claims,
     * their respective values will be as follows:
     * * `iat` - `timestamp`
     * * `nbf` - `timestamp`
     * * `exp` - `timestamp` plus 15 minutes
     */
    timestamp?: Date;
    /**
     * ---
     *
     * You should set values here that align with the `privateClaimsSchema` that you have defined.
     */
    privateClaims: z.infer<PrivateClaimsSchema>;
  }) {
    const { algorithm, privateClaims: providedPrivateClaims, publicClaims: providedPublicClaims, timestamp } = args;

    // verify alg is enabled
    this._verifyAlgorithmIsEnabled(args.algorithm);

    // construct the header
    const header = this._constructHeader(algorithm);

    // construct the publicClaims portion of the payload
    const publicClaims = this._constructPublicClaims({
      publicClaims: providedPublicClaims,
      constructionDate: timestamp,
    });

    // convert the header and payload into [base64UrlHeader].[base64UrlPayload]
    const headerPayload = this._constructHeaderPayload({
      header,
      payload: {
        ...(await Promise.all([
          // prettier-ignore
          this._validatePrivateClaimsSchema(providedPrivateClaims),
          this._validatePublicClaimsSchema(publicClaims),
        ]).then(([privateClaims, publicClaims]) => ({
          ...privateClaims,
          ...publicClaims,
        }))),
      },
    });

    // generate the signature from the provider
    const signature = await this._generateSignature({
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
  public async decode(args: {
    token: string;
    /**
     * Use this function to perform any additional validation
     */
    validate?: (args: {
      publicClaims: z.infer<PublicClaimsSchema>;
      privateClaims: z.infer<PrivateClaimsSchema>;
      header: JwtHeaderSchema<EnabledAlgorithms>;
    }) => Promise<boolean>;
  }) {
    const { token, validate } = args;
    const { header, payload, headerPayload, signature } = this._decodeJwt(token);
    const privateClaimsParsed = await this._validatePrivateClaimsSchema(payload);
    const publicClaimsParsed = await this._validatePublicClaimsSchema(payload);
    const headerParsed = this._validateHeaderSchema(header);
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
      publicClaims: publicClaimsParsed,
      privateClaims: privateClaimsParsed,
      header: headerParsed,
      headerPayload,
      signature,
    };
  }

  /**
   * Decodes the JWT and returns the components
   *
   * ---
   *
   * WARNING: This does not validate any claims or the signature. The returned data should not be trusted.
   *
   * ---
   *
   * * `header` is the JSON value of the header
   * * `payload` is the JSON value of the payload
   * * `signature` is the base64UrlEncoded signature
   * * `headerPayload` is the [base64UrlEncodedHeader].[base64UrlEncodedPayload]
   */
  public async decodeWithoutParse(args: { token: string }) {
    const { token } = args;
    return this._decodeJwt(token);
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
  public async verify(args: {
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
    /**
     * Use this function to perform any additional validation
     *
     * ---
     *
     * This function is called after all validation has passed
     */
    validate?: (args: {
      publicClaims: z.infer<PublicClaimsSchema>;
      privateClaims: z.infer<PrivateClaimsSchema>;
      header: JwtHeaderSchema<EnabledAlgorithms>;
    }) => Promise<boolean>;
  }) {
    const { validate, clockSkew: clockSkewOverride, token, timestamp: timestampOverride } = args;
    const { header, headerPayload, payload, signature } = await this.decodeWithoutParse({ token });

    const headerParsed = this._validateHeaderSchema(header);
    this._verifyAlgorithmIsEnabled(headerParsed.alg);
    const isValid = await this._verifySignature({
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
    const privateClaimsParsed = await this._validatePrivateClaimsSchema(payload);
    const publicClaimsParsed = await this._validatePublicClaimsSchema(payload);

    // validate public claims
    this._validatePublicClaims({
      timestampOverride,
      clockSkewOverride,
      parsedClaims: publicClaimsParsed,
      claimRequirements: {
        type: 'schema',
        schema: this._publicClaimsSchema,
      },
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

      return {
        header: headerParsed,
        privateClaims: privateClaimsParsed,
        publicClaims: publicClaimsParsed,
      };
    } else {
      return {
        header: headerParsed,
        privateClaims: privateClaimsParsed,
        publicClaims: publicClaimsParsed,
      };
    }
  }

  /**
   * ---
   *
   * Verifies a JWT without parsing the `publicClaims` or the `privateClaims`
   *
   * ---
   *
   * WARNING: This function does not parse against the `publicClaims` and you need to
   * explicitly set them in this function call.
   *
   * ---
   *
   * * The `exp` claim is the only required claim by default. If no `exp` claim is found in the provided JWT a `JwtTokenClaimError` will be thrown.
   * * If the `nbf` claim is present on the provided JWT it will be validated.
   * * The `sub`, `iss`, `aud`, and `jti` claims can and should be set with the `publicClaims` prop
   */
  public async verifyWithoutParse<T>(args: {
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
     * const clockSkew = '1 minute';
     * // or
     * const clockSkew = 60000 * 1; // 1 minute
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
    /**
     * Can be used to verify the `sub`, `iss`, `aud`, `jti` claims with each individual call.
     *
     * These values should be set since the `publicClaimsSchema` is not utilized for validation with this call
     */
    publicClaims: Partial<Omit<z.infer<PublicClaimsSchema>, 'iat' | 'exp' | 'nbf'>>;
    /**
     * Use this function to perform any additional validation
     *
     * ---
     *
     * This function is called after all validation has passed
     */
    validate?: (args: { claims: IJSON; header: JwtHeaderSchema<EnabledAlgorithms> }) => Promise<boolean>;
  }) {
    const { validate, clockSkew: clockSkewOverride, token, timestamp: timestampOverride, publicClaims: claimRequirements } = args;
    const { header, headerPayload, payload, signature } = await this.decodeWithoutParse({ token });

    const headerParsed = this._validateHeaderSchema(header);
    this._verifyAlgorithmIsEnabled(headerParsed.alg);
    const isValid = await this._verifySignature({
      algorithm: headerParsed.alg,
      headerPayload,
      signature,
    });
    if (!isValid) {
      throw new JwtTokenInvalidSignatureError({
        message: `JWT has an invalid signature`,
      });
    }

    this._validatePublicClaims({
      timestampOverride,
      clockSkewOverride,
      claimRequirements: {
        type: 'values',
        schema: payload,
      },
      parsedClaims: payload,
    });

    if (validate) {
      const res = await validate({
        header: headerParsed,
        claims: payload,
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

      return {
        claims: payload,
        header: headerParsed,
      };
    } else {
      return {
        claims: payload,
        header: headerParsed,
      };
    }
  }

  protected _validatePublicClaims({
    timestampOverride,
    clockSkewOverride,
    parsedClaims,
    /**
     * This should be provided when decoding without parsing
     *
     * The validation of claims can be offloaded to zod when decoding with a parse
     */
    claimRequirements,
  }: {
    timestampOverride?: Date;
    clockSkewOverride?: string | number;
    /**
     * Should be from the JWT
     */
    parsedClaims: {
      sub?: string;
      aud?: string;
      jti?: string;
      iss?: string;
      nbf?: number;
      exp?: number;
      iat?: number;
    };
    /**
     * Should be from the user
     */
    claimRequirements:
      | {
          type: 'values';
          schema: {
            sub?: string;
            aud?: string;
            jti?: string;
            iss?: string;
          };
        }
      | {
          type: 'schema';
          schema: PublicClaimsSchema;
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

    const { aud, iss, jti, sub } = parsedClaims;

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

    if (claimRequirements?.type === 'values') {
      if (typeof claimRequirements.schema.aud !== 'undefined') {
        schema = schema.extend({
          aud: z.literal(claimRequirements.schema.aud, {
            required_error: `The 'aud' claim is required`,
            invalid_type_error: `The 'aud' claim must be ${claimRequirements.schema.aud} but received ${aud}`,
          }),
        });
      }
      if (typeof claimRequirements.schema.iss !== 'undefined') {
        schema = schema.extend({
          iss: z.literal(claimRequirements.schema.iss, {
            required_error: `The 'iss' claim is required`,
            invalid_type_error: `The 'iss' claim must be ${claimRequirements.schema.iss} but received ${iss}`,
          }),
        });
      }
      if (typeof claimRequirements.schema.sub !== 'undefined') {
        schema = schema.extend({
          sub: z.literal(claimRequirements.schema.sub, {
            required_error: `The 'sub' claim is required`,
            invalid_type_error: `The 'sub' claim must be ${claimRequirements.schema.sub} but received ${sub}`,
          }),
        });
      }
      if (typeof claimRequirements.schema.jti !== 'undefined') {
        schema = schema.extend({
          jti: z.literal(claimRequirements.schema.jti, {
            required_error: `The 'jti' claim is required`,
            invalid_type_error: `The 'jti' claim must be ${claimRequirements.schema.jti} but received ${jti}`,
          }),
        });
      }
    } else {
      const shape = schema.shape;
      if ('aud' in shape) {
        schema.extend({
          aud: shape.aud as ZodTypeAny,
        });
      }
      if ('sub' in shape) {
        schema.extend({
          sub: shape.sub as ZodTypeAny,
        });
      }
      if ('iss' in shape) {
        schema.extend({
          iss: shape.iss as ZodTypeAny,
        });
      }
      if ('jti' in shape) {
        schema.extend({
          jti: shape.jti as ZodTypeAny,
        });
      }
    }

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
   * Validates that the `privateClaims` are well formed
   */
  protected async _validatePrivateClaimsSchema(data: IJSON) {
    if (this.args.privateClaimsSchema) {
      const test = await this.args.privateClaimsSchema.safeParseAsync(data);
      if (!test.success) {
        throw new JwtTokenClaimError({
          message: `Unable to validate the private claims`,
          zodError: test.error,
        });
      }
      return test.data as z.infer<PrivateClaimsSchema>;
    } else {
      return data as z.infer<PrivateClaimsSchema>;
    }
  }

  /**
   * ---
   *
   * Validates that the `publicClaims` are well formed
   *
   * ---
   *
   * Does not check the validity of claims such as `nbf` or `exp`
   *
   * ---
   *
   * If a z.literal() is set for the `sub`, `iss`, or `aud` this will fail if the provided data does not match
   */
  protected async _validatePublicClaimsSchema(data: IJSON) {
    const test = await this._publicClaimsSchema.safeParseAsync(data);
    if (!test.success) {
      throw new JwtTokenClaimError({
        message: `Unable to validate the private claims`,
        zodError: test.error,
      });
    }
    return test.data as z.infer<PublicClaimsSchema>;
  }

  protected _validateHeaderSchema(data: IJSON) {
    const test = JwtHeaderSchema.safeParse(data);
    if (!test.success) {
      throw new JwtTokenMalformedError({
        message: `Error when validating the header of the JWT`,
      });
    }
    return test.data as unknown as JwtHeaderSchema<EnabledAlgorithms>;
  }

  /**
   * If you are creating your own provider you can override this method
   *
   * Default implementation generates a set of JWT headers including the `alg` and `typ` props
   *
   */
  protected _constructHeader(algorithm: EnabledAlgorithms) {
    return {
      typ: 'JWT',
      alg: algorithm,
    } as const;
  }

  protected _verifyAlgorithmIsEnabled(algorithm: string) {
    if (this.args.algorithms.indexOf(algorithm as EnabledAlgorithms) === -1) {
      throw new JwtProviderBadConfigError({
        message: `Algorithm ${algorithm} is not enabled. Enabled algorithms are ${this.args.algorithms.join(', ')}`,
      });
    }
    return algorithm as EnabledAlgorithms;
  }

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method if you are creating your own provider or enhance it
   * by performing additional validation in your provider
   *
   * ---
   *
   * Validates the bitSize of the `secret` is greater than or equal to the hashing algorithm bitSize
   *
   */
  protected _validateSecretKey<Algorithm extends JwtSymmetricAlgorithmsSchema>(props: {
    secret: string;
    encoding: JwtSecretEncodingSchema;
    algorithm: Algorithm;
  }) {
    validateSecretMaterial({
      secret: props.secret,
      encoding: props.encoding,
      algorithm: props.algorithm,
    });
  }

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method or call your own if you are creating your own provider and
   * want to enhance the validation in your provider
   *
   * ---
   *
   * Validates that the `modulusLength` is long enough for type type of algorithm
   *
   * * `RS256` and `PS256` should have a `modulusLength` of at least `2048`
   * * `RS384` and `PS384` should have a `modulusLength` of at least `3072`
   * * `RS512` and `PS512` should have a `modulusLength` of at least `4096`
   *
   * ---
   *
   * For `ES` algorithms it checks the curve is correct
   * * `prime256v1` for `ES256`
   * * `secp384r1` for `ES384`
   * * `secp521r1` for `ES512`
   *
   * ---
   *
   * Provide the `publicKey`, not the `privateKey` when calling this function
   */
  protected _validatePublicKey<Algorithm extends JwtAsymmetricAlgorithmsSchema>(props: { publicKey: string; algorithm: Algorithm }) {
    validatePublicKeyMaterial({
      algorithm: props.algorithm,
      publicKey: props.publicKey,
    });
  }

  /**
   *
   * If you are creating a provider you should call this method to ensure the user has
   * provided valid credentials to your signing algorithm.
   *
   * You can override this method if you are creating your own provider or enhance it
   * by performing additional validation in your provider
   *
   * ---
   *
   * * Validates the modulus length of the `privateKey` against the hash size
   * * Validates that the `privateKey` and algorithm combination are valid (i.e. can't sign ES with RS keys)
   *
   * ---
   *
   * * Returns an object with the `privateKey` unaltered
   */
  protected _validatePrivateKey<Algorithm extends JwtAsymmetricAlgorithmsSchema>(props: { privateKey: string; algorithm: Algorithm }) {
    validatePrivateKeyMaterial({
      algorithm: props.algorithm,
      privateKey: props.privateKey,
    });
  }

  /**
   * todo: should validate if the publickey privatekey match
   * Could generate and verify a signature
   * Since this will need to be promise based it couldn't be awaited in the constructor (could still call it though)
   */
  protected _validatePrivateKeyPublicKeyMatch() {
    throw new Error('not implemented');
  }

  // util helpers
  protected _toBase64 = toBase64;
  protected _toBase64Url = toBase64Url;
  protected _constructHeaderPayload = constructHeaderPayload;
  protected _decodeJwt = decodeJwt;
  protected _constructPublicClaims = constructPublicClaims;
}
