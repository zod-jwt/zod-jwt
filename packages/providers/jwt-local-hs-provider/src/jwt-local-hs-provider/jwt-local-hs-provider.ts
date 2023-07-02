import {
  Base64Encoded,
  HeaderPayload,
  JwtAbstractProvider,
  JwtAlgorithmsHSSchema,
  JwtAudienceClaim,
  JwtIssuerClaim,
  JwtJtiClaim,
  JwtProviderConstructorArgs,
  JwtProviderSignArgs,
  JwtProviderVerifyArgs,
  JwtSecretEncodingSchema,
  JwtSecretSchema,
  JwtSubjectClaim,
  signatureMatches,
} from '@zod-jwt/core';
import { createHmac } from 'node:crypto';
import { z } from 'zod';

export type JwtLocalHsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsHSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsHSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
  credentials: {
    /**
     * Must be the string literal value of either base64 or hex.
     *
     * Make sure this value coincides with the secret you have generated.
     *
     * See the `secret` property for more details on how to generate a secure secret.
     */
    encoding: JwtSecretEncodingSchema;
    /**
     *
     *
     * ---
     *
     * If your `secret` value is at least 256 bits in size, you can sign and verify using only the HS256 algorithm.
     *
     * ---
     *
     * If your `secret` value is at least 384 bits in size, you can sign and verify using either the HS256 or the HS384 algorithms.
     *
     * ---
     *
     * If your `secret` value is at least 512 bits in size, you can sign and verify using the HS256, HS384, or HS512 algorithms.
     *
     * ---
     *
     * You are most likely only going to sign and verify using one algorithm, but if you do want to sign tokens
     * using different algorithms with this provider, these are the conditions.
     *
     * ---
     *
     * To generate your secret see the directions on the `secret` property.
     * * The secret value for symmetric based algorithms: `HS256`, `HS384`, `HS512`.
     *
     * It must have a bit length greater than or equal to your signing algorithm.
     *
     * You must also provide the type of encoding that your string is in. This is either
     * base64 encoding or hex encoding.
     *
     * ---
     *
     * To generate a secure secret use one of the following commands based on the value you provide to encoding:
     * ```bash
     * # For HS256 (32 bytes aka 256 bits)
     * openssl rand -hex 32
     * openssl rand -base64 32
     * # For HS384 (48 bytes aka 384 bits)
     * openssl rand -hex 48
     * openssl rand -base64 48
     * # For HS512 (64 bytes aka 512 bits)
     * openssl rand -hex 64
     * openssl rand -base64 64
     * ```
     */
    secret: JwtSecretSchema;
  };
};

export class JwtLocalHsProvider<
  EnabledAlgorithms extends JwtAlgorithmsHSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsHSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  constructor(private config: JwtLocalHsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['HS256', 'HS384', 'HS512'],
      algorithms: config.algorithms,
      publicClaimsSchema: config.publicClaimsSchema,
    });
    this.config.algorithms.forEach((alg) => {
      this._validateSecretKey({
        algorithm: alg,
        secret: this.config.credentials.secret,
        encoding: this.config.credentials.encoding,
      });
    });
  }

  private get secret() {
    return Buffer.from(this.config.credentials.secret, this.config.credentials.encoding);
  }

  protected async _verifySignature({ signature: providedSignature, ...args }: JwtProviderVerifyArgs<EnabledAlgorithms>) {
    const actualSignature = this.getSignature(args);
    return signatureMatches(actualSignature, providedSignature);
  }

  protected async _generateSignature(args: JwtProviderSignArgs<EnabledAlgorithms>) {
    return this.getSignature(args);
  }

  /**
   * Returns the generated signature as a branded `base64UrlEncoded` string
   */
  private getSignature({ algorithm, headerPayload }: { algorithm: JwtAlgorithmsHSSchema; headerPayload: HeaderPayload }) {
    const sig = createHmac(`sha${algorithm.slice(-3)}`, this.secret)
      .update(headerPayload)
      .digest('base64') as Base64Encoded;
    return this._toBase64Url(sig, 'base64');
  }
}
