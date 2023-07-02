import {
  Base64Encoded,
  JwtAbstractProvider,
  JwtAlgorithmsRSSchema,
  JwtAudienceClaim,
  JwtIssuerClaim,
  JwtJtiClaim,
  JwtProviderBadConfigError,
  JwtProviderConstructorArgs,
  JwtProviderSignArgs,
  JwtProviderSignResponse,
  JwtProviderVerifyArgs,
  JwtProviderVerifyResponse,
  JwtSubjectClaim,
} from '@zod-jwt/core';
import { constants, createSign, createVerify } from 'node:crypto';
import { z } from 'zod';

export type JwtLocalRsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsRSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsRSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
  credentials: {
    /**
     * The publicKey used when verifying JWTs
     */
    publicKey: string;
    /**
     * The privateKey used when signing JWTs
     */
    privateKey?: string;
  };
};

export class JwtLocalRsProvider<
  EnabledAlgorithms extends JwtAlgorithmsRSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsRSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  constructor(private config: JwtLocalRsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['RS256', 'RS384', 'RS512'],
      algorithms: config.algorithms,
      privateClaimsSchema: config.privateClaimsSchema,
      publicClaimsSchema: config.publicClaimsSchema,
    });

    this.config.algorithms.forEach((algorithm) => {
      if (this.config.credentials.privateKey) {
        this._validatePrivateKey({
          algorithm,
          privateKey: this.config.credentials.privateKey,
        });
      }
      this._validatePublicKey({
        algorithm,
        publicKey: this.config.credentials.publicKey,
      });
    });
  }

  protected async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
    if (!this.config.credentials.privateKey) {
      throw new JwtProviderBadConfigError({
        message: `You attempted to call sign without providing a private key`,
      });
    }
    const sig = createSign(`RSA-SHA${algorithm.slice(-3)}`)
      .update(headerPayload, 'utf8')
      .sign(
        {
          key: this.config.credentials.privateKey,
          padding: constants.RSA_PKCS1_PADDING,
        },
        'base64'
      ) as Base64Encoded;
    return this._toBase64Url(sig, 'base64');
  }

  protected async _verifySignature({
    algorithm,
    headerPayload,
    signature: providedSignature,
  }: JwtProviderVerifyArgs<EnabledAlgorithms>): Promise<JwtProviderVerifyResponse> {
    return createVerify(`RSA-SHA${algorithm.slice(2)}`)
      .update(headerPayload, 'utf8')
      .verify(
        {
          key: this.config.credentials.publicKey,
          padding: constants.RSA_PKCS1_PADDING,
        },
        this._toBase64(providedSignature),
        'base64'
      );
  }
}
