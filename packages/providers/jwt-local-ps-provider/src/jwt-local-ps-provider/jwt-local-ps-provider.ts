import {
  Base64Encoded,
  JwtAbstractProvider,
  JwtAlgorithmsPSSchema,
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

export type JwtLocalPsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsPSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsPSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
  credentials: {
    PS256?: {
      /**
       * The publicKey used when verifying JWTs
       */
      publicKey: string;
      /**
       * The privateKey used when signing JWTs
       */
      privateKey?: string;
    };
    PS384?: {
      /**
       * The publicKey used when verifying JWTs
       */
      publicKey: string;
      /**
       * The privateKey used when signing JWTs
       */
      privateKey?: string;
    };
    PS512?: {
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
};

export class JwtLocalPsProvider<
  EnabledAlgorithms extends JwtAlgorithmsPSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsPSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  constructor(private config: JwtLocalPsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['PS256', 'PS384', 'PS512'],
      algorithms: config.algorithms,
      privateClaimsSchema: config.privateClaimsSchema,
      publicClaimsSchema: config.publicClaimsSchema,
    });

    this.config.algorithms.forEach((algorithm) => {
      this._validatePublicKey({
        publicKey: this.getPublicKey(algorithm),
        algorithm,
      });
      const privateKey = this.getPrivateKey(algorithm, false);
      if (privateKey) {
        this._validatePrivateKey({
          privateKey,
          algorithm,
        });
      }
    });
  }

  private getPrivateKey(algorithm: EnabledAlgorithms, error: false): void | string;
  private getPrivateKey(algorithm: EnabledAlgorithms, error: boolean): string;
  private getPrivateKey(algorithm: EnabledAlgorithms, error: boolean): void | string {
    if (algorithm === 'PS256') {
      if (!this.config.credentials.PS256 || !this.config.credentials.PS256.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.PS256.privateKey;
      }
    } else if (algorithm === 'PS384') {
      if (!this.config.credentials.PS384 || !this.config.credentials.PS384.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.PS384.privateKey;
      }
    } else {
      if (!this.config.credentials.PS512 || !this.config.credentials.PS512.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.PS512.privateKey;
      }
    }
  }

  private getPublicKey(algorithm: EnabledAlgorithms) {
    if (algorithm === 'PS256') {
      if (!this.config.credentials.PS256 || !this.config.credentials.PS256.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.PS256.publicKey;
      }
    } else if (algorithm === 'PS384') {
      if (!this.config.credentials.PS384 || !this.config.credentials.PS384.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.PS384.publicKey;
      }
    } else {
      if (!this.config.credentials.PS512 || !this.config.credentials.PS512.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.PS512.publicKey;
      }
    }
  }

  protected async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
    const sig = createSign(`RSA-SHA${algorithm.slice(-3)}`)
      .update(headerPayload, 'utf8')
      .sign(
        {
          key: this.getPrivateKey(algorithm, true),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
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
          key: this.getPublicKey(algorithm),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        this._toBase64(providedSignature),
        'base64'
      );
  }
}
