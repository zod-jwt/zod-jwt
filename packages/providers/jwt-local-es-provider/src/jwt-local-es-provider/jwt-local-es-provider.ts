import {
  Base64Encoded,
  Base64UrlEncoded,
  JwtAbstractProvider,
  JwtAlgorithmsESSchema,
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
import { derToJose, joseToDer } from 'ecdsa-sig-formatter';
import { createSign, createVerify } from 'node:crypto';
import { z } from 'zod';

export type JwtLocalEsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsESSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsESSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
  credentials: {
    ES256?: {
      /**
       * The publicKey used when verifying JWTs
       */
      publicKey: string;
      /**
       * The privateKey used when signing JWTs
       */
      privateKey?: string;
    };
    ES384?: {
      /**
       * The publicKey used when verifying JWTs
       */
      publicKey: string;
      /**
       * The privateKey used when signing JWTs
       */
      privateKey?: string;
    };
    ES512?: {
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

export class JwtLocalEsProvider<
  EnabledAlgorithms extends JwtAlgorithmsESSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsESSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  constructor(private config: JwtLocalEsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['ES256', 'ES384', 'ES512'],
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
    if (algorithm === 'ES256') {
      if (!this.config.credentials.ES256 || !this.config.credentials.ES256.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.ES256.privateKey;
      }
    } else if (algorithm === 'ES384') {
      if (!this.config.credentials.ES384 || !this.config.credentials.ES384.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.ES384.privateKey;
      }
    } else {
      if (!this.config.credentials.ES512 || !this.config.credentials.ES512.privateKey) {
        if (error) {
          throw new JwtProviderBadConfigError({
            message: `No privateKey provided for ${algorithm}`,
          });
        }
        return;
      } else {
        return this.config.credentials.ES512.privateKey;
      }
    }
  }

  private getPublicKey(algorithm: EnabledAlgorithms) {
    if (algorithm === 'ES256') {
      if (!this.config.credentials.ES256 || !this.config.credentials.ES256.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.ES256.publicKey;
      }
    } else if (algorithm === 'ES384') {
      if (!this.config.credentials.ES384 || !this.config.credentials.ES384.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.ES384.publicKey;
      }
    } else {
      if (!this.config.credentials.ES512 || !this.config.credentials.ES512.publicKey) {
        throw new JwtProviderBadConfigError({
          message: `No publicKey provided for ${algorithm}`,
        });
      } else {
        return this.config.credentials.ES512.publicKey;
      }
    }
  }

  protected async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
    const sig = createSign(`RSA-SHA${algorithm.slice(-3)}`)
      .update(headerPayload, 'utf8')
      .sign(
        {
          key: this.getPrivateKey(algorithm, true),
        },
        'base64'
      ) as Base64Encoded;
    return derToJose(sig, algorithm) as Base64UrlEncoded;
  }

  protected async _verifySignature({
    algorithm,
    headerPayload,
    signature: providedSignature,
  }: JwtProviderVerifyArgs<EnabledAlgorithms>): Promise<JwtProviderVerifyResponse> {
    const der = joseToDer(providedSignature, algorithm).toString('base64');
    return createVerify(`RSA-SHA${algorithm.slice(2)}`)
      .update(headerPayload, 'utf8')
      .verify(
        {
          key: this.getPublicKey(algorithm),
        },
        der,
        'base64'
      );
  }
}
