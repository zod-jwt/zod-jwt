import { KMSClient, KMSInvalidSignatureException, SignCommand, SigningAlgorithmSpec, VerifyCommand } from '@aws-sdk/client-kms';
import type { AwsCredentialIdentity } from '@aws-sdk/types';
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
  JwtProviderServiceExceptionError,
  JwtProviderSignArgs,
  JwtProviderSignResponse,
  JwtProviderVerifyArgs,
  JwtProviderVerifyResponse,
  JwtSubjectClaim,
} from '@zod-jwt/core';
import { derToJose, joseToDer } from 'ecdsa-sig-formatter';
import { z } from 'zod';

export type JwtKmsEsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsESSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsESSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
  credentials: {
    region: string;
    account: string;
    /**
     * You AWS `accessKeyId` and `secretAccessKey`
     *
     * Note: this is optional if running inside an AWS environment (Lambda, ec2, etc.) that has the appropriate access to call the KMS service. If you are running in a
     * non AWS environment (local, vercel, digital ocean, etc.) then you need to provide your credentials
     */
    credentials?: Omit<AwsCredentialIdentity, 'sessionToken'>;
    /**
     * Provide either you `keyId` or your `keyAlias`
     *
     * Do not provide the full arn. This library builds the arn internally.
     *
     * The signing keys are specific to the algorithm for AWS KMS
     */
    kms: {
      ES256?:
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:key/mrk-abcd...` you should provide the `mrk-abcd...` part
             */
            keyId: string;
          }
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:alias/MY_ALIAS` you should provide the `MY_ALIAS` part
             */
            keyAlias: string;
          };
      ES384?:
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:key/mrk-abcd...` you should provide the `mrk-abcd...` part
             */
            keyId: string;
          }
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:alias/MY_ALIAS` you should provide the `MY_ALIAS` part
             */
            keyAlias: string;
          };
      ES512?:
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:key/mrk-abcd...` you should provide the `mrk-abcd...` part
             */
            keyId: string;
          }
        | {
            /**
             * If your arn looks like this `arn:aws:kms:us-east-1:111111111111:alias/MY_ALIAS` you should provide the `MY_ALIAS` part
             */
            keyAlias: string;
          };
    };
  };
};

export class JwtKmsEsProvider<
  EnabledAlgorithms extends JwtAlgorithmsESSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsESSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  private client: KMSClient;
  constructor(private config: JwtKmsEsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['ES256', 'ES384', 'ES512'],
      algorithms: config.algorithms,
      privateClaimsSchema: config.privateClaimsSchema,
      publicClaimsSchema: config.publicClaimsSchema,
    });

    this.client = new KMSClient({
      credentials: this.config.credentials.credentials,
      region: this.config.credentials.region,
    });
  }

  private getCredentials(algorithm: EnabledAlgorithms) {
    if (algorithm === 'ES256') {
      if (!this.config.credentials.kms.ES256) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.ES256;
    } else if (algorithm === 'ES384') {
      if (!this.config.credentials.kms.ES384) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.ES384;
    } else if (algorithm === 'ES512') {
      if (!this.config.credentials.kms.ES512) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.ES512;
    } else {
      throw new JwtProviderBadConfigError({
        message: `Invalid algorithm ${algorithm}`,
      });
    }
  }

  private getArn(algorithm: EnabledAlgorithms) {
    const credentials = this.getCredentials(algorithm);
    if ('keyId' in credentials) {
      return `arn:aws:kms:${this.config.credentials.region}:${this.config.credentials.account}:key/${credentials.keyId}`;
    } else {
      return `arn:aws:kms:${this.config.credentials.region}:${this.config.credentials.account}:alias/${credentials.keyAlias}`;
    }
  }

  private getSigningAlgorithm(algorithm: EnabledAlgorithms) {
    if (algorithm === 'ES256') {
      return SigningAlgorithmSpec.ECDSA_SHA_256;
    } else if (algorithm === 'ES384') {
      return SigningAlgorithmSpec.ECDSA_SHA_384;
    } else if (algorithm === 'ES512') {
      return SigningAlgorithmSpec.ECDSA_SHA_512;
    } else {
      throw new JwtProviderBadConfigError({
        message: `Unknown algorithm ${algorithm}`,
      });
    }
  }

  protected async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
    const sig = await this.client
      .send(
        new SignCommand({
          KeyId: this.getArn(algorithm),
          Message: Buffer.from(headerPayload, 'utf-8'),
          SigningAlgorithm: this.getSigningAlgorithm(algorithm),
          MessageType: 'RAW',
        })
      )
      .then((res) => {
        if (!res.Signature) {
          throw new JwtProviderServiceExceptionError({
            message: `AWS KMS responded without a signature`,
          });
        }
        return Buffer.from(res.Signature).toString('base64');
      })
      .catch((error) => {
        throw new JwtProviderServiceExceptionError({
          message: `AWS KMS Error while generating signature`,
          error,
        });
      });
    return derToJose(this._toBase64Url(sig as Base64Encoded, 'base64'), algorithm) as Base64UrlEncoded;
  }

  protected async _verifySignature({
    algorithm,
    headerPayload,
    signature: providedSignature,
  }: JwtProviderVerifyArgs<EnabledAlgorithms>): Promise<JwtProviderVerifyResponse> {
    const der = joseToDer(providedSignature, algorithm).toString('base64');
    return this.client
      .send(
        new VerifyCommand({
          KeyId: this.getArn(algorithm),
          Message: Buffer.from(headerPayload, 'utf-8'),
          Signature: Buffer.from(der, 'base64'),
          SigningAlgorithm: this.getSigningAlgorithm(algorithm),
          MessageType: 'RAW',
        })
      )
      .then((res) => res.SignatureValid as boolean)
      .catch((error) => {
        if (error instanceof KMSInvalidSignatureException) {
          return false;
        }
        throw new JwtProviderServiceExceptionError({
          message: `AWS KMS Error while generating signature`,
          error,
        });
      });
  }
}
