import { GenerateMacCommand, KMSClient, KMSInvalidSignatureException, MacAlgorithmSpec, VerifyMacCommand } from '@aws-sdk/client-kms';
import type { AwsCredentialIdentity } from '@aws-sdk/types';
import {
  Base64Encoded,
  JwtAbstractProvider,
  JwtAlgorithmsHSSchema,
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
import { z } from 'zod';

export type JwtKmsHsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsHSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsHSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
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
      HS256?:
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
      HS384?:
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
      HS512?:
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

export class JwtKmsHsProvider<
  EnabledAlgorithms extends JwtAlgorithmsHSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsHSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  private client: KMSClient;
  constructor(private config: JwtKmsHsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['HS256', 'HS384', 'HS512'],
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
    if (algorithm === 'HS256') {
      if (!this.config.credentials.kms.HS256) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.HS256;
    } else if (algorithm === 'HS384') {
      if (!this.config.credentials.kms.HS384) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.HS384;
    } else if (algorithm === 'HS512') {
      if (!this.config.credentials.kms.HS512) {
        throw new JwtProviderBadConfigError({
          message: `No credentials provided for ${algorithm}`,
        });
      }
      return this.config.credentials.kms.HS512;
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
    if (algorithm === 'HS256') {
      return MacAlgorithmSpec.HMAC_SHA_256;
    } else if (algorithm === 'HS384') {
      return MacAlgorithmSpec.HMAC_SHA_384;
    } else if (algorithm === 'HS512') {
      return MacAlgorithmSpec.HMAC_SHA_512;
    } else {
      throw new JwtProviderBadConfigError({
        message: `Unknown algorithm ${algorithm}`,
      });
    }
  }

  protected async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
    const sig = await this.client
      .send(
        new GenerateMacCommand({
          KeyId: this.getArn(algorithm),
          Message: Buffer.from(headerPayload, 'utf-8'),
          MacAlgorithm: this.getSigningAlgorithm(algorithm),
        })
      )
      .then((res) => {
        if (!res.Mac) {
          throw new JwtProviderServiceExceptionError({
            message: `AWS KMS responded without a mac`,
          });
        }
        return Buffer.from(res.Mac).toString('base64');
      })
      .catch((error) => {
        throw new JwtProviderServiceExceptionError({
          message: `AWS KMS Error while generating signature`,
          error,
        });
      });

    return this._toBase64Url(sig as Base64Encoded, 'base64');
  }

  protected async _verifySignature({
    algorithm,
    headerPayload,
    signature: providedSignature,
  }: JwtProviderVerifyArgs<EnabledAlgorithms>): Promise<JwtProviderVerifyResponse> {
    return this.client
      .send(
        new VerifyMacCommand({
          KeyId: this.getArn(algorithm),
          Message: Buffer.from(headerPayload, 'utf-8'),
          Mac: Buffer.from(this._toBase64(providedSignature), 'base64'),
          MacAlgorithm: this.getSigningAlgorithm(algorithm),
        })
      )
      .then((res) => res.MacValid as boolean)
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
