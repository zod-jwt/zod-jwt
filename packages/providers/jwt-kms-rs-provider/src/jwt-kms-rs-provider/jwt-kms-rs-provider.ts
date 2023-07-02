import { KMSClient, KMSInvalidSignatureException, SignCommand, SigningAlgorithmSpec, VerifyCommand } from '@aws-sdk/client-kms';
import type { AwsCredentialIdentity } from '@aws-sdk/types';
import {
  Base64Encoded,
  JwtAbstractProvider,
  JwtAlgorithmsRSSchema,
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

export type JwtKmsRsProviderConfig<
  EnabledAlgorithms extends JwtAlgorithmsRSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> = JwtProviderConstructorArgs<JwtAlgorithmsRSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> & {
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
     */
    kms:
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

export class JwtKmsRsProvider<
  EnabledAlgorithms extends JwtAlgorithmsRSSchema,
  PrivateClaimsSchema extends z.AnyZodObject,
  IssuerClaim extends JwtIssuerClaim = JwtIssuerClaim,
  SubjectClaim extends JwtSubjectClaim = JwtSubjectClaim,
  AudienceClaim extends JwtAudienceClaim = JwtAudienceClaim,
  JtiClaim extends JwtJtiClaim = JwtJtiClaim
> extends JwtAbstractProvider<JwtAlgorithmsRSSchema, EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim> {
  private client: KMSClient;
  constructor(private config: JwtKmsRsProviderConfig<EnabledAlgorithms, PrivateClaimsSchema, IssuerClaim, SubjectClaim, AudienceClaim, JtiClaim>) {
    super({
      supportedAlgorithms: ['RS256', 'RS384', 'RS512'],
      algorithms: config.algorithms,
      privateClaimsSchema: config.privateClaimsSchema,
      publicClaimsSchema: config.publicClaimsSchema,
    });

    this.client = new KMSClient({
      credentials: this.config.credentials.credentials,
      region: this.config.credentials.region,
    });
  }

  private get arn() {
    if ('keyId' in this.config.credentials.kms) {
      return `arn:aws:kms:${this.config.credentials.region}:${this.config.credentials.account}:key/${this.config.credentials.kms.keyId}`;
    } else {
      return `arn:aws:kms:${this.config.credentials.region}:${this.config.credentials.account}:alias/${this.config.credentials.kms.keyAlias}`;
    }
  }

  private getSigningAlgorithm(algorithm: EnabledAlgorithms) {
    if (algorithm === 'RS256') {
      return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
    } else if (algorithm === 'RS384') {
      return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384;
    } else if (algorithm === 'RS512') {
      return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512;
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
          KeyId: this.arn,
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

    return this._toBase64Url(sig as Base64Encoded, 'base64');
  }

  protected async _verifySignature({
    algorithm,
    headerPayload,
    signature: providedSignature,
  }: JwtProviderVerifyArgs<EnabledAlgorithms>): Promise<JwtProviderVerifyResponse> {
    return this.client
      .send(
        new VerifyCommand({
          KeyId: this.arn,
          Message: Buffer.from(headerPayload, 'utf-8'),
          Signature: Buffer.from(this._toBase64(providedSignature), 'base64'),
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
