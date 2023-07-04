import { constants, createSign, createVerify } from 'node:crypto';
import {
  JwtAbstractProvider,
  JwtProviderConstructorArgs,
  JwtProviderSignArgs,
  JwtProviderSignResponse,
  JwtProviderVerifyArgs,
  JwtProviderVerifyResponse,
} from '../../../abstract-provider/index.js';
import { JwtProviderBadConfigError } from '../../../errors/index.js';
import { Base64Encoded, JwtAlgorithmsRSSchema } from '../../../schema/index.js';

export type LocalRsProviderConfig<ProviderName extends string, EnabledAlgorithms extends JwtAlgorithmsRSSchema> = JwtProviderConstructorArgs<
  ProviderName,
  JwtAlgorithmsRSSchema,
  EnabledAlgorithms
> & {
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

export class LocalRsProvider<
  // prettier-ignore
  ProviderName extends string,
  EnabledAlgorithms extends JwtAlgorithmsRSSchema
> extends JwtAbstractProvider<ProviderName, JwtAlgorithmsRSSchema, EnabledAlgorithms> {
  constructor(private config: LocalRsProviderConfig<ProviderName, EnabledAlgorithms>) {
    super({
      supportedAlgorithms: ['RS256', 'RS384', 'RS512'],
      algorithms: config.algorithms,
      providerName: config.providerName,
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

  public async _generateSignature({ algorithm, headerPayload }: JwtProviderSignArgs<EnabledAlgorithms>): Promise<JwtProviderSignResponse> {
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

  public async _verifySignature({
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
