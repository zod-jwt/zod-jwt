import { Base64UrlEncoded, HeaderPayload, IJSON, JwtAlgorithmsSchema, JwtHeaderSchema } from '../../schema/index.js';

export type JwtProviderDecodeResponse<EnabledAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema> = {
  header: JwtHeaderSchema<EnabledAlgorithms>;
  payload: IJSON;
  signature: Base64UrlEncoded;
  headerPayload: HeaderPayload;
};

export type JwtProviderVerifyArgs<EnabledAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema> = {
  headerPayload: HeaderPayload;
  signature: Base64UrlEncoded;
  algorithm: EnabledAlgorithms;
};

export type JwtProviderVerifyResponse = boolean;

export type JwtProviderSignResponse = Base64UrlEncoded;

export type JwtProviderSignArgs<EnabledAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema> = {
  headerPayload: HeaderPayload;
  algorithm: EnabledAlgorithms;
};
