import { JwtTokenMalformedError } from '../../errors/index.js';
import { Base64UrlEncoded, HeaderPayload, IJSON } from '../../schema/index.js';
import { toBase64 } from '../to-base-64/to-base-64.js';

/**
 * This is a low level function that decodes a JWT.
 *
 * ---
 *
 * It does not perform any validation except to make sure that the JWT
 * is well formed.
 *
 * ---
 *
 * It will throw `JwtTokenMalformedError` under the following conditions
 * 1. Provided input was not of type string
 * 2. After splitting the token into three parts:
 *    - The header is not typeof string
 *    - The header is a string but has a length of zero
 *    - The header is not a JSON object (this is done after decoding from base64 to utf8)
 *    - The header does not satisfy a zod parse according to the `JwtHeaderSchema` defined in this library
 *        - `typ` must be "JWT"
 *        - `alg` must be one of the supported algorithms (HS256, RS256, etc...)
 *    - The payload is not typeof string
 *    - The payload is a string but has a length of zero
 *    - The payload is not a JSON object (this is done after decoding from base64 to utf8)
 *    - The signature is not typeof string
 *    - The signature is a string but has a length of zero
 *
 */
export const decodeJwt = (jwt: string) => {
  if (typeof jwt !== 'string') {
    throw new JwtTokenMalformedError({ message: `JWT was not a string` });
  }

  const [header, payload, signature] = jwt.split('.');

  if (typeof header !== 'string' || header.length === 0) {
    throw new JwtTokenMalformedError({ message: `No Header` });
  }

  if (!payload || typeof payload !== 'string') {
    throw new JwtTokenMalformedError({ message: `No Payload` });
  }

  if (!signature || typeof signature !== 'string') {
    throw new JwtTokenMalformedError({ message: `No Signature` });
  }

  let jsonHeader: IJSON;
  try {
    jsonHeader = JSON.parse(Buffer.from(toBase64(header as Base64UrlEncoded), 'base64').toString('utf-8'));
  } catch (e) {
    throw new JwtTokenMalformedError({ message: `Unable to JSON.parse JWT header` });
  }
  let jsonPayload: IJSON;
  try {
    jsonPayload = JSON.parse(Buffer.from(toBase64(payload as Base64UrlEncoded), 'base64').toString('utf-8'));
  } catch (e) {
    throw new JwtTokenMalformedError({ message: `Unable to JSON.parse JWT payload` });
  }

  return {
    /**
     * JSON
     */
    header: jsonHeader,
    /**
     * JSON
     */
    payload: jsonPayload,
    /**
     * [base64UrlSignature]
     */
    signature: signature as Base64UrlEncoded,
    /**
     * [base64UrlHeader].[base64UrlPayload]
     */
    headerPayload: `${header}.${payload}` as HeaderPayload,
  };
};
