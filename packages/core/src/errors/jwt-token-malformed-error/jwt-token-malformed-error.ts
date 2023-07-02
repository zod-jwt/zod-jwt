import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown whenever an attempt to decode a malformed JWT is made
 *
 * If the token is not a string an this error is thrown
 *
 * After splitting the token into 3 parts, and any of the header, payload or signature is not a string
 * this error is thrown
 */
export class JwtTokenMalformedError extends JwtError {
  constructor(error: { message: string }) {
    super(`[${JwtTokenMalformedError.name}]: ${error.message}`);
    Object.setPrototypeOf(this, JwtTokenMalformedError.prototype);
  }
}
