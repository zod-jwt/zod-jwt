import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown whenever a signature is checked and is invalid
 */
export class JwtTokenInvalidSignatureError extends JwtError {
  constructor(error: { message: string }) {
    super(`[${JwtTokenInvalidSignatureError.name}]: ${error.message}`);
    Object.setPrototypeOf(this, JwtTokenInvalidSignatureError.prototype);
  }
}
