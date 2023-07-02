import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown when you provide invalid key material to a provider
 *
 * ---
 *
 * If you provide a secret string instead of a private key and public key to an asymmetric algorithm
 * this error will be thrown
 *
 * ---
 *
 * If you provide a public or private key to a symmetric algorithm
 * this error will be thrown
 *
 */
export class JwtProviderInvalidKeyMaterialError extends JwtError {
  error?: unknown;
  constructor(error: { message: string; error?: unknown }) {
    super(`[${JwtProviderInvalidKeyMaterialError.name}]: ${error.message}`);
    this.error = error.error;
    Object.setPrototypeOf(this, JwtProviderInvalidKeyMaterialError.prototype);
  }
}
