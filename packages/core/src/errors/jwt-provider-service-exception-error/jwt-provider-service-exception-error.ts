import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown when the underlying service provider throws an exception
 *
 * For KMS this will be thrown when a KMSServiceException or any of its subclasses throw an error
 */
export class JwtProviderServiceExceptionError extends JwtError {
  error?: unknown;
  constructor(error: { message: string; error?: unknown }) {
    super(`[${JwtProviderServiceExceptionError.name}]: ${error.message}`);
    this.error = error.error;
    Object.setPrototypeOf(this, JwtProviderServiceExceptionError.prototype);
  }
}
