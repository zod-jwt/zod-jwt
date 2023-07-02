import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown as a catch all when something fails and is not explicity thrown by the other
 * error defined in this library.
 */
export class JwtUnknownError extends JwtError {
  error: unknown;
  constructor(error: { message: string; error: unknown }) {
    super(`[${JwtUnknownError.name}]: ${error.message}`);
    this.error = error.error;
    Object.setPrototypeOf(this, JwtUnknownError.prototype);
  }
}
