import { JwtError } from '../jwt-error/jwt-error.js';

/**
 * This error is thrown when you provide an incorrect configuration to a provider
 */
export class JwtProviderBadConfigError extends JwtError {
  constructor(error: { message: string }) {
    super(`[${JwtProviderBadConfigError.name}]: ${error.message}`);
    Object.setPrototypeOf(this, JwtProviderBadConfigError.prototype);
  }
}
