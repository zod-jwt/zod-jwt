import { readFileSync } from 'fs';
import { randomBytes } from 'node:crypto';
import { join } from 'path';
import {
  JwtAlgorithmsESSchema,
  JwtAlgorithmsHSSchema,
  JwtAlgorithmsPSSchema,
  JwtAlgorithmsRSSchema,
  JwtAlgorithmsSchema,
  JwtSymmetricAlgorithmsSchema,
} from '../schema/index.js';

export function getTestCredentials(algorithm: JwtAlgorithmsESSchema): { publicKey: string; privateKey: string };
export function getTestCredentials(algorithm: JwtAlgorithmsPSSchema): { publicKey: string; privateKey: string };
export function getTestCredentials(algorithm: JwtAlgorithmsRSSchema): { publicKey: string; privateKey: string };
export function getTestCredentials(algorithm: JwtAlgorithmsHSSchema, type: 'valid' | 'invalid', encoding: 'hex' | 'base64'): { secret: string };

export function getTestCredentials(algorithm: JwtAlgorithmsSchema, type?: 'valid' | 'invalid', encoding?: 'base64' | 'hex') {
  function isSymmetricAlgorithm(algorithm: JwtAlgorithmsSchema): algorithm is JwtSymmetricAlgorithmsSchema {
    return algorithm.slice(0, 2) === 'HS';
  }

  if (isSymmetricAlgorithm(algorithm)) {
    if (type === 'invalid') {
      return { secret: randomBytes(parseInt(algorithm.slice(-3), 10) / 8).toString(encoding) };
    } else {
      return { secret: randomBytes(parseInt(algorithm.slice(-3), 10) / 8).toString(encoding) };
    }
  } else {
    // vitest polyfills __dirname in esm environment
    // ok to use here; this is not included in shipped package
    return {
      privateKey: readFileSync(
        join(__dirname, `../../../../test-credentials/${algorithm.slice(0, 2).toLowerCase()}_${algorithm.slice(-3)}_private.pem`)
      ).toString('utf8'),
      publicKey: readFileSync(
        join(__dirname, `../../../../test-credentials/${algorithm.slice(0, 2).toLowerCase()}_${algorithm.slice(-3)}_public.pem`)
      ).toString('utf8'),
    };
  }
}
