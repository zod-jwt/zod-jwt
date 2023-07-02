import { describe, expect, it, test } from 'vitest';
import { JwtProviderInvalidKeyMaterialError } from '../../errors/index.js';
import { JwtAlgorithmsPSSchema, JwtAlgorithmsRSSchema } from '../../schema/index.js';
import { validateModulusLength } from '../index.js';

describe('validateModulusLength', () => {
  it('should exist', () => {
    expect(validateModulusLength).toBeTruthy();
  });

  test.each([
    { algorithm: 'RS256', modulusLength: 2047 },
    { algorithm: 'RS384', modulusLength: 3071 },
    { algorithm: 'RS512', modulusLength: 4095 },
    { algorithm: 'PS256', modulusLength: 2047 },
    { algorithm: 'PS384', modulusLength: 3071 },
    { algorithm: 'PS512', modulusLength: 4095 },
  ] satisfies { algorithm: JwtAlgorithmsRSSchema | JwtAlgorithmsPSSchema; modulusLength: number }[])(
    '$algorithm rejects low modulusLength length of $modulusLength',
    ({ algorithm, modulusLength }) => {
      expect(() => {
        validateModulusLength(algorithm, modulusLength, 'privateKey');
      }).toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );

  test.each([
    { algorithm: 'RS256', modulusLength: 2048 },
    { algorithm: 'RS384', modulusLength: 3072 },
    { algorithm: 'RS512', modulusLength: 4096 },
    { algorithm: 'PS256', modulusLength: 2048 },
    { algorithm: 'PS384', modulusLength: 3072 },
    { algorithm: 'PS512', modulusLength: 4096 },
  ] satisfies { algorithm: JwtAlgorithmsRSSchema | JwtAlgorithmsPSSchema; modulusLength: number }[])(
    '$algorithm accepts valid modulusLength length of $modulusLength',
    ({ algorithm, modulusLength }) => {
      expect(() => {
        validateModulusLength(algorithm, modulusLength, 'privateKey');
      }).not.toThrow(JwtProviderInvalidKeyMaterialError);
    }
  );
});
