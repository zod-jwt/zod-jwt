import { describe, expect, it } from 'vitest';
import { constructHeaderPayload, toBase64 } from '../index.js';

describe('constructHeaderPayload', () => {
  it('should exist', () => {
    expect(constructHeaderPayload).toBeTruthy();
  });

  it('should create a valid payload', () => {
    const headerPayload = constructHeaderPayload({
      header: {
        typ: 'JWT',
        alg: 'RS256',
      },
      payload: {
        test: 'test',
      },
    });

    const [header, payload] = toBase64(headerPayload, 'headerPayload').split('.');

    const headerJson = JSON.parse(Buffer.from(header, 'base64').toString('utf-8'));
    const payloadJson = JSON.parse(Buffer.from(payload, 'base64').toString('utf-8'));

    expect(headerJson).deep.equal({
      typ: 'JWT',
      alg: 'RS256',
    });

    expect(payloadJson).deep.equal({
      test: 'test',
    });
  });
});
