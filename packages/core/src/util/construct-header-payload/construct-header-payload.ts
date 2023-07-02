import { HeaderPayload, IJSON, JsonString, JwtAlgorithmsSchema, JwtHeaderSchema } from '../../schema/index.js';
import { toBase64Url } from '../index.js';

export type ConstructHeaderPayloadArgs<SupportedAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema> = {
  header: JwtHeaderSchema<SupportedAlgorithms>;
  payload: IJSON;
};

/**
 * Combines the header and payload of the jwt in a base64 string separated by a "."
 *
 *
 */
export const constructHeaderPayload = <SupportedAlgorithms extends JwtAlgorithmsSchema = JwtAlgorithmsSchema>(
  args: ConstructHeaderPayloadArgs<SupportedAlgorithms>
) => {
  const header = toBase64Url(JSON.stringify(args.header) as JsonString, 'utf8');
  const payload = toBase64Url(JSON.stringify(args.payload) as JsonString, 'utf8');
  return `${header}.${payload}` as HeaderPayload;
};
