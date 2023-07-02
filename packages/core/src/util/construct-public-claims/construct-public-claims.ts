import ms from 'ms';

export type ConstructPublicClaimsArgs = {
  publicClaims: {
    iat?: string | number;
    exp?: string | number;
    nbf?: string | number;
    iss?: string;
    aud?: string;
    sub?: string;
    jti?: string;
  };
  constructionDate?: Date;
};

export const constructPublicClaims = (props: ConstructPublicClaimsArgs) => {
  const {
    constructionDate,
    publicClaims: { aud, exp, iat, iss, nbf, sub, jti },
  } = props;

  const constructionTime = constructionDate ? constructionDate.getTime() : new Date().getTime();

  // All of time based claims are rounded down to the nearest second.
  // To avoid issues with a token not being immediately available the nbf claim is rounded down.
  // The same logic is applied to the iat and exp claims to remain consistent in methodology.

  const publicClaims = {
    iat:
      typeof iat === 'number'
        ? Math.floor((constructionTime + iat) / 1000)
        : typeof iat === 'string'
        ? Math.floor((constructionTime + ms(iat)) / 1000)
        : Math.floor(constructionTime / 1000),
    exp:
      typeof exp === 'number'
        ? Math.floor((constructionTime + exp) / 1000)
        : typeof exp === 'string'
        ? Math.floor((constructionTime + ms(exp)) / 1000)
        : Math.floor((constructionTime + 60000 * 15) / 1000),
    nbf:
      typeof nbf === 'number'
        ? Math.floor((constructionTime + nbf) / 1000)
        : typeof nbf === 'string'
        ? Math.floor((constructionTime + ms(nbf)) / 1000)
        : Math.floor(constructionTime / 1000),
    aud,
    iss,
    jti,
    sub,
  } as const;

  return publicClaims;
};
