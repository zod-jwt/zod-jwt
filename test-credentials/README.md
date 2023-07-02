## You should not ever use these in a real application!!!

---

This directory contains a set of public/private keys for testing.

These are the commands that generated them:

```bash

# Make sure your openssl version is up to date
sudo apt update
sudo apt upgrade openssl

# For RS256
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rs_256_private.pem
openssl pkey -in rs_256_private.pem -pubout -out rs_256_public.pem

# For RS384
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rs_384_private.pem
openssl pkey -in rs_384_private.pem -pubout -out rs_384_public.pem

# For RS512
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rs_512_private.pem
openssl pkey -in rs_512_private.pem -pubout -out rs_512_public.pem

############

# For ES256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es_256_private.pem
openssl pkey -in es_256_private.pem -pubout -out es_256_public.pem

# For ES384
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out es_384_private.pem
openssl pkey -in es_384_private.pem -pubout -out es_384_public.pem

# For ES512 (Yes, curve is 521, not 512)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out es_512_private.pem
openssl pkey -in es_512_private.pem -pubout -out es_512_public.pem

############

# For PS256
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out ps_256_private.pem
openssl rsa -pubout -in ps_256_private.pem -out ps_256_public.pem

# For PS384
openssl genpkey -algorithm RSA-PSS -out ps_384_private.pem -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:48
openssl rsa -pubout -in ps_384_private.pem -out ps_384_public.pem

# For PS512
openssl genpkey -algorithm RSA-PSS -out ps_512_private.pem -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_pss_keygen_md:sha512 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:64
openssl rsa -pubout -in ps_512_private.pem -out ps_512_public.pem

```
