openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve | \
  openssl pkcs8 -topk8 -nocrypt -outform pem > vldm_private_nonstandard.pem

openssl pkey -pubout -inform pem -outform pem \
    -in vldm_private_nonstandard.pem \
    -out vldm_public.pem

openssl ec -in vldm_private_nonstandard.pem  -out vldm_private.pem
