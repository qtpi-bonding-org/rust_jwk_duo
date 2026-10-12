# Upstream sources

## Wycheproof (Apache-2.0, see wycheproof/LICENSE)
Repository C2SP/wycheproof, commit `12fd3aa`, `testvectors_v1/` (fetched from raw.githubusercontent.com at that commit; byte-identical to the earlier seed copies).

## RFC 9180
Filtered from the `hpke` 0.14.1 crate's `test-vectors/origrfc-5f503c5.json` (the final-RFC copy of cfrg test-vectors.json), keeping the single vector with mode 0, KEM 0x0010, KDF 0x0001, AEAD 0x0002.

## JOSE HPKE
`draft-ietf-jose-hpke-encrypt-22`, Appendix A.13, the HPKE-7 private JWK (expected kid `YGdLPiZno0vV3kJKu4kEMQEjK3_upFF2D_lFDf1FFwk`).

## SHA-256
```
985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7  wycheproof/aes_gcm_test.json
648f16d077caf2400d02331ca51f44744c72c799830c8d0595d0b18b6dd9f886  wycheproof/ecdh_secp256r1_ecpoint_test.json
578ddbae7cba6ba89583ed539b15cb601fcbd78c9614480895b577199bc8c985  wycheproof/ecdh_secp256r1_webcrypto_test.json
c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986  wycheproof/ecdsa_secp256r1_sha256_p1363_test.json
182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332  wycheproof/ecdsa_secp256r1_sha256_test.json
58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd  wycheproof/LICENSE
2f218cce52d6d212aadae39afd7374a10aac7b42be864b4981391bc3d26b66c4  rfc9180/test-vectors.json
4c1412db8b6107fde364a02649f54eaa112ddfb3bf37f42c4bf9aaade592910f  jose_hpke/a13_hpke7_private_jwk.json
```
