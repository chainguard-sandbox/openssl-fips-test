# openssl-fips-test

A simple tool for validating whether or not OpenSSL is properly configured
to use its FIPS module.

## Caveats

This tool can only detect whether or not OpenSSL is properly configured:
applications and languages must be built to make use of shared linked system
libcrypto in order for the OpenSSL FIPS configuration to be used.

This tool does not validate whether any other element in an overall delivered
configuration is, or is not, FIPS 140-3 compliant. It only tests whether
OpenSSL is properly configured and is making use of the FIPS module correctly.

## Usage

All Chainguard FIPS images ship `openssl-fips-test` preinstalled.

On other systems, run `make` and `make install`.  You must have the OpenSSL
development headers installed in order to build this tool, as well as a C
compiler.

## About this tool

Prior to loading any providers, a callback is added to capture output of KAT
(known answer tests) selftests.

It then loads default OpenSSL library context, and verifies that a FIPS
provider is loaded. It checks that by default the FIPS variants of algorithms
are used.

It also retrieves FIPS module information and returns CMVP & ESV certificates
where known, or a CMVP search URL where one should be able to find applicable
certificates. If certificates cannot be located with matching versions, one is
using non-validated module.

It also provides a summary of available algorithms, which is useful to compare
different CMVP modules and the algorithms they offer.

## Example output

Systems without a FIPS provider will typically report this:

```
$ openssl-fips-test
Checking OpenSSL lifecycle assurance.

	✗ Check FIPS cryptographic module is available... FAILED.
	✗ Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)... FAILED.
	✗ Check non-approved algorithm blocked (HMAC-MD5)... FAILED.

Failed to retrieve cryptographic module version information
```

Example of systems using Chainguard FIPS provider:

```
$ OPENSSL_CONF_INCLUDE=/etc/ssl-3.6.0 openssl-fips-test
Checking OpenSSL lifecycle assurance.

	✓ Self-test KAT_Integrity HMAC ... passed.
	✓ Self-test Module_Integrity HMAC ... passed.
	✓ Self-test KAT_Digest SHA2 ... passed.
	✓ Self-test KAT_Digest SHA3 ... passed.
	✓ Self-test KAT_Cipher AES_GCM ... passed.
	✓ Self-test KAT_Cipher AES_ECB_Decrypt ... passed.
	✓ Self-test KAT_Signature RSA ... passed.
	✓ Self-test KAT_Signature ECDSA ... passed.
	✓ Self-test KAT_Signature DetECDSA ... passed.
	✓ Self-test KAT_Signature EDDSA ... passed.
	✓ Self-test KAT_Signature EDDSA ... passed.
	✓ Self-test KAT_Signature ML-DSA ... passed.
	✓ Self-test KAT_Signature SLH-DSA ... passed.
	✓ Self-test KAT_Signature SLH-DSA ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXTRACT ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXPAND ... passed.
	✓ Self-test KAT_KDF TLS12_PRF ... passed.
	✓ Self-test KAT_KDF PBKDF2 ... passed.
	✓ Self-test KAT_KDF KBKDF ... passed.
	✓ Self-test KAT_KDF KBKDF_KMAC ... passed.
	✓ Self-test KAT_KDF HKDF ... passed.
	✓ Self-test KAT_KDF SSKDF ... passed.
	✓ Self-test KAT_KDF X963KDF ... passed.
	✓ Self-test KAT_KDF X942KDF ... passed.
	✓ Self-test DRBG HASH ... passed.
	✓ Self-test DRBG CTR ... passed.
	✓ Self-test DRBG HMAC ... passed.
	✓ Self-test KAT_KA DH ... passed.
	✓ Self-test KAT_KA ECDH ... passed.
	✓ Self-test KAT_AsymmetricKeyGeneration ML-KEM ... passed.
	✓ Self-test KAT_AsymmetricKeyGeneration ML-DSA ... passed.
	✓ Self-test KAT_AsymmetricKeyGeneration SLH-DSA ... passed.
	✓ Self-test KAT_KEM KEM_Encap ... passed.
	✓ Self-test KAT_KEM KEM_Decap ... passed.
	✓ Self-test KAT_KEM KEM_Decap_Reject ... passed.

	✓ 35 out of 35 self-tests passed.
	✓ Check FIPS cryptographic module is available... passed.
	✓ Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)... passed.
	✓ Check non-approved algorithm blocked (HMAC-MD5)... passed.

Non-approved allowed legacy services for non-security purposes as per FIPS 140-3 I.G. 2.4.A:
	✓ MD4  Digest-only; no HMAC, no digital signatures
	✓ MD5  Digest-only; no HMAC, no digital signatures
	✓ SHA1 Digest-only; no HMAC, no digital signatures

Approved services allowed for security purposes:
	✗ MD5
	✗ SHA-1
	✓ SHA-2
	✓ SHA-3
	✗ DSA
	✓ RSA
	✓ ECDSA
	✓ Ed25519
	✓ DetECDSA
	✓ ML-DSA
	✓ SLH-DSA
	✓ ML-KEM
	✓ X25519MLKEM768
	✓ SecP256r1MLKEM768
	✓ SecP384r1MLKEM1024

FIPS algorithms compliance:
	✓ RSA    enforces minimum 112 bits of security
	✓ ECDSA  enforces minimum 112 bits of security
	✓ HMAC   enforces minimum 112 bits of security
	✓ X25519 blocked

CVE fix status in the FIPS module boundary:
	✓ CVE-2026-42770
	✓ CVE-2026-31790
	✓ CVE-2026-28386
	✓ CVE-2024-13176
	✓ CVE-2024-4603
	✓ CVE-2023-6237
	✓ CVE-2023-1255
	✓ CVE-2023-0217
	✓ CVE-2022-4304

Public OpenSSL API (libssl.so & libcrypto.so):
	name:     	OpenSSL 4.0.3 29 Sep 2026
	version:  	4.0.3

FIPS cryptographic module provider details (fips.so):
	name:     	Chainguard FIPS Provider for OpenSSL
	version:  	3.6.0
	build:    	3.6.0-r4

Locate applicable certificate(s) at: CMVP #5523 (with entropy #E191)

Lifecycle assurance satisfied.
```

Example of systems using OpenSSL Project FIPS provider with unacceptable weaknesses, requiring continuous monitoring:

```
$ OPENSSL_CONF=/etc/ssl/openssl-fips.cnf openssl-fips-test
Checking OpenSSL lifecycle assurance.

	✓ Self-test KAT_Integrity HMAC ... passed.
	✓ Self-test Module_Integrity HMAC ... passed.
	✓ Self-test KAT_Digest SHA1 ... passed.
	✓ Self-test KAT_Digest SHA2 ... passed.
	✓ Self-test KAT_Digest SHA3 ... passed.
	✓ Self-test KAT_Cipher AES_GCM ... passed.
	✓ Self-test KAT_Cipher AES_ECB_Decrypt ... passed.
	✓ Self-test Continuous_RNG_Test RNG ... passed.
	✓ Self-test KAT_Signature RSA ... passed.
	✓ Self-test KAT_Signature ECDSA ... passed.
	✓ Self-test KAT_Signature ECDSA ... passed.
	✓ Self-test KAT_Signature DSA ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXTRACT ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXPAND ... passed.
	✓ Self-test KAT_KDF TLS12_PRF ... passed.
	✓ Self-test KAT_KDF PBKDF2 ... passed.
	✓ Self-test KAT_KDF SSHKDF ... passed.
	✓ Self-test KAT_KDF KBKDF ... passed.
	✓ Self-test KAT_KDF HKDF ... passed.
	✓ Self-test KAT_KDF SSKDF ... passed.
	✓ Self-test KAT_KDF X963KDF ... passed.
	✓ Self-test KAT_KDF X942KDF ... passed.
	✓ Self-test DRBG HASH ... passed.
	✓ Self-test DRBG CTR ... passed.
	✓ Self-test DRBG HMAC ... passed.
	✓ Self-test KAT_KA DH ... passed.
	✓ Self-test KAT_KA ECDH ... passed.
	✓ Self-test KAT_AsymmetricCipher RSA_Encrypt ... passed.
	✓ Self-test KAT_AsymmetricCipher RSA_Decrypt ... passed.
	✓ Self-test KAT_AsymmetricCipher RSA_Decrypt ... passed.

	✓ 30 out of 30 self-tests passed.
	✓ Check FIPS cryptographic module is available... passed.
	✓ Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)... passed.
	✓ Check non-approved algorithm blocked (HMAC-MD5)... passed.

Non-approved allowed legacy services for non-security purposes as per FIPS 140-3 I.G. 2.4.A:
	✓ MD5  Digest-only; no HMAC, no digital signatures
	✗ SHA1 HMAC not blocked

Approved services allowed for security purposes:
	✗ MD5
	✓ SHA-1
	✓ SHA-2
	✓ SHA-3
	✓ DSA
	✓ RSA
	✓ ECDSA
	✗ Ed25519
	✗ DetECDSA
	✗ ML-DSA
	✗ SLH-DSA
	✗ ML-KEM
	✗ X25519MLKEM768
	✗ SecP256r1MLKEM768
	✗ SecP384r1MLKEM1024

FIPS algorithms compliance:
	✓ RSA    enforces minimum 112 bits of security
	✗ ECDSA  allows less than 112 bits of security
	✗ HMAC   allows less than 112 bits of security
	✗ X25519 disallowed algorithm marked as approved

CVE fix status in the FIPS module boundary:
	✗ CVE-2026-42770
	✗ CVE-2026-31790
	✓ CVE-2026-28386
	✗ CVE-2024-13176
	✗ CVE-2024-4603
	✗ CVE-2023-6237
	✗ CVE-2023-1255
	✗ CVE-2023-0217
	✗ CVE-2022-4304

Public OpenSSL API (libssl.so & libcrypto.so):
	name:     	OpenSSL 3.5.7 9 Jun 2026
	version:  	3.5.7

FIPS cryptographic module provider details (fips.so):
	name:     	OpenSSL FIPS Provider
	version:  	3.1.2
	build:    	3.1.2

Locate applicable certificate(s) at: CMVP #4985

Lifecycle assurance satisfied. Unacceptable weaknesses detected. Continuous monitoring required.
```
