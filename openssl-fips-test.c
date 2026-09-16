// Copyright 2023-2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>
#include <openssl/opensslv.h>

struct test_ {
	const char *name;
	const bool expected;
	bool (*test_fn)(void);
};

struct digest_ {
	const char *name;
	const bool dissallowed;
	const bool legacy;
};

struct feature_ {
	const char *fetch;
	const char *name;
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

#define BOLD_RED "\x1B[0;1;31m"
#define BOLD_GREEN "\x1B[0;1;32m"
#define RESET "\x1B[0m"

#define OSC_8_START "\033]8;;"
#define OSC_8_END "\033\\"

#define FAILED (BOLD_RED " FAILED" RESET ".\n")
#define PASSED (BOLD_GREEN " passed" RESET ".\n")

#define RED_CROSS (BOLD_RED "✗ " RESET)
#define GREEN_CHECK (BOLD_GREEN "✓ " RESET)
#define GREEN_CROSS (BOLD_GREEN "✗ " RESET)

int selftest_passes = 0;
int selftest_failures = 0;
int selftest_total = 0;
int detecdsa = 0;

static bool
test_fips_module_is_available(void)
{
	fprintf(stderr, "\n");

	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	int rc = OSSL_PROVIDER_available(ctx, "fips");

	if (!rc)
		return false;

	if (selftest_passes == 0)
		return false;

	fprintf(stderr, "\n");
	fprintf(stderr, "\t");
	fprintf(stderr, GREEN_CHECK);
	fprintf(stderr, "%i out of %i self-tests", selftest_passes, selftest_passes+selftest_failures);
	fprintf(stderr, PASSED);

	return (selftest_failures == 0);
}

static bool
test_fips_module_is_enabled(void)
{
	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	if (!EVP_default_properties_is_fips_enabled(ctx))
		return false;

	return true;
}

static bool
test_hmac_md5_not_available(void)
{
	size_t outlen = 0;

	unsigned char *hmac_md5 = EVP_Q_mac(NULL, "HMAC", NULL, "MD5", NULL, "12345678901234", 14, NULL, 0, NULL, 0, &outlen);
	if (hmac_md5 != NULL) {
		free(hmac_md5);
		return false;
	}

	return true;
}

static const struct test_ tests[] = {
	{
		.name = "Check FIPS cryptographic module is available...",
		.expected = true,
		.test_fn = test_fips_module_is_available,
	},
	{
		.name = "Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)...",
		.expected = true,
		.test_fn = test_fips_module_is_enabled,
	},
	{
		.name = "Check non-approved algorithm blocked (HMAC-MD5)...",
		.expected = true,
		.test_fn = test_hmac_md5_not_available,
	},
};

static const struct digest_ non_approved_digests[] = {
	{
		.name = "MD5",
	},
	{
		.name = "SHA1",
	},
};

static const struct feature_ digest_features[] = {
	{
		.fetch = "MD5",
		.name = "MD5",
	},
	{
		.fetch = "SHA1",
		.name = "SHA-1",
	},
	{
		.fetch = "SHA2-256",
		.name = "SHA-2",
	},
	{
		.fetch = "SHA3-256",
		.name = "SHA-3",
	},
};

static const struct feature_ signature_features[] = {
	{
		.fetch = "DSA",
		.name = "DSA",
	},
	{
		.fetch = "RSA",
		.name = "RSA",
	},
	{
		.fetch = "ECDSA",
		.name = "ECDSA",
	},
	{
		.fetch = "ED25519",
		.name = "Ed25519",
	},
	{
		.fetch = "ECDSA",
		.name = "DetECDSA",
	},
	{
		.fetch = "ML-DSA-87",
		.name = "ML-DSA",
	},
	{
		.fetch = "SLH-DSA-SHAKE-128s",
		.name = "SLH-DSA",
	},
};

static const struct feature_ kem_features[] = {
	{
		.fetch = "ML-KEM-1024",
		.name = "ML-KEM",
	},
	{
		.fetch = "X25519MLKEM768",
		.name = "X25519MLKEM768",
	},
	{
		.fetch = "SecP256r1MLKEM768",
		.name = "SecP256r1MLKEM768",
	},
	{
		.fetch = "SecP384r1MLKEM1024",
		.name = "SecP384r1MLKEM1024",
	},
};


static int self_test_events(const OSSL_PARAM params[], void *arg)
{
	const OSSL_PARAM *p = NULL;
	const char *phase = NULL, *type = NULL, *desc = NULL;

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
	if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
		goto err;
	phase = (const char *)p->data;

	if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) != 0
	    && strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) != 0) {
		return true;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
	if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
		goto err;
	desc = (const char *)p->data;

	p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
	if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
		goto err;
	type = (const char *)p->data;

	if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0) {
		fprintf(stderr, "\t");
		fprintf(stderr, GREEN_CHECK);
		fprintf(stderr, "Self-test %s %s ...", type, desc);
		fprintf(stderr, PASSED);
		selftest_passes++;
                selftest_total++;
		if (strcmp(desc, "DetECDSA") == 0) {
			detecdsa = 1;
		}
	} else if (strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0) {
		fprintf(stderr, "\t");
		fprintf(stderr, RED_CROSS);
		fprintf(stderr, "Self-test %s %s ...", type, desc);
		fprintf(stderr, FAILED);
		selftest_failures++;
                selftest_total++;
	}

	return true;

 err:
	selftest_failures++;
	return false;
}

static void print_non_security_digests(void) {
	EVP_MD *digest = NULL;

	fprintf(stderr, "\nDigests available for non-security use as per FIPS 140-3 I.G. 2.4.A (fips=no):\n");

	for (size_t i = 0; i < ARRAY_SIZE(non_approved_digests); i++)
	{
		digest = EVP_MD_fetch(NULL, non_approved_digests[i].name, "?fips=no");
		fprintf(stderr, "\t");
		if (digest != NULL) {

			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%s", non_approved_digests[i].name);
			EVP_MD_free(digest);
			digest = NULL;
		} else {
			fprintf(stderr, "\t");
			fprintf(stderr, RED_CROSS);
			fprintf(stderr, "%s", non_approved_digests[i].name);
			fprintf(stderr, "- expect failures with all public cloud SDKs");
		}
		fprintf(stderr, "\n");
	}
}

static void print_security_features(void) {
	EVP_MD *digest = NULL;
        EVP_SIGNATURE *signature = NULL;
        EVP_KEM *kem = NULL;

	fprintf(stderr, "\nAvailable approved algorithms for security purposes (provider=fips,fips=yes):\n");

	for (size_t i = 0; i < ARRAY_SIZE(digest_features); i++)
	{
		digest = EVP_MD_fetch(NULL, digest_features[i].fetch, "provider=fips,fips=yes");
		fprintf(stderr, "\t");
		if (digest != NULL) {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%s", digest_features[i].name);
			EVP_MD_free(digest);
			digest = NULL;
		} else {
			fprintf(stderr, "✗ ");
			fprintf(stderr, "%s", digest_features[i].name);
		}
		fprintf(stderr, "\n");
	}
	for (size_t i = 0; i < ARRAY_SIZE(signature_features); i++)
	{
		signature = EVP_SIGNATURE_fetch(NULL, signature_features[i].fetch, "provider=fips,fips=yes");
		fprintf(stderr, "\t");
		if (strcmp(signature_features[i].name, "DetECDSA") == 0
		    && detecdsa == 0) {
			EVP_SIGNATURE_free(signature);
			signature = NULL;
		}
		if (signature != NULL) {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%s", signature_features[i].name);
			EVP_SIGNATURE_free(signature);
			signature = NULL;
		} else {
			fprintf(stderr, "✗ ");
			fprintf(stderr, "%s", signature_features[i].name);
		}
		fprintf(stderr, "\n");
	}
	for (size_t i = 0; i < ARRAY_SIZE(kem_features); i++)
	{
		kem = EVP_KEM_fetch(NULL, kem_features[i].fetch, "provider=fips,fips=yes");
		fprintf(stderr, "\t");
		if (kem != NULL) {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%s", kem_features[i].name);
			EVP_KEM_free(kem);
			kem = NULL;
		} else {
			fprintf(stderr, "✗ ");
			fprintf(stderr, "%s", kem_features[i].name);
		}
		fprintf(stderr, "\n");
	}
}

static void print_base_version(void) {
	fprintf(stderr, "\nPublic OpenSSL API (libssl.so & libcrypto.so):\n");
	fprintf(stderr, "\t%-10s\t%s\n", "name:", OpenSSL_version(OPENSSL_VERSION));
	fprintf(stderr, "\t%-10s\t%s\n", "version:", OpenSSL_version(OPENSSL_VERSION_STRING));
	//fprintf(stderr, "\t%-10s\t%s\n", "full-version:", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
	//fprintf(stderr, "\t%-10s\t%s\n", "built-on:", OpenSSL_version(OPENSSL_BUILT_ON) + 10);
	fprintf(stderr, "\n");
}

static void print_module_version(void) {

	OSSL_PROVIDER *prov = NULL;
	OSSL_PARAM params[4], *p = params;
	char *name = "", *vers = "", *build = "";

	fprintf(stderr, "FIPS cryptographic module provider details (fips.so):\n");
	prov = OSSL_PROVIDER_load(NULL, "fips");
	if (prov == NULL)
		goto err;

	*p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, sizeof(name));
	*p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &vers, sizeof(vers));
	*p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &build, sizeof(build));
	*p = OSSL_PARAM_construct_end();
	if (!OSSL_PROVIDER_get_params(prov, params))
		goto err;
	if (OSSL_PARAM_modified(params))
		fprintf(stderr, "\t%-10s\t%s\n", "name:", name);
	if (OSSL_PARAM_modified(params + 1))
		fprintf(stderr, "\t%-10s\t%s\n", "version:", vers);
	if (OSSL_PARAM_modified(params + 2))
		fprintf(stderr, "\t%-10s\t%s\n", "build:", build);

	fprintf(stderr, "\nLocate applicable certificate(s) at: ");
        /* NIST CMVP search still does not have a version search working */
        if (strcmp(name, "Chainguard FIPS Provider for OpenSSL") == 0) {
                if (strncmp(vers, "3.1.2", 5) == 0) {
                        fprintf(stderr, "%s%s%s%s%s%s%s\n",
                                OSC_8_START,
                                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5102",
                                OSC_8_END,
                                "CMVP #5102",
                                OSC_8_START,
                                "",
                                OSC_8_END
                        );
                        return;
                }
                if (strncmp(vers, "3.4.0", 5) == 0) {
                        fprintf(stderr, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
                                OSC_8_START,
                                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5132",
                                OSC_8_END,
                                "CMVP #5132",
                                OSC_8_START,
                                "",
                                OSC_8_END,
                                " (with ",
                                OSC_8_START,
                                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations/certificate/191",
                                OSC_8_END,
                                "entropy #E191",
                                OSC_8_START,
                                "",
                                OSC_8_END,
                                ")"
                        );
                        return;
                }
                if (strncmp(vers, "3.6.0", 5) == 0) {
                        fprintf(stderr, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
                                OSC_8_START,
                                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5523",
                                OSC_8_END,
                                "CMVP #5523",
                                OSC_8_START,
                                "",
                                OSC_8_END,
                                " (with ",
                                OSC_8_START,
                                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations/certificate/191",
                                OSC_8_END,
                                "entropy #E191",
                                OSC_8_START,
                                "",
                                OSC_8_END,
                                ")"
                        );
                        return;
                }
        }
        if (strcmp(name, "OpenSSL FIPS Provider") == 0
            && strncmp(vers, "3.1.2", 5) == 0) {
		fprintf(stderr, "%s%s%s%s%s%s%s\n",
                        OSC_8_START,
                        "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985",
                        OSC_8_END,
                        "CMVP #4985",
                        OSC_8_START,
                        "",
                        OSC_8_END
                );
                return;
        }

        fprintf(stderr, "%s%s%.5s%s%s%s%s%s\n",
                OSC_8_START,
                "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=OpenSSL&CertificateStatus=Active&ValidationYear=0&SoftwareVersions=",
                vers,
                OSC_8_END,
                "CMVP Search",
                OSC_8_START,
                "",
                OSC_8_END
        );
	return;
 err:
	fprintf(stderr, BOLD_RED);
	fprintf(stderr, "\tFailed to retrieve cryptographic module version information\n");
}

int
main(int argc, const char *argv[])
{
	int rc = EXIT_SUCCESS;

	fprintf(stderr, "Checking OpenSSL lifecycle assurance.\n");

	OSSL_SELF_TEST_set_callback(NULL, self_test_events, NULL);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++)
	{
		bool ret = tests[i].test_fn();

		if (ret != tests[i].expected)
		{
			fprintf(stderr, "\t");
			fprintf(stderr, RED_CROSS);
			fprintf(stderr, "%s", tests[i].name);
			fprintf(stderr, FAILED);
			rc = EXIT_FAILURE;
		}
		else
		{
			fprintf(stderr, "\t");
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%s", tests[i].name);
			fprintf(stderr, PASSED);
		}
	}

	if (rc == EXIT_SUCCESS) {
		print_non_security_digests();
		//print_security_digests();
		print_security_features();
		print_base_version();
		print_module_version();
		fprintf(stderr, BOLD_GREEN);
		fprintf(stderr, "\nLifecycle assurance satisfied.");
		fprintf(stderr, RESET);
		fprintf(stderr, "\n");
	} else {
		fprintf(stderr, BOLD_RED);
		fprintf(stderr, "\nFailed to retrieve cryptographic module version information");
		fprintf(stderr, RESET);
		fprintf(stderr, "\n");
	}

	return rc;
}
