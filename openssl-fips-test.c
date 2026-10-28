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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>
#include <openssl/opensslv.h>

#include <dlfcn.h>

/*
 * libcrypto is dlopen'ed at runtime, OpenSSL headers are only used for
 * function prototypes.
 */
#define LIBCRYPTO_FUNCS(X) \
	X(ERR_clear_error) \
	X(EVP_default_properties_is_fips_enabled) \
	X(EVP_KEM_fetch) \
	X(EVP_KEM_free) \
	X(EVP_KEYEXCH_fetch) \
	X(EVP_KEYEXCH_free) \
	X(EVP_MD_fetch) \
	X(EVP_MD_free) \
	X(EVP_PKEY_free) \
	X(EVP_PKEY_Q_keygen) \
	X(EVP_Q_mac) \
	X(EVP_SIGNATURE_fetch) \
	X(EVP_SIGNATURE_free) \
	X(OpenSSL_version) \
	X(OSSL_LIB_CTX_get0_global_default) \
	X(OSSL_PARAM_construct_end) \
	X(OSSL_PARAM_construct_utf8_ptr) \
	X(OSSL_PARAM_construct_utf8_string) \
	X(OSSL_PARAM_locate_const) \
	X(OSSL_PARAM_modified) \
	X(OSSL_PROVIDER_available) \
	X(OSSL_PROVIDER_get_params) \
	X(OSSL_PROVIDER_load) \
	X(OSSL_SELF_TEST_set_callback)

#define LIBCRYPTO_DECLARE(f) static __typeof__(&f) p_##f;
LIBCRYPTO_FUNCS(LIBCRYPTO_DECLARE)

static const char *libcrypto_names[] = {
	"libcrypto.so.4",
	"libcrypto.so.3",
	"libcrypto.so",
};

static bool
load_libcrypto(void)
{
	void *handle = NULL;

	for (size_t i = 0; i < sizeof(libcrypto_names) / sizeof(*libcrypto_names) && handle == NULL; i++)
		handle = dlopen(libcrypto_names[i], RTLD_NOW | RTLD_GLOBAL);

	if (handle == NULL) {
		fprintf(stderr, "Failed to dlopen libcrypto: %s\n", dlerror());
		return false;
	}

#define LIBCRYPTO_LOAD(f) \
	if ((p_##f = (__typeof__(p_##f))dlsym(handle, #f)) == NULL) { \
		fprintf(stderr, "Failed to load %s from libcrypto: %s\n", #f, dlerror()); \
		return false; \
	}
	LIBCRYPTO_FUNCS(LIBCRYPTO_LOAD)

	return true;
}

#define ERR_clear_error p_ERR_clear_error
#define EVP_default_properties_is_fips_enabled p_EVP_default_properties_is_fips_enabled
#define EVP_KEM_fetch p_EVP_KEM_fetch
#define EVP_KEM_free p_EVP_KEM_free
#define EVP_KEYEXCH_fetch p_EVP_KEYEXCH_fetch
#define EVP_KEYEXCH_free p_EVP_KEYEXCH_free
#define EVP_MD_fetch p_EVP_MD_fetch
#define EVP_MD_free p_EVP_MD_free
#define EVP_PKEY_free p_EVP_PKEY_free
#define EVP_PKEY_Q_keygen p_EVP_PKEY_Q_keygen
#define EVP_Q_mac p_EVP_Q_mac
#define EVP_SIGNATURE_fetch p_EVP_SIGNATURE_fetch
#define EVP_SIGNATURE_free p_EVP_SIGNATURE_free
#define OpenSSL_version p_OpenSSL_version
#define OSSL_LIB_CTX_get0_global_default p_OSSL_LIB_CTX_get0_global_default
#define OSSL_PARAM_construct_end p_OSSL_PARAM_construct_end
#define OSSL_PARAM_construct_utf8_ptr p_OSSL_PARAM_construct_utf8_ptr
#define OSSL_PARAM_construct_utf8_string p_OSSL_PARAM_construct_utf8_string
#define OSSL_PARAM_locate_const p_OSSL_PARAM_locate_const
#define OSSL_PARAM_modified p_OSSL_PARAM_modified
#define OSSL_PROVIDER_available p_OSSL_PROVIDER_available
#define OSSL_PROVIDER_get_params p_OSSL_PROVIDER_get_params
#define OSSL_PROVIDER_load p_OSSL_PROVIDER_load
#define OSSL_SELF_TEST_set_callback p_OSSL_SELF_TEST_set_callback

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
int weaknesses = 0;

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
		.name = "MD4",
	},
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

/* CVEs within the FIPS module boundary, from https://openssl-library.org/news/fips-cve/ */
static const char *fips_cves[] = {
	"CVE-2026-42770",
	"CVE-2026-31790",
	"CVE-2026-28386",
	"CVE-2024-13176",
	"CVE-2024-4603",
	"CVE-2023-6237",
	"CVE-2023-1255",
	"CVE-2023-0217",
	"CVE-2022-4304",
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

static const char *non_security_propqs[] = {
	"fips=no",
	"provider=legacy",
};

static bool
test_hmac_blocked(const char *digest, const char *propq)
{
	size_t outlen = 0;
	OSSL_PARAM params[2];

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES, (char *)propq, 0);
	params[1] = OSSL_PARAM_construct_end();

	unsigned char *hmac = EVP_Q_mac(NULL, "HMAC", propq, digest, params, "12345678901234", 14, NULL, 0, NULL, 0, &outlen);
	if (hmac != NULL) {
		free(hmac);
		return false;
	}

	return true;
}

static void print_non_security_digests(void) {
	EVP_MD *digest = NULL;

	fprintf(stderr, "\nNon-approved allowed legacy services for non-security purposes as per FIPS 140-3 I.G. 2.4.A:\n");

	for (size_t i = 0; i < ARRAY_SIZE(non_approved_digests); i++)
	{
		const char *propq = NULL;

		for (size_t j = 0; j < ARRAY_SIZE(non_security_propqs) && digest == NULL; j++)
		{
			propq = non_security_propqs[j];
			digest = EVP_MD_fetch(NULL, non_approved_digests[i].name, propq);
			ERR_clear_error();
		}
		if (digest == NULL)
			continue;

		fprintf(stderr, "\t");
		if (test_hmac_blocked(non_approved_digests[i].name, propq)) {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%-4s Digest-only; no HMAC, no digital signatures", non_approved_digests[i].name);
		} else {
			fprintf(stderr, RED_CROSS);
			fprintf(stderr, "%-4s HMAC not blocked", non_approved_digests[i].name);
		}
		fprintf(stderr, "\n");
		ERR_clear_error();
		EVP_MD_free(digest);
		digest = NULL;
	}
}

static void print_security_features(void) {
	EVP_MD *digest = NULL;
        EVP_SIGNATURE *signature = NULL;
        EVP_KEM *kem = NULL;

	fprintf(stderr, "\nApproved services allowed for security purposes:\n");

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

static void print_fips_compliance(void) {
	EVP_KEYEXCH *keyexch = NULL;
	unsigned char *hmac = NULL;
	size_t outlen = 0;
	EVP_PKEY *rsa1k = NULL, *rsa2k = NULL;
	EVP_PKEY *ec192 = NULL, *ec256 = NULL;

	fprintf(stderr, "\nFIPS algorithms compliance:\n");

	/* RSA 1024 provides 80 bits of security, RSA 2048 provides 112 bits */
	rsa1k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)1024);
	ERR_clear_error();
	rsa2k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
	ERR_clear_error();
	if (rsa2k != NULL) {
		fprintf(stderr, "\t");
		if (rsa1k != NULL) {
			fprintf(stderr, RED_CROSS);
			weaknesses++;
			fprintf(stderr, "%-6s allows less than 112 bits of security", "RSA");
		} else {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%-6s enforces minimum 112 bits of security", "RSA");
		}
		fprintf(stderr, "\n");
	}
	EVP_PKEY_free(rsa1k);
	EVP_PKEY_free(rsa2k);

	/* prime192v1 provides 96 bits of security, below the 112 bits minimum */
	ec192 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime192v1");
	ERR_clear_error();
	ec256 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
	ERR_clear_error();
	if (ec256 != NULL) {
		fprintf(stderr, "\t");
		if (ec192 != NULL) {
			fprintf(stderr, RED_CROSS);
			weaknesses++;
			fprintf(stderr, "%-6s allows less than 112 bits of security", "ECDSA");
		} else {
			fprintf(stderr, GREEN_CHECK);
			fprintf(stderr, "%-6s enforces minimum 112 bits of security", "ECDSA");
		}
		fprintf(stderr, "\n");
	}
	EVP_PKEY_free(ec192);
	EVP_PKEY_free(ec256);

	/* 13 bytes is 104 bits, below the 112 bits minimum key length */
	hmac = EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, "1234567890123", 13, NULL, 0, NULL, 0, &outlen);
	ERR_clear_error();
	fprintf(stderr, "\t");
	if (hmac == NULL) {
		fprintf(stderr, GREEN_CHECK);
		fprintf(stderr, "%-6s enforces minimum 112 bits of security", "HMAC");
	} else {
		fprintf(stderr, RED_CROSS);
		weaknesses++;
		fprintf(stderr, "%-6s allows less than 112 bits of security", "HMAC");
		free(hmac);
	}
	fprintf(stderr, "\n");

	keyexch = EVP_KEYEXCH_fetch(NULL, "X25519", "fips=yes");
	ERR_clear_error();
	fprintf(stderr, "\t");
	if (keyexch == NULL) {
		fprintf(stderr, GREEN_CHECK);
		fprintf(stderr, "%-6s blocked", "X25519");
	} else {
		fprintf(stderr, RED_CROSS);
		weaknesses++;
		fprintf(stderr, "%-6s disallowed algorithm marked as approved", "X25519");
		EVP_KEYEXCH_free(keyexch);
	}
	fprintf(stderr, "\n");
}

static void print_base_version(void) {
	fprintf(stderr, "\nPublic OpenSSL API (libssl.so & libcrypto.so):\n");
	fprintf(stderr, "\t%-10s\t%s\n", "name:", OpenSSL_version(OPENSSL_VERSION));
	fprintf(stderr, "\t%-10s\t%s\n", "version:", OpenSSL_version(OPENSSL_VERSION_STRING));
	//fprintf(stderr, "\t%-10s\t%s\n", "full-version:", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
	//fprintf(stderr, "\t%-10s\t%s\n", "built-on:", OpenSSL_version(OPENSSL_BUILT_ON) + 10);
	fprintf(stderr, "\n");
}

static void print_module_cves(void) {
	OSSL_PROVIDER *prov = NULL;
	OSSL_PARAM params[3];
	char *name = "", *vers = "";

	prov = OSSL_PROVIDER_load(NULL, "fips");
	if (prov == NULL)
		return;

	params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, sizeof(name));
	params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &vers, sizeof(vers));
	params[2] = OSSL_PARAM_construct_end();
	if (!OSSL_PROVIDER_get_params(prov, params))
		return;

	bool chainguard = strcmp(name, "Chainguard FIPS Provider for OpenSSL") == 0
		&& (strncmp(vers, "3.4.", 4) == 0 || strncmp(vers, "3.6.", 4) == 0);

	if (!chainguard && strncmp(vers, "3.1.2", 5) != 0)
		return;

	fprintf(stderr, "\nCVE fix status in the FIPS module boundary:\n");
	for (size_t i = 0; i < ARRAY_SIZE(fips_cves); i++)
	{
		fprintf(stderr, "\t");
		if (chainguard || strcmp(fips_cves[i], "CVE-2026-28386") == 0)
			fprintf(stderr, GREEN_CHECK);
		else {
			fprintf(stderr, RED_CROSS);
			weaknesses++;
		}
		fprintf(stderr, "%s\n", fips_cves[i]);
	}
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
                if (strcmp(build, "3.4.0-r5") == 0) {
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

	if (!load_libcrypto())
		return EXIT_FAILURE;

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
		/* Do not report conditional self-tests triggered by the checks below */
		OSSL_SELF_TEST_set_callback(NULL, NULL, NULL);
		print_non_security_digests();
		//print_security_digests();
		print_security_features();
		print_fips_compliance();
		print_module_cves();
		print_base_version();
		print_module_version();
		if (weaknesses == 0) {
			fprintf(stderr, BOLD_GREEN);
			fprintf(stderr, "\nLifecycle assurance satisfied.");
		} else {
			fprintf(stderr, BOLD_RED);
			fprintf(stderr, "\nLifecycle assurance satisfied. Unacceptable weaknesses detected. Continuous monitoring required.");
		}
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
