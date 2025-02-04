#if defined(_WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(_WIN32) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "pattern.h"
#include "util.h"
#include "sph_groestl.h"
#include "sha3.h"
#include "ticker.h"
#include "avl.h"
#include <Windows.h>

#define BYTES_TO_COMPARE 21
#define ADR_LENGTH 25
#define VERBOSE

typedef struct _bruteforce_context_s {
	vg_context_t		base;
	char** addresses;
	//avl_root_t		vcp_avlroot;
	//BIGNUM* vcp_difficulty;
	//int			vcp_caseinsensitive;
} bruteforce_context_t;

static void
bruteforce_context_free(vg_context_t* vcp)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;
	free(vcpp->addresses);
	free(vcpp);
}

static int compare_addresses(void* context, const void* a, const void* b) {
	bruteforce_context_t* vcpp = (bruteforce_context_t*)context;

	const char* adr1 = *(const char**)a;
	const char* adr2 = *(const char**)b;

	return memcmp(adr1, adr2, BYTES_TO_COMPARE);
}

static int
bruteforce_context_add_patterns(vg_context_t* vcp,
	const char** const patterns, int npatterns)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;
	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, "Adding and sorting %i patterns...", npatterns);
	}

	char** addresses = (char**)malloc(npatterns * sizeof(char*));
	for (int i = 0; i < npatterns; i++) {
		const char* encoded = patterns[i];
		if (vcpp->base.vc_verbose > 1) {
			fprintf(stderr, "\nprocessing %i: %s", i, encoded);
		}
		char decoded[ADR_LENGTH];
		int check = vg_b58_decode_check(encoded, decoded, ADR_LENGTH * sizeof(char));
		char* bytes2compare = (char*)malloc(BYTES_TO_COMPARE * sizeof(char));
		memcpy(bytes2compare, decoded, BYTES_TO_COMPARE * sizeof(char));
		if (vcpp->base.vc_verbose > 1) {
			fprintf(stderr, " -> ");
			char hex[BYTES_TO_COMPARE * 3]{};
			size_t hexsz = BYTES_TO_COMPARE * sizeof(char) * 3;
			hex_enc(hex, &hexsz, bytes2compare, BYTES_TO_COMPARE * sizeof(char));
			fprintf(stderr, "%s", hex);
			fprintf(stderr, " at %p", bytes2compare);
		}
		addresses[i] = bytes2compare;
	}

	qsort_s(addresses, npatterns, sizeof(char*), compare_addresses, vcp);

	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, "\nResult:");

		for (int i = 0; i < npatterns; i++) {
			const char* adr = addresses[i];
			char hex[BYTES_TO_COMPARE * 3]{};
			size_t hexsz = BYTES_TO_COMPARE * sizeof(char) * 3;
			hex_enc(hex, &hexsz, adr, BYTES_TO_COMPARE * sizeof(char));
			fprintf(stderr, "\n%s at %p", hex, adr);
		}
	}

	vcpp->base.vc_npatterns = npatterns;
	vcpp->addresses = addresses;

	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, " done!\n");
		fprintf(stderr, "Addresses set to %p, element 0: %p\n", vcpp->addresses, vcpp->addresses[0]);
	}

	return 1;
}

static void
bruteforce_context_clear_all_patterns(vg_context_t* vcp)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;
	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, "Clearing all patterns...");
	}

	for (int i = 0; i < vcpp->base.vc_npatterns; i++) {
		free(vcpp->addresses[i]);
	}
}


// return 0 (not found), 1 (found), 2 (not continue)
static int
bruteforce_test(vg_exec_context_t* vxcp)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vxcp->vxc_vc;

research:
#ifdef VERBOSE
	if (vcpp->base.vc_verbose > 1) {
		char hex[BYTES_TO_COMPARE * 3]{};
		size_t hexsz = BYTES_TO_COMPARE * sizeof(char) * 3;
		hex_enc(hex, &hexsz, vxcp->vxc_binres, BYTES_TO_COMPARE * sizeof(char));
		fprintf(stderr, "Candidate: %s at %p", hex, vxcp->vxc_binres);
	}
#endif

	char* p_binres = (char*)&vxcp->vxc_binres[0];

	char** result = (char**)bsearch_s(&p_binres, vcpp->addresses, vcpp->base.vc_npatterns, sizeof(char*), compare_addresses, vxcp->vxc_vc);

	if (result == NULL) {
		return 0;
	}

	if (vg_exec_context_upgrade_lock(vxcp))
		goto research;

	vg_exec_context_consolidate_key(vxcp);

	char hex[BYTES_TO_COMPARE * 3]{};
	size_t hexsz = BYTES_TO_COMPARE * sizeof(char) * 3;
	hex_enc(hex, &hexsz, vxcp->vxc_binres, BYTES_TO_COMPARE * sizeof(char));

	vcpp->base.vc_output_match(&vcpp->base, vxcp->vxc_key, hex);

	vcpp->base.vc_found++;
	if (vcpp->base.vc_numpairs >= 1 && vcpp->base.vc_found >= vcpp->base.vc_numpairs) {
		exit(1);
	}
	if (vcpp->base.vc_only_one) {
		return 2;
	}
}

vg_context_t*
bruteforce_context_new(int addrtype, int privtype)
{
	fprintf(stderr, "Brute force length: %d bytes\n", BYTES_TO_COMPARE);
	bruteforce_context_t* vcpp;

	vcpp = (bruteforce_context_t*)malloc(sizeof(*vcpp));
	if (vcpp) {
		memset(vcpp, 0, sizeof(*vcpp));
		vcpp->base.vc_addrtype = addrtype;
		vcpp->base.vc_privtype = privtype;
		vcpp->base.vc_npatterns = 0;
		vcpp->base.vc_npatterns_start = 0;
		vcpp->base.vc_found = 0;
		vcpp->base.vc_chance = 0.0;
		vcpp->base.vc_free = bruteforce_context_free;
		vcpp->base.vc_add_patterns = bruteforce_context_add_patterns;
		vcpp->base.vc_clear_all_patterns = bruteforce_context_clear_all_patterns;
		vcpp->base.vc_test = bruteforce_test;
	}
	return &vcpp->base;
}