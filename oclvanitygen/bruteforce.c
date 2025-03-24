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
#include <vector>
#include <array>
#include <cmath>

#define BYTES_TO_COMPARE 21
#define ADR_LENGTH 25
//#define VERBOSE

typedef struct _bruteforce_context_s {
	vg_context_t base;
	std::vector <std::vector<std::array<char, BYTES_TO_COMPARE>>> hashmap;

	_bruteforce_context_s() {
		std::memset(&base, 0, sizeof(base));
	}
} bruteforce_context_t;

static void
bruteforce_context_free(vg_context_t* vcp)
{
	/*
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;
	delete(vcpp);
	*/
}

static unsigned long long rotateLeft(unsigned long long value, unsigned int shift) {
	unsigned int bitCount = sizeof(value) * 8;  // Get the bit width (e.g., 32 for unsigned int)
	shift = shift % bitCount;  // Handle shifts greater than the bit width
	return (value << shift) | (value >> (bitCount - shift));
}

static int calculate_hash(char* bytes2compare, bruteforce_context_t* vcpp) {
	const unsigned int di = sizeof(unsigned int);
	const unsigned int n = (BYTES_TO_COMPARE / di) * di;
	const int sizeofchar = sizeof(char);

	unsigned int hashcode = *(unsigned int*)(bytes2compare + sizeofchar);

	for (int i = 1 + di; i < n; i += di) {
		hashcode ^= *(unsigned int*)(bytes2compare + i * sizeofchar);
	}

	return hashcode % vcpp->base.vc_npatterns;
}

static int
bruteforce_context_add_patterns(vg_context_t* vcp,
	const char** const patterns, int npatterns)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;

#ifdef VERBOSE
	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, "Adding %i patterns...", npatterns);
	}
#endif
	vcpp->base.vc_npatterns = npatterns;

	std::vector<std::array<char, BYTES_TO_COMPARE>> def;
	vcpp->hashmap.resize(npatterns, def);

	unsigned int max_hashcode = 0;

	for (int i = 0; i < npatterns; i++) {
		const char* encoded = patterns[i];

#ifdef VERBOSE
		if (vcpp->base.vc_verbose > 1) {
			fprintf(stderr, "\nprocessing %i: %s", i, encoded);
		}
#endif

		char decoded[ADR_LENGTH];
		int check = vg_b58_decode_check(encoded, decoded, ADR_LENGTH);
		std::array<char, BYTES_TO_COMPARE> bytes2compare{};
		memcpy(bytes2compare.data(), decoded, BYTES_TO_COMPARE);

		int hashcode = calculate_hash(bytes2compare.data(), vcpp);
		max_hashcode = max(max_hashcode, hashcode);

		vcpp->hashmap.at(hashcode).push_back(bytes2compare);

#ifdef VERBOSE
		if (vcpp->base.vc_verbose > 1) {
			fprintf(stderr, " -> ");
			char hex[BYTES_TO_COMPARE * 3]{};
			size_t hexsz = BYTES_TO_COMPARE * 3;
			hex_enc(hex, &hexsz, bytes2compare.data(), BYTES_TO_COMPARE);
			fprintf(stderr, "%s", hex);
			fprintf(stderr, "\n\thashcode: %i, collisions: %i", hashcode, vcpp->hashmap.at(hashcode).size() - 1);
		}
#endif
	}

#ifdef VERBOSE
	if (vcpp->base.vc_verbose > 1) {
		for (unsigned int i = 0; i < vcpp->hashmap.size(); i++) {
			fprintf(stderr, "\n--- Hashcode %u ---", i);
			for (std::array<char, BYTES_TO_COMPARE> bytes2compare : vcpp->hashmap.at(i)) {
				char hex[BYTES_TO_COMPARE * 3]{};
				size_t hexsz = BYTES_TO_COMPARE * 3;
				hex_enc(hex, &hexsz, bytes2compare.data(), BYTES_TO_COMPARE);
				fprintf(stderr, "\n%s", hex);
			}
		}
	}
#endif

	int empty = 0, max_collisions = 0;

	for (unsigned int i = 0; i < vcpp->hashmap.size(); i++) {
		if (vcpp->hashmap.at(i).empty()) empty++;
		max_collisions = max(max_collisions, vcpp->hashmap.at(i).size());
	}
	fprintf(stderr, "\nmax. hashcode: %u, empty: %i, max. collisions: %i - done!\n", max_hashcode, empty, max_collisions);

	return 1;
}

static void
bruteforce_context_clear_all_patterns(vg_context_t* vcp)
{
	/*
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vcp;
	if (vcpp->base.vc_verbose > 1) {
		fprintf(stderr, "Clearing all patterns...");
	}

	delete& vcpp->hashmap;
	*/
}


// return 0 (not found), 1 (found), 2 (not continue)
static int
bruteforce_test(vg_exec_context_t* vxcp)
{
	bruteforce_context_t* vcpp = (bruteforce_context_t*)vxcp->vxc_vc;
	int hashcode = calculate_hash((char*)vxcp->vxc_binres, vcpp);

research:
#ifdef VERBOSE
	if (vcpp->base.vc_verbose > 1) {
		char hex[BYTES_TO_COMPARE * 3]{};
		size_t hexsz = BYTES_TO_COMPARE * sizeof(char) * 3;
		hex_enc(hex, &hexsz, vxcp->vxc_binres, BYTES_TO_COMPARE * sizeof(char));
		fprintf(stderr, "\nCandidate: %s at %p hash %i", hex, vxcp->vxc_binres, hashcode);
	}
#endif

	boolean found = false;

	for (std::array<char, BYTES_TO_COMPARE> bytes2compare : vcpp->hashmap.at(hashcode)) {
#ifdef VERBOSE
		if (vcpp->base.vc_verbose > 1) {
			char hex[BYTES_TO_COMPARE * 3]{};
			size_t hexsz = BYTES_TO_COMPARE * 3;
			hex_enc(hex, &hexsz, bytes2compare.data(), BYTES_TO_COMPARE);
			fprintf(stderr, "\n\ttrying %s", hex);
		}
#endif

		if (!memcmp(vxcp->vxc_binres, bytes2compare.data(), BYTES_TO_COMPARE)) {
			found = true;
			break;
		}

		if (found) break;
	}

	if (!found) {
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
	bruteforce_context_t* vcpp = new bruteforce_context_t();

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

	return &vcpp->base;
}