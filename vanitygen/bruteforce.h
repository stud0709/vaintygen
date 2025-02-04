#pragma once
#pragma once
#include <stdio.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "pattern.h"

/* Prefix context methods */
extern vg_context_t* bruteforce_context_new(int addrtype, int privtype);