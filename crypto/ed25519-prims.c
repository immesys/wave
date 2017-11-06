/*
	Public domain by Andrew M. <liquidsun@gmail.com>

	Ed25519 reference implementation using Ed25519-donna
*/


/* define ED25519_SUFFIX to have it appended to the end of each public function */
#if !defined(ED25519_SUFFIX)
#define ED25519_SUFFIX 
#endif

#define ED25519_FN3(fn,suffix) fn##suffix
#define ED25519_FN2(fn,suffix) ED25519_FN3(fn,suffix)
#define ED25519_FN(fn)         ED25519_FN2(fn,ED25519_SUFFIX)

#define STATIC

#include "ed25519-donna.h"
#include "ed25519.h"

