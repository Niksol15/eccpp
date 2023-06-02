#ifndef INTERNAL_H
#define INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "private/quirks.h"

/*
 fe means field element.
 Here the field is \Z/(2^255-19).
 */

typedef uint64_t fe25519[5];

void fe25519_invert(fe25519 out, const fe25519 z);
void fe25519_frombytes(fe25519 h, const unsigned char *s);
void fe25519_tobytes(unsigned char *s, const fe25519 h);

# include "ed25519_ref10_fe_51.h"

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
} ge25519_p2;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p3;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p1p1;

typedef struct {
    fe25519 yplusx;
    fe25519 yminusx;
    fe25519 xy2d;
} ge25519_precomp;

typedef struct {
    fe25519 YplusX;
    fe25519 YminusX;
    fe25519 Z;
    fe25519 T2d;
} ge25519_cached;

void ge25519_tobytes(unsigned char *s, const ge25519_p2 *h);

void ge25519_p3_tobytes(unsigned char *s, const ge25519_p3 *h);

int ge25519_frombytes(ge25519_p3 *h, const unsigned char *s);

int ge25519_frombytes_negate_vartime(ge25519_p3 *h, const unsigned char *s);

void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p);

void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p);

void ge25519_p2_to_p3(ge25519_p3 *r, const ge25519_p2 *p);

void ge25519_p3_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q);

void ge25519_p3_sub(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q);

void ge25519_scalarmult_base(ge25519_p3 *h, const unsigned char *a);

void ge25519_double_scalarmult_vartime(ge25519_p2 *r, const unsigned char *a,
                                       const ge25519_p3 *A,
                                       const unsigned char *b);

void ge25519_scalarmult(ge25519_p3 *h, const unsigned char *a,
                        const ge25519_p3 *p);

void ge25519_clear_cofactor(ge25519_p3 *p3);

int ge25519_is_canonical(const unsigned char *s);

int ge25519_is_on_curve(const ge25519_p3 *p);

int ge25519_is_on_main_subgroup(const ge25519_p3 *p);

int ge25519_has_small_order(const ge25519_p3 *p);

void ge25519_from_uniform(unsigned char s[32], const unsigned char r[32]);

void ge25519_from_hash(unsigned char s[32], const unsigned char h[64]);

/*
 Ristretto group
 */

int ristretto255_frombytes(ge25519_p3 *h, const unsigned char *s);

void ristretto255_p3_tobytes(unsigned char *s, const ge25519_p3 *h);

void ristretto255_from_hash(unsigned char s[32], const unsigned char h[64]);

/*
 The set of scalars is \Z/l
 where l = 2^252 + 27742317777372353535851937790883648493.
 */

void sc25519_invert(unsigned char recip[32], const unsigned char s[32]);

void sc25519_reduce(unsigned char s[64]);

void sc25519_mul(unsigned char s[32], const unsigned char a[32],
                 const unsigned char b[32]);

void sc25519_muladd(unsigned char s[32], const unsigned char a[32],
                    const unsigned char b[32], const unsigned char c[32]);

int sc25519_is_canonical(const unsigned char s[32]);

#endif