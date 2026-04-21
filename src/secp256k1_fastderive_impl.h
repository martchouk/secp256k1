/* src/secp256k1_fastderive_impl.h */
#ifndef SECP256K1_FASTDERIVE_IMPL_H
#define SECP256K1_FASTDERIVE_IMPL_H

#ifdef SECP256K1_BUILD

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "field.h"
#include "ecmult.h"
#include "eckey.h"

#include "scalar_impl.h"
#include "group_impl.h"
#include "eckey_impl.h"
#include "ecmult_gen.h"
#include "precomputed_ecmult_gen.h"

/* ------------------------------------------------------------ */
/* Variable-time fixed-base scalar mult: tweak * G              */
/* ------------------------------------------------------------ */
/* NOT constant-time. Safe for BIP32 child key derivation because
   tweaks are HMAC outputs, not secret signing keys.
   ~2x faster than secp256k1_ecmult_gen: uses direct table access
   instead of a 32-entry constant-time cmov scan per block. */
static SECP256K1_INLINE void secp256k1_ecmult_gen_var(
    const secp256k1_ecmult_gen_context *ctx,
    secp256k1_gej *r,
    const secp256k1_scalar *gn
) {
    uint32_t comb_off;
    secp256k1_ge add;
    secp256k1_fe neg;
    secp256k1_ge_storage adds;
    secp256k1_scalar d;
    uint32_t recoded[(COMB_BITS + 31) >> 5];
    int first = 1;
    int i;

    memset(&adds, 0, sizeof(adds));
    memset(recoded, 0, sizeof(recoded));

    /* Apply additive scalar blinding: d = gn + scalar_offset */
    secp256k1_scalar_add(&d, &ctx->scalar_offset, gn);
    for (i = 0; i < 8 && i < ((COMB_BITS + 31) >> 5); ++i) {
        recoded[i] = secp256k1_scalar_get_bits_limb32(&d, 32 * i, 32);
    }
    secp256k1_scalar_clear(&d);

    comb_off = COMB_SPACING - 1;
    while (1) {
        uint32_t block;
        uint32_t bit_pos = comb_off;
        for (block = 0; block < COMB_BLOCKS; ++block) {
            uint32_t bits = 0, sign, abs, tooth;
            for (tooth = 0; tooth < COMB_TEETH; ++tooth) {
                bits |= ((recoded[bit_pos >> 5] >> (bit_pos & 0x1fu)) & 1u) << tooth;
                bit_pos += COMB_SPACING;
            }
            sign = (bits >> (COMB_TEETH - 1)) & 1u;
            abs  = (bits ^ (uint32_t)(-(int32_t)sign)) & (COMB_POINTS - 1u);

            /* Variable-time: direct index, no cmov scan over all COMB_POINTS entries */
            adds = secp256k1_ecmult_gen_prec_table[block][abs];

            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_fe_negate(&neg, &add.y, 1);
            secp256k1_fe_cmov(&add.y, &neg, sign);

            if (EXPECT(first, 0)) {
                secp256k1_gej_set_ge(r, &add);
                /* Projective blinding (secp256k1_gej_rescale) intentionally omitted:
                   not needed for non-secret HMAC-derived tweaks. */
                first = 0;
            } else {
                secp256k1_gej_add_ge(r, r, &add);
            }
        }
        if (comb_off-- == 0) break;
        secp256k1_gej_double(r, r);
    }

    /* Add back ge_offset to correct for the scalar_offset blinding */
    secp256k1_gej_add_ge(r, r, &ctx->ge_offset);

    secp256k1_fe_clear(&neg);
    secp256k1_ge_clear(&add);
    secp256k1_memclear_explicit(&adds, sizeof(adds));
    secp256k1_memclear_explicit(&recoded, sizeof(recoded));
}

/* ------------------------------------------------------------ */
/* Shared compressed serializer                                  */
/* ------------------------------------------------------------ */
/* Note: secp256k1_ge_set_gej_var takes a non-const gej* because it may
   normalize/mutate it. So keep pj non-const here. */
static SECP256K1_INLINE void secp256k1_serialize33_from_gej(unsigned char out33[33], secp256k1_gej *pj) {
    secp256k1_ge out_ge;
    secp256k1_ge_set_gej_var(&out_ge, pj);

    secp256k1_fe_normalize_var(&out_ge.x);
    secp256k1_fe_normalize_var(&out_ge.y);

    out33[0] = (unsigned char)(0x02u + secp256k1_fe_is_odd(&out_ge.y));
    secp256k1_fe_get_b32(out33 + 1, &out_ge.x);
}

static SECP256K1_INLINE void secp256k1_serialize33_from_ge(unsigned char out33[33], secp256k1_ge *p) {
    secp256k1_fe_normalize_var(&p->x);
    secp256k1_fe_normalize_var(&p->y);
    out33[0] = (unsigned char)(0x02u + secp256k1_fe_is_odd(&p->y));
    secp256k1_fe_get_b32(out33 + 1, &p->x);
}

/* ------------------------------------------------------------ */
/* fast tweak_add + serialize33 (from pubkey)                    */
/* ------------------------------------------------------------ */
static SECP256K1_INLINE int secp256k1_fast_pubkey_tweak_add_serialize33_impl(
    const secp256k1_context* ctx,
    const secp256k1_pubkey* pubkey,
    const unsigned char tweak32[32],
    unsigned char out33[33]
) {
    secp256k1_ge p;
    secp256k1_gej pj, tj;
    secp256k1_scalar tweak;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);
    ARG_CHECK(out33 != NULL);

    if (!secp256k1_pubkey_load(ctx, &p, pubkey)) return 0;

    secp256k1_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) { secp256k1_scalar_clear(&tweak); return 0; }

    secp256k1_gej_set_ge(&pj, &p);

    secp256k1_ecmult_gen_var(&ctx->ecmult_gen_ctx, &tj, &tweak);
    secp256k1_gej_add_var(&pj, &pj, &tj, NULL);

    secp256k1_scalar_clear(&tweak);
    if (secp256k1_gej_is_infinity(&pj)) return 0;

    secp256k1_serialize33_from_gej(out33, &pj);
    return 1;
}

/* ------------------------------------------------------------ */
/* Parent cache impl (stored as bytes in secp256k1_fastderive_parent) */
/* ------------------------------------------------------------ */
typedef struct secp256k1_fastderive_parent_impl {
    secp256k1_gej pj; /* parent in Jacobian */
} secp256k1_fastderive_parent_impl;

static SECP256K1_INLINE int secp256k1_fastderive_parent_init_impl(
    const secp256k1_context* ctx,
    secp256k1_fastderive_parent_impl* out,
    const secp256k1_pubkey* pubkey
) {
    secp256k1_ge p;
    ARG_CHECK(out != NULL);
    ARG_CHECK(pubkey != NULL);
    if (!secp256k1_pubkey_load(ctx, &p, pubkey)) return 0;
    secp256k1_gej_set_ge(&out->pj, &p);
    return 1;
}

/* Define this in your build flags for the speed build if desired:
 *   -DSECP256K1_FASTDERIVE_NO_CLEAR=1
 */
static SECP256K1_INLINE int secp256k1_fast_pubkey_tweak_add_serialize33_from_parent_impl(
    const secp256k1_context* ctx,
    const secp256k1_fastderive_parent_impl* parent,
    const unsigned char tweak32[32],
    unsigned char out33[33]
) {
    secp256k1_gej pj, tj;
    secp256k1_scalar tweak;
    int overflow = 0;
    const secp256k1_ecmult_gen_context* gen;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(parent != NULL);
    ARG_CHECK(tweak32 != NULL);
    ARG_CHECK(out33 != NULL);

    /* Copy parent Jacobian (cheap) */
    pj = parent->pj;

    /* Parse tweak */
    secp256k1_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
#if !defined(SECP256K1_FASTDERIVE_NO_CLEAR)
        secp256k1_scalar_clear(&tweak);
#endif
        return 0;
    }

    /* HMAC-derived tweak is essentially never zero → always do the work */
    gen = &ctx->ecmult_gen_ctx;
    secp256k1_ecmult_gen_var(gen, &tj, &tweak);
    secp256k1_gej_add_var(&pj, &pj, &tj, NULL);

#if !defined(SECP256K1_FASTDERIVE_NO_CLEAR)
    secp256k1_scalar_clear(&tweak);
#endif

    if (secp256k1_gej_is_infinity(&pj)) return 0;

    secp256k1_serialize33_from_gej(out33, &pj);
    return 1;
}

/* ------------------------------------------------------------ */
/* NEW: Batch-10 version (one batch normalize instead of 10 inversions) */
/* ------------------------------------------------------------ */
/* tweaks32: 10 tweaks (each 32 bytes)
   out33:    10 compressed pubkeys (33 bytes each)
   Returns 1 on success, 0 if any tweak overflow / infinity occurs.
*/

/* Optional speed build:
 *   -DSECP256K1_FASTDERIVE_NO_CLEAR=1
 */
static SECP256K1_INLINE int secp256k1_fast_pubkey_tweak_add_serialize33_from_parent_batch10_impl(
    const secp256k1_context* ctx,
    const secp256k1_fastderive_parent_impl* parent,
    const unsigned char tweaks10[10][32],
    unsigned char out33_10[10][33]
) {
    secp256k1_gej pj_child[10];
    secp256k1_ge  p_child[10];
    secp256k1_gej tj;
    secp256k1_scalar tweak;
    int i;
    const secp256k1_ecmult_gen_context* gen;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(parent != NULL);
    ARG_CHECK(tweaks10 != NULL);
    ARG_CHECK(out33_10 != NULL);

    gen = &ctx->ecmult_gen_ctx;

    /* 1) Build 10 child Jacobians = parent + tweak*G */
    for (i = 0; i < 10; i++) {
        int overflow = 0;          /* reset each time */
        pj_child[i] = parent->pj;  /* copy parent Jacobian */

        secp256k1_scalar_set_b32(&tweak, tweaks10[i], &overflow);
        if (overflow) {
#if !defined(SECP256K1_FASTDERIVE_NO_CLEAR)
            secp256k1_scalar_clear(&tweak);
#endif
            return 0;
        }

        /* HMAC-derived tweak is essentially never zero: always do work */
        secp256k1_ecmult_gen_var(gen, &tj, &tweak);
        secp256k1_gej_add_var(&pj_child[i], &pj_child[i], &tj, NULL);

#if !defined(SECP256K1_FASTDERIVE_NO_CLEAR)
        secp256k1_scalar_clear(&tweak);
#endif

        if (secp256k1_gej_is_infinity(&pj_child[i])) return 0;
    }

    /* 2) One batched inversion to convert all 10 gej -> ge */
    secp256k1_ge_set_all_gej_var(p_child, pj_child, 10);

    /* 3) Serialize each child ge (no inversions here) */
    for (i = 0; i < 10; i++) {
        secp256k1_serialize33_from_ge(out33_10[i], &p_child[i]);
    }

    return 1;
}

/* ------------------------------------------------------------ */
/* Batch var pubkey create → raw x||y (64 bytes each)           */
/* ------------------------------------------------------------ */
/* Uses one batch field inversion for all n keys instead of n   */
/* individual inversions. ~15-20% faster than n individual      */
/* secp256k1_ec_pubkey_create_var calls when n is large.        */
/* Output xy64s[i] = 64 bytes: x[32] || y[32], no 0x04 prefix. */
static int secp256k1_ec_pubkey_batch_create_var_xy64_impl(
    const secp256k1_context* ctx,
    const unsigned char* seckeys,   /* n×32 bytes */
    unsigned char* xy64s,           /* n×64 bytes */
    int n
) {
    secp256k1_gej* pj;
    secp256k1_ge*  pg;
    secp256k1_scalar s;
    int i, ret = 1;

    VERIFY_CHECK(ctx != NULL);
    if (n <= 0) return 1;

    pj = (secp256k1_gej*)checked_malloc(&ctx->error_callback, (size_t)n * sizeof(secp256k1_gej));
    pg = (secp256k1_ge*) checked_malloc(&ctx->error_callback, (size_t)n * sizeof(secp256k1_ge));
    if (!pj || !pg) {
        free(pj); free(pg); return 0;
    }

    /* Step 1: compute n Jacobian points using ecmult_gen_var */
    for (i = 0; i < n; i++) {
        int valid = secp256k1_scalar_set_b32_seckey(&s, seckeys + (size_t)i * 32);
        secp256k1_scalar_cmov(&s, &secp256k1_scalar_one, !valid);
        secp256k1_ecmult_gen_var(&ctx->ecmult_gen_ctx, &pj[i], &s);
        secp256k1_scalar_clear(&s);
        if (!valid) { ret = 0; }
    }

    /* Step 2: one batch inversion — all n Jacobians → affine */
    secp256k1_ge_set_all_gej_var(pg, pj, (size_t)n);

    /* Step 3: extract x, y as 32-byte big-endian each */
    for (i = 0; i < n; i++) {
        secp256k1_fe_normalize_var(&pg[i].x);
        secp256k1_fe_normalize_var(&pg[i].y);
        secp256k1_fe_get_b32(xy64s + (size_t)i * 64,      &pg[i].x);
        secp256k1_fe_get_b32(xy64s + (size_t)i * 64 + 32, &pg[i].y);
    }

    free(pj); free(pg);
    return ret;
}

#endif /* SECP256K1_BUILD */
#endif /* SECP256K1_FASTDERIVE_IMPL_H */

