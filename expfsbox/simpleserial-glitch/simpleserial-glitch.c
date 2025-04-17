/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2020 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"


#include "simpleserial.h"


#include "common.h"
#include "aes.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Forward S-box & tables
 */
MBEDTLS_MAYBE_UNUSED static unsigned char FSb[256];
MBEDTLS_MAYBE_UNUSED static uint32_t FT0[256];
MBEDTLS_MAYBE_UNUSED static uint32_t FT1[256];
MBEDTLS_MAYBE_UNUSED static uint32_t FT2[256];
MBEDTLS_MAYBE_UNUSED static uint32_t FT3[256];

/*
 * Reverse S-box & tables
 */
MBEDTLS_MAYBE_UNUSED static unsigned char RSb[256];

MBEDTLS_MAYBE_UNUSED static uint32_t RT0[256];
MBEDTLS_MAYBE_UNUSED static uint32_t RT1[256];
MBEDTLS_MAYBE_UNUSED static uint32_t RT2[256];
MBEDTLS_MAYBE_UNUSED static uint32_t RT3[256];

/*
 * Round constants
 */
MBEDTLS_MAYBE_UNUSED static uint32_t round_constants[10];

/*
 * Tables generation code
 */
#define ROTL8(x) (((x) << 8) & 0xFFFFFFFF) | ((x) >> 24)
#define XTIME(x) (((x) << 1) ^ (((x) & 0x80) ? 0x1B : 0x00))
#define MUL(x, y) (((x) && (y)) ? pow[(log[(x)]+log[(y)]) % 255] : 0)

MBEDTLS_MAYBE_UNUSED static int aes_init_done = 0;

MBEDTLS_MAYBE_UNUSED static void aes_gen_tables(void)
{
    int i;
    uint8_t x, y, z;
    uint8_t pow[256];
    uint8_t log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for (i = 0, x = 1; i < 256; i++) {
        pow[i] = x;
        log[x] = (uint8_t) i;
        x ^= XTIME(x);       
    }

    /*
     * calculate the round constants
     */
    for (i = 0, x = 1; i < 10; i++) {
        round_constants[i] = x;
        x = XTIME(x);
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
#if defined(MBEDTLS_AES_NEED_REVERSE_TABLES)
    RSb[0x63] = 0x00;
#endif
    trigger_high();
    for (i = 1; i < 256; i++) {
        x = pow[255 - log[i]];

        y  = x; y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y; y = (y << 1) | (y >> 7);
        x ^= y ^ 0x63;

        FSb[i] = x;
#if defined(MBEDTLS_AES_NEED_REVERSE_TABLES)
        RSb[x] = (unsigned char) i;
#endif
    }
    trigger_low();

    /*
     * generate the forward and reverse tables
     */
    for (i = 0; i < 256; i++) {
        x = FSb[i];
        y = XTIME(x);
        z = y ^ x;

        FT0[i] = ((uint32_t) y) ^
                 ((uint32_t) x <<  8) ^
                 ((uint32_t) x << 16) ^
                 ((uint32_t) z << 24);

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        FT1[i] = ROTL8(FT0[i]);
        FT2[i] = ROTL8(FT1[i]);
        FT3[i] = ROTL8(FT2[i]);
#endif /* !MBEDTLS_AES_FEWER_TABLES */

#if defined(MBEDTLS_AES_NEED_REVERSE_TABLES)
        x = RSb[i];

        RT0[i] = ((uint32_t) MUL(0x0E, x)) ^
                 ((uint32_t) MUL(0x09, x) <<  8) ^
                 ((uint32_t) MUL(0x0D, x) << 16) ^
                 ((uint32_t) MUL(0x0B, x) << 24);

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        RT1[i] = ROTL8(RT0[i]);
        RT2[i] = ROTL8(RT1[i]);
        RT3[i] = ROTL8(RT2[i]);
#endif /* !MBEDTLS_AES_FEWER_TABLES */
#endif /* MBEDTLS_AES_NEED_REVERSE_TABLES */
    }
}

#undef ROTL8

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) RT1[idx]
#define AES_RT2(idx) RT2[idx]
#define AES_RT3(idx) RT3[idx]

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]

unsigned mbedtls_aes_rk_offset(uint32_t *buf)
{
    (void) buf;
    return 0;
}

/*
 * AES key schedule (encryption)
 */
uint8_t n_gencalls = 0;
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    uint32_t *RK;

    switch (keybits) {
        case 128: ctx->nr = 10; break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    if (aes_init_done == 0) {
        n_gencalls++;
        aes_gen_tables();
        aes_init_done = 1;
    }

    ctx->rk_offset = mbedtls_aes_rk_offset(ctx->buf);
    RK = ctx->buf + ctx->rk_offset;

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
    for (unsigned int i = 0; i < (keybits >> 5); i++) {
        RK[i] = MBEDTLS_GET_UINT32_LE(key, i << 2);
    }

    switch (ctx->nr) {
        case 10:

            for (unsigned int i = 0; i < 10; i++, RK += 4) {
                RK[4]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[3])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[3])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[3])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[3])] << 24);

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 12:

            for (unsigned int i = 0; i < 8; i++, RK += 6) {
                RK[6]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[5])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[5])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[5])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[5])] << 24);

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for (unsigned int i = 0; i < 7; i++, RK += 8) {
                RK[8]  = RK[0] ^ round_constants[i] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[7])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[7])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[7])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[7])] << 24);

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_0(RK[11])]) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_1(RK[11])] <<  8) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_2(RK[11])] << 16) ^
                         ((uint32_t) FSb[MBEDTLS_BYTE_3(RK[11])] << 24);

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
#endif /* !MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH */
    }

    return 0;
#endif /* !MBEDTLS_AES_USE_HARDWARE_ONLY */
}

static void *(*const volatile memset_func)(void *, int, size_t) = memset;

void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_aes_context));
}

void mbedtls_aes_free(mbedtls_aes_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_aes_context));
}

void mbedtls_platform_zeroize(void *buf, size_t len)
{
    if (len > 0) {
        memset_func(buf, 0, len);
#if defined(__GNUC__)
        /* For clang and recent gcc, pretend that we have some assembly that reads the
         * zero'd memory as an additional protection against being optimised away. */
#if defined(__clang__) || (__GNUC__ >= 10)
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvla"
#elif defined(MBEDTLS_COMPILER_IS_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
#endif
        asm volatile ("" : : "m" (*(char (*)[len]) buf) :);
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(MBEDTLS_COMPILER_IS_GCC)
#pragma GCC diagnostic pop
#endif
#endif
#endif
    }
}

/*
 * AES key schedule (decryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_DEC_ALT) && !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
    uint32_t *SK;
#endif
    int ret;
    mbedtls_aes_context cty;
    uint32_t *RK;


    mbedtls_aes_init(&cty);

    ctx->rk_offset = mbedtls_aes_rk_offset(ctx->buf);
    RK = ctx->buf + ctx->rk_offset;

    /* Also checks keybits */
    if ((ret = mbedtls_aes_setkey_enc(&cty, key, keybits)) != 0) {
        goto exit;
    }

    ctx->nr = cty.nr;

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
    SK = cty.buf + cty.rk_offset + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    SK -= 8;
    for (int i = ctx->nr - 1; i > 0; i--, SK -= 8) {
        for (int j = 0; j < 4; j++, SK++) {
            *RK++ = AES_RT0(FSb[MBEDTLS_BYTE_0(*SK)]) ^
                    AES_RT1(FSb[MBEDTLS_BYTE_1(*SK)]) ^
                    AES_RT2(FSb[MBEDTLS_BYTE_2(*SK)]) ^
                    AES_RT3(FSb[MBEDTLS_BYTE_3(*SK)]);
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
#endif /* !MBEDTLS_AES_USE_HARDWARE_ONLY */
exit:
    mbedtls_aes_free(&cty);

    return ret;
}
#endif /* !MBEDTLS_AES_SETKEY_DEC_ALT && !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

#define AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3)                 \
    do                                                      \
    {                                                       \
        (X0) = *RK++ ^ AES_FT0(MBEDTLS_BYTE_0(Y0)) ^    \
               AES_FT1(MBEDTLS_BYTE_1(Y1)) ^    \
               AES_FT2(MBEDTLS_BYTE_2(Y2)) ^    \
               AES_FT3(MBEDTLS_BYTE_3(Y3));     \
                                                            \
        (X1) = *RK++ ^ AES_FT0(MBEDTLS_BYTE_0(Y1)) ^    \
               AES_FT1(MBEDTLS_BYTE_1(Y2)) ^    \
               AES_FT2(MBEDTLS_BYTE_2(Y3)) ^    \
               AES_FT3(MBEDTLS_BYTE_3(Y0));     \
                                                            \
        (X2) = *RK++ ^ AES_FT0(MBEDTLS_BYTE_0(Y2)) ^    \
               AES_FT1(MBEDTLS_BYTE_1(Y3)) ^    \
               AES_FT2(MBEDTLS_BYTE_2(Y0)) ^    \
               AES_FT3(MBEDTLS_BYTE_3(Y1));     \
                                                            \
        (X3) = *RK++ ^ AES_FT0(MBEDTLS_BYTE_0(Y3)) ^    \
               AES_FT1(MBEDTLS_BYTE_1(Y0)) ^    \
               AES_FT2(MBEDTLS_BYTE_2(Y1)) ^    \
               AES_FT3(MBEDTLS_BYTE_3(Y2));     \
    } while (0)

#define AES_RROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3)                 \
    do                                                      \
    {                                                       \
        (X0) = *RK++ ^ AES_RT0(MBEDTLS_BYTE_0(Y0)) ^    \
               AES_RT1(MBEDTLS_BYTE_1(Y3)) ^    \
               AES_RT2(MBEDTLS_BYTE_2(Y2)) ^    \
               AES_RT3(MBEDTLS_BYTE_3(Y1));     \
                                                            \
        (X1) = *RK++ ^ AES_RT0(MBEDTLS_BYTE_0(Y1)) ^    \
               AES_RT1(MBEDTLS_BYTE_1(Y0)) ^    \
               AES_RT2(MBEDTLS_BYTE_2(Y3)) ^    \
               AES_RT3(MBEDTLS_BYTE_3(Y2));     \
                                                            \
        (X2) = *RK++ ^ AES_RT0(MBEDTLS_BYTE_0(Y2)) ^    \
               AES_RT1(MBEDTLS_BYTE_1(Y1)) ^    \
               AES_RT2(MBEDTLS_BYTE_2(Y0)) ^    \
               AES_RT3(MBEDTLS_BYTE_3(Y3));     \
                                                            \
        (X3) = *RK++ ^ AES_RT0(MBEDTLS_BYTE_0(Y3)) ^    \
               AES_RT1(MBEDTLS_BYTE_1(Y2)) ^    \
               AES_RT2(MBEDTLS_BYTE_2(Y1)) ^    \
               AES_RT3(MBEDTLS_BYTE_3(Y0));     \
    } while (0)

/*
 * AES-ECB block encryption
 */
#if !defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    int i;
    uint32_t *RK = ctx->buf + ctx->rk_offset;
    struct {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    t.X[0] = MBEDTLS_GET_UINT32_LE(input,  0); t.X[0] ^= *RK++;
    t.X[1] = MBEDTLS_GET_UINT32_LE(input,  4); t.X[1] ^= *RK++;
    t.X[2] = MBEDTLS_GET_UINT32_LE(input,  8); t.X[2] ^= *RK++;
    t.X[3] = MBEDTLS_GET_UINT32_LE(input, 12); t.X[3] ^= *RK++;

    for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
        AES_FROUND(t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3]);
        AES_FROUND(t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3]);
    }

    AES_FROUND(t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3]);

    t.X[0] = *RK++ ^ \
             ((uint32_t) FSb[MBEDTLS_BYTE_0(t.Y[0])]) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_1(t.Y[1])] <<  8) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_2(t.Y[2])] << 16) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_3(t.Y[3])] << 24);

    t.X[1] = *RK++ ^ \
             ((uint32_t) FSb[MBEDTLS_BYTE_0(t.Y[1])]) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_1(t.Y[2])] <<  8) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_2(t.Y[3])] << 16) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_3(t.Y[0])] << 24);

    t.X[2] = *RK++ ^ \
             ((uint32_t) FSb[MBEDTLS_BYTE_0(t.Y[2])]) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_1(t.Y[3])] <<  8) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_2(t.Y[0])] << 16) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_3(t.Y[1])] << 24);

    t.X[3] = *RK++ ^ \
             ((uint32_t) FSb[MBEDTLS_BYTE_0(t.Y[3])]) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_1(t.Y[0])] <<  8) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_2(t.Y[1])] << 16) ^
             ((uint32_t) FSb[MBEDTLS_BYTE_3(t.Y[2])] << 24);

    MBEDTLS_PUT_UINT32_LE(t.X[0], output,  0);
    MBEDTLS_PUT_UINT32_LE(t.X[1], output,  4);
    MBEDTLS_PUT_UINT32_LE(t.X[2], output,  8);
    MBEDTLS_PUT_UINT32_LE(t.X[3], output, 12);

    mbedtls_platform_zeroize(&t, sizeof(t));

    return 0;
}
#endif /* !MBEDTLS_AES_ENCRYPT_ALT */

/*
 * AES-ECB block decryption
 */
#if !defined(MBEDTLS_AES_DECRYPT_ALT) && !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    int i;
    uint32_t *RK = ctx->buf + ctx->rk_offset;
    struct {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    t.X[0] = MBEDTLS_GET_UINT32_LE(input,  0); t.X[0] ^= *RK++;
    t.X[1] = MBEDTLS_GET_UINT32_LE(input,  4); t.X[1] ^= *RK++;
    t.X[2] = MBEDTLS_GET_UINT32_LE(input,  8); t.X[2] ^= *RK++;
    t.X[3] = MBEDTLS_GET_UINT32_LE(input, 12); t.X[3] ^= *RK++;

    for (i = (ctx->nr >> 1) - 1; i > 0; i--) {
        AES_RROUND(t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3]);
        AES_RROUND(t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3]);
    }

    AES_RROUND(t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3]);

    t.X[0] = *RK++ ^ \
             ((uint32_t) RSb[MBEDTLS_BYTE_0(t.Y[0])]) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_1(t.Y[3])] <<  8) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_2(t.Y[2])] << 16) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_3(t.Y[1])] << 24);

    t.X[1] = *RK++ ^ \
             ((uint32_t) RSb[MBEDTLS_BYTE_0(t.Y[1])]) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_1(t.Y[0])] <<  8) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_2(t.Y[3])] << 16) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_3(t.Y[2])] << 24);

    t.X[2] = *RK++ ^ \
             ((uint32_t) RSb[MBEDTLS_BYTE_0(t.Y[2])]) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_1(t.Y[1])] <<  8) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_2(t.Y[0])] << 16) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_3(t.Y[3])] << 24);

    t.X[3] = *RK++ ^ \
             ((uint32_t) RSb[MBEDTLS_BYTE_0(t.Y[3])]) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_1(t.Y[2])] <<  8) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_2(t.Y[1])] << 16) ^
             ((uint32_t) RSb[MBEDTLS_BYTE_3(t.Y[0])] << 24);

    MBEDTLS_PUT_UINT32_LE(t.X[0], output,  0);
    MBEDTLS_PUT_UINT32_LE(t.X[1], output,  4);
    MBEDTLS_PUT_UINT32_LE(t.X[2], output,  8);
    MBEDTLS_PUT_UINT32_LE(t.X[3], output, 12);

    mbedtls_platform_zeroize(&t, sizeof(t));

    return 0;
}
#endif /* !MBEDTLS_AES_DECRYPT_ALT && !MBEDTLS_BLOCK_CIPHER_NO_DECRYPT */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16])
{
    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }
   
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        return mbedtls_internal_aes_decrypt(ctx, input, output);
    } else
#endif
    {
        return mbedtls_internal_aes_encrypt(ctx, input, output);
    }
#endif /* !MBEDTLS_AES_USE_HARDWARE_ONLY */
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)

/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    int ret;
    unsigned char temp[16];

    if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT) {
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    }

    /* Nothing to do if length is zero. */
    if (length == 0) {
        return 0;
    }

    if (length % 16) {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    const unsigned char *ivp = iv;

    if (mode == MBEDTLS_AES_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 16);
            ret = mbedtls_aes_crypt_ecb(ctx, mode, input, output);
            if (ret != 0) {
                goto exit;
            }
            /* Avoid using the NEON implementation of mbedtls_xor. Because of the dependency on
             * the result for the next block in CBC, and the cost of transferring that data from
             * NEON registers, NEON is slower on aarch64. */
            mbedtls_xor_no_simd(output, output, iv, 16);

            memcpy(iv, temp, 16);

            input  += 16;
            output += 16;
            length -= 16;
        }
    } else {
        while (length > 0) {
            mbedtls_xor_no_simd(output, input, ivp, 16);

            ret = mbedtls_aes_crypt_ecb(ctx, mode, output, output);
            if (ret != 0) {
                goto exit;
            }
            ivp = output;

            input  += 16;
            output += 16;
            length -= 16;
        }
        memcpy(iv, ivp, 16);
    }
    ret = 0;

exit:
    return ret;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */


/*
 * Inject fault and encrypt 
 */
unsigned char key[16] = {0x5b, 0x12, 0xa4, 0x7f, 0x2b, 0x55, 0x71, 0x19, 
    0x1e, 0xc0, 0x6d, 0x7c, 0x02, 0xfc, 0x60, 0x76};
mbedtls_aes_context ctx;
static int aes_ctx_done = 0;

uint8_t fault_and_encrypt(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t* indata){

    if (aes_ctx_done == 0){
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_enc(&ctx, key, 128);
        aes_ctx_done = 1;        
    }

    int ret = 0, mode=MBEDTLS_AES_ENCRYPT;
    unsigned char buf[16];

    for (int i = 0; i < 16; i++){
        buf[i] = indata[i];
    }

    ret = mbedtls_aes_crypt_ecb(&ctx, mode, buf, buf);
    if (ret != 0) {
        printf("[FAILED] ECB encryption!\n");
        return ret;
    }
    simpleserial_put('r', 16, buf);
    return 0;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Device reset detected */
    putch('r');
    putch('R');
    putch('E');
    putch('S');
    putch('E');
    putch('T');
    putch(' ');
    putch(' ');
    putch(' ');
    putch('\n');

    simpleserial_init();
    simpleserial_addcmd('a', 16, fault_and_encrypt);  

    while(1)
        simpleserial_get();
}
