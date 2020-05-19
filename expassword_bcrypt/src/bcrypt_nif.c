/*	$OpenBSD: bcrypt.c,v 1.57 2016/08/26 08:25:02 guenther Exp $	*/

/*
 * Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* This password hashing algorithm was designed by David Mazieres
 * <dm@lcs.mit.edu> and works as follows:
 *
 * 1. state := InitState ()
 * 2. state := ExpandKey (state, salt, password)
 * 3. REPEAT rounds:
 *      state := ExpandKey (state, 0, password)
 *	state := ExpandKey (state, 0, salt)
 * 4. ctext := "OrpheanBeholderScryDoubt"
 * 5. REPEAT 64:
 * 	ctext := Encrypt_ECB (state, ctext);
 * 6. RETURN Concatenate (salt, ctext);
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <inttypes.h>

#include <erl_nif.h>

#include "blf.h"

#ifdef __GNUC__
# define GCC_VERSION (__GNUC__ * 1000 + __GNUC_MINOR__)
#else
# define GCC_VERSION 0
#endif /* __GNUC__ */

#ifndef __has_attribute
# define __has_attribute(x) 0
#endif /* !__has_attribute */

#ifndef __has_builtin
# define __has_builtin(x) 0
#endif /* !__has_builtin */

#if GCC_VERSION || __has_attribute(unused)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#else
# define UNUSED
#endif /* UNUSED */

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof((array)[0]))
#define STR_LEN(str) \
    (ARRAY_SIZE(str) - 1)
#define STR_SIZE(str) \
    (ARRAY_SIZE(str))

#define BCRYPT_MINOR 'b'
#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16	/* Precomputation is just so nice */
#define BCRYPT_WORDS 6		/* Ciphertext words */
#define BCRYPT_MINLOGROUNDS 4	/* we have log2(rounds) in salt */

#define	BCRYPT_SALTSPACE	(STR_LEN("$vm$cc$") + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1)
#define	BCRYPT_HASHSPACE	61

#define BCRYPT_PREFIX "$2*$"
#define BCRYPT_MAXLOGROUNDS 31

#ifndef STANDALONE
# define ATOM(x) \
    static ERL_NIF_TERM atom_##x;
# include "atoms.h"
# undef ATOM
#endif /* !STANDALONE */

/* <default values> */
#define DEFAULT_BCRYPT_COST 10
// #define DEFAULT_SALT_LENGTH 16
/* </default values> */

static const uint8_t Base64Code[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static const uint8_t index_64[] = {
    /*      0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F */
    /* 0 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 1 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 2 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
    /* 3 */ 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 4 */ 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    /* 5 */ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 6 */ 0xFF, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    /* 7 */ 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 8 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 9 */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* A */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* B */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* C */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* D */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* E */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* F */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static uint8_t *encode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    uint8_t c1, c2;
    uint8_t *w = buffer;
    const uint8_t *r = data;

    while (r < data_end) {
        c1 = *r++;
        *w++ = Base64Code[(c1 >> 2)];
        c1 = (c1 & 0x03) << 4;
        if (r >= data_end) {
            *w++ = Base64Code[c1];
            break;
        }
        c2 = *r++;
        c1 |= (c2 >> 4) & 0x0F;
        *w++ = Base64Code[c1];
        c1 = (c2 & 0x0F) << 2;
        if (r >= data_end) {
            *w++ = Base64Code[c1];
            break;
        }
        c2 = *r++;
        c1 |= (c2 >> 6) & 0x03;
        *w++ = Base64Code[c1];
        *w++ = Base64Code[c2 & 0x3F];
    }

    return w;
}

#ifndef STANDALONE
static
#endif /* !STANDALONE */
uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    uint8_t *w = buffer;
    const uint8_t *r = data;
#if 0
    uint8_t c1, c2, c3, c4;

    while (w < buffer_end) {
        c1 = index_64[r[0]];
        /* Invalid data */
        if (0xFF == c1) {
            return NULL;
        }
        c2 = index_64[r[1]];
        if (0xFF == c2) {
            return NULL;
        }
        *w++ = (c1 << 2) | ((c2 & 0x30) >> 4);
        if (w >= buffer_end) {
            break;
        }
        c3 = index_64[r[2]];
        if (0xFF == c3) {
            return NULL;
        }
        *w++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
        if (w >= buffer_end) {
            break;
        }
        c4 = index_64[r[3]];
        if (0xFF == c4) {
            return NULL;
        }
        *w++ = ((c3 & 0x03) << 6) | c4;
        r += 4;
    }
#else
    size_t i;
    uint8_t c;

    i = 0;
    while (r < data_end && w < buffer_end) {
        if (0xFF == (c = index_64[*r++])) {
            // invalid character found
            return NULL;
        }
        switch (i & 0b11) {
            case 0b00:
                *w = c << 2;
                break;
            case 0b01:
                *w++ |= c >> 4;
                *w = (c & 0x0F) << 4;
                break;
            case 0b10:
                *w++ |= c >> 2;
                *w = (c & 0x03) << 6;
                break;
            case 0b11:
                *w++ |= c;
                break;
        }
        i++;
    }
    if (r < data_end && w >= buffer_end) {
        // buffer is too small to fully convert data
        return NULL;
    }
#endif

    return w;
}

static uint8_t *write_prefix(uint8_t *buffer, const uint8_t * const buffer_end, int minor, int cost)
{
#if 1
    int written;

    written = snprintf((char *) buffer, buffer_end - buffer, "$%c%c$%2.2u$", BCRYPT_VERSION, minor, cost);
    if (written < 0 || ((size_t) written) >= ((size_t) (buffer_end - buffer))) {
        return NULL;
    } else {
        return buffer + written;
    }
#else
    if ((buffer_end - buffer_size) < STR_LEN("$vm$cc$")) {
        return NULL;
    }

    *buffer++ = '$';
    *buffer++ = BCRYPT_VERSION;
    *buffer++ = minor;
    *buffer++ = '$';
    *buffer++ = '0' + (cost / 10);
    *buffer++ = '0' + (cost % 10);
    *buffer++ = '$';

    return buffer;
#endif
}

static bool bcrypt_valid_hash(const ErlNifBinary *hash)
{
    return
           hash->size == (BCRYPT_HASHSPACE - 1)
        && '$' == hash->data[0]
        && BCRYPT_VERSION == hash->data[1]
        && ('a' == hash->data[2] || 'b' == hash->data[2] || 'y' == hash->data[2])
//         && '$' == hash->data[3]
    ;
}

#ifndef STANDALONE
static bool extract_options_from_erlang_map(ErlNifEnv *env, ERL_NIF_TERM map, int *cost)
{
    ERL_NIF_TERM value;

    if (enif_get_map_value(env, map, atom_cost, &value) && enif_get_int(env, value, cost)) {
        // ok
    } else {
        *cost = DEFAULT_BCRYPT_COST;
    }

    return *cost >= BCRYPT_MINLOGROUNDS && *cost <= BCRYPT_MAXLOGROUNDS;
}
#endif /* !STANDALONE */

#ifndef STANDALONE
static
#endif /* !STANDALONE */
uint8_t *bcrypt_init_salt(int cost, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    uint8_t *w;

#if 0
    if ((buffer_end - buffer) < BCRYPT_SALTSPACE) {
        return NULL;
    }
#endif
    if ((raw_salt_end - raw_salt) < BCRYPT_MAXSALT) {
        // salt is too short
        return NULL;
    }

    if (cost < BCRYPT_MINLOGROUNDS) {
        cost = BCRYPT_MINLOGROUNDS;
    } else if (cost > BCRYPT_MAXLOGROUNDS) {
        cost = BCRYPT_MAXLOGROUNDS;
    }

    if (NULL == (w = write_prefix(buffer, buffer_end, BCRYPT_MINOR, cost))) {
        return NULL;
    }
    if (NULL == (w = encode_base64(raw_salt, raw_salt + BCRYPT_MAXSALT, w, buffer_end))) {
        return NULL;
    }

    return w;
}

#ifndef STANDALONE
static
#endif /* !STANDALONE */
// salt here means prefix "$vm$cc$" + base64 encoded salt
// raw_salt is the real unencoded (base64) hash
uint8_t *bcrypt_full_parse_hash(const uint8_t *salt, const uint8_t *salt_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end)
{
    uint8_t *r, d1, d2;

    r = salt;
    if ((salt_end - salt) < BCRYPT_SALTSPACE) {
        return NULL;
    }
    if ('$' != *r++) {
        return NULL;
    }
    if (BCRYPT_VERSION != *r++) {
        return NULL;
    }
    *minor = *r++;
    if ('a' != *minor && 'b' != *minor && 'y' != *minor) {
        return NULL;
    }
    if ('$' != *r++) {
        return NULL;
    }
    if (!isdigit(d1 = *r++) || !isdigit(d2 = *r++)) {
        return NULL;
    }
    *cost = (d2 - '0') + ((d1 - '0') * 10);
    if (*cost < BCRYPT_MINLOGROUNDS || *cost > BCRYPT_MAXLOGROUNDS) {
        return NULL;
    }
    if ('$' != *r++) {
        return NULL;
    }
    if (NULL == (r = decode_base64(r, r + 22 /* TODO */, raw_salt, raw_salt_end))) {
        return NULL;
    }

    return r;
}

static bool bcrypt_parse_hash(const ErlNifBinary *hash, int *cost)
{
    // NOTE: length is checked before by a call to bcrypt_valid_hash
    unsigned const char * const r = hash->data + STR_LEN(BCRYPT_PREFIX);

    if (isdigit(r[0]) && isdigit(r[1])) {
        *cost = (r[1] - '0') + ((r[0] - '0') * 10);
    } else {
        *cost = 0;
    }

    return *cost >= BCRYPT_MINLOGROUNDS && *cost <= BCRYPT_MAXLOGROUNDS;
}

#ifndef STANDALONE
static
#endif /* !STANDALONE */
bool bcrypt_hash(
    // WARNING: password have to be null terminated and password_end should be located AFTER it!
    const uint8_t *password, const uint8_t * const password_end,
    // "salt" here means prefix "$vm$cc$" + base64 encoded salt
    const uint8_t *salt, const uint8_t * const salt_end,
    uint8_t *hash, const uint8_t * const hash_end
) {
    uint16_t j;
    blf_ctx state;
    int cost, minor;
    size_t password_len;
    uint32_t i, k, rounds, cdata[BCRYPT_WORDS];
    uint8_t *w, raw_salt[BCRYPT_MAXSALT], ciphertext[4 * BCRYPT_WORDS] = "OrpheanBeholderScryDoubt";
    const uint8_t * const raw_salt_end = raw_salt + STR_SIZE(raw_salt);

    if (!bcrypt_full_parse_hash(salt, salt_end, &minor, &cost, raw_salt, raw_salt_end)) {
        return false;
    }
    password_len = (password_end - password);
    if ('a' == minor) {
        password_len = (uint8_t) (password_len/* + 1*/); // TODO
    } else if ('b' == minor || 'y' == minor) {
        if (password_len > /*72*/73) {
            password_len = /*72*/73;
        }
//         password_len++; /* include the NUL */ // TODO
    } else {
        assert(false);
        return false;
    }
#if 0
    {
        const uint8_t *c;

        printf("PASSWORD : >%.*s< (%ld vs %zu)\n", (int) (password_end - password), password, password_end - password, password_len);
//         printf("SALT : >%.*s< (%ld)\n", (int) (raw_salt_end - raw_salt), raw_salt, raw_salt_end - raw_salt);
        for (c = raw_salt; c < raw_salt_end; c++) {
            printf("0x%02" PRIX8, *c);
        }
        printf("\n");
    }
#endif

    rounds = UINT32_C(1) << cost;
    Blowfish_initstate(&state);
    Blowfish_expandstate(&state, raw_salt, BCRYPT_MAXSALT, password, password_len);
    for (k = 0; k < rounds; k++) {
        Blowfish_expand0state(&state, password, password_len);
        Blowfish_expand0state(&state, raw_salt, BCRYPT_MAXSALT);
    }

    /* This can be precomputed later */
    j = 0;
    for (i = 0; i < BCRYPT_WORDS; i++) {
        cdata[i] = Blowfish_stream2word(ciphertext, STR_SIZE(ciphertext), &j);
    }

    /* Now do the encryption */
    for (k = 0; k < 64; k++) {
        blf_enc(&state, cdata, BCRYPT_WORDS / 2);
    }

    for (i = 0; i < BCRYPT_WORDS; i++) {
        ciphertext[4 * i + 3] = cdata[i] & 0xFF;
        cdata[i] = cdata[i] >> 8;
        ciphertext[4 * i + 2] = cdata[i] & 0xFF;
        cdata[i] = cdata[i] >> 8;
        ciphertext[4 * i + 1] = cdata[i] & 0xFF;
        cdata[i] = cdata[i] >> 8;
        ciphertext[4 * i + 0] = cdata[i] & 0xFF;
    }

    if (NULL == (w = write_prefix(hash, hash_end, minor, cost))) {
        return false;
    }
    if (NULL == (w = encode_base64(raw_salt, raw_salt_end, w, hash_end))) {
        return false;
    }
    if (NULL == (w = encode_base64(ciphertext, ciphertext + STR_LEN(ciphertext), w, hash_end))) {
        return false;
    }
    explicit_bzero(cdata, sizeof(cdata));
    explicit_bzero(&state, sizeof(state));
    explicit_bzero(raw_salt, sizeof(raw_salt));
    explicit_bzero(ciphertext, sizeof(ciphertext));
#if 0
    printf("H = >%.*s<\n", (int) (w - hash), hash);
#endif

    return true;
}

#ifndef STANDALONE
static ERL_NIF_TERM expassword_bcrypt_generate_salt_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int cost;
    ERL_NIF_TERM output;
    ErlNifBinary raw_salt;

    if (
           2 == argc
        && enif_inspect_binary(env, argv[0], &raw_salt)
        && enif_is_map(env, argv[2])
        && extract_options_from_erlang_map(env, argv[2], &cost)
    ) {
        uint8_t salt[BCRYPT_SALTSPACE];

        if (NULL == bcrypt_init_salt(cost, raw_salt.data, raw_salt.data + raw_salt.size, salt, salt + STR_SIZE(salt))) {
            output = enif_make_badarg(env);
        } else {
            unsigned char *buffer;

            if (NULL == (buffer = enif_make_new_binary(env, STR_SIZE(salt), &output))) {
                output = enif_make_badarg(env); // TODO: better
            } else {
                memcpy(buffer, salt, STR_SIZE(salt));
            }
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_hash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM output;
    ErlNifBinary password, salt;

    if (
           2 == argc
        && enif_inspect_binary(env, argv[0], &password)
        && enif_inspect_binary(env, argv[1], &salt)
    ) {
        uint8_t hash[BCRYPT_HASHSPACE - 1], password0[password.size + 1];

        memcpy(password0, password.data, password.size);
        password0[password.size] = '\0';
        if (bcrypt_hash(password0, password0 + STR_SIZE(password0), salt.data, salt.data + salt.size, hash, hash + STR_SIZE(hash))) {
            unsigned char *buffer;

            if (NULL == (buffer = enif_make_new_binary(env, STR_SIZE(hash), &output))) {
                output = enif_make_badarg(env); // TODO: better
            } else {
                memcpy(buffer, hash, STR_SIZE(hash));
            }
        } else {
            output = atom_false; // TODO
        }
//         explicit_bzero(hash, sizeof(hash));
        explicit_bzero(password0, sizeof(password0));
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_verify_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM output;
    ErlNifBinary password, goodhash;

    if (
           2 == argc
        && enif_inspect_binary(env, argv[0], &password)
        && enif_inspect_binary(env, argv[1], &goodhash)
        && bcrypt_valid_hash(&goodhash)
    ) {
        uint8_t hash[BCRYPT_HASHSPACE - 1], password0[password.size + 1];

        memcpy(password0, password.data, password.size);
        password0[password.size] = '\0';
        if (bcrypt_hash(password0, password0 + STR_SIZE(password0), goodhash.data, goodhash.data + goodhash.size, hash, hash + STR_SIZE(hash))) {
            // TODO: length check
// printf("%s: %d\n", __func__, __LINE__);
            output = 0 == timingsafe_bcmp(goodhash.data, hash, STR_SIZE(hash)) ? atom_true : atom_false;
        } else {
// printf("%s: %d\n", __func__, __LINE__);
            output = atom_false;
        }
//         explicit_bzero(hash, sizeof(hash));
        explicit_bzero(password0, sizeof(password0));
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_valid_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary hash;
    ERL_NIF_TERM output;

    if (1 == argc && enif_inspect_binary(env, argv[0], &hash)) {
        output = bcrypt_valid_hash(&hash) ? atom_true : atom_false;
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_get_options_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    enum {
        BCRYPT_OPTIONS_COST,
        _BCRYPT_OPTIONS_COUNT,
    };
    int cost;
    ErlNifBinary hash;
    ERL_NIF_TERM output;

    if (1 != argc || !enif_inspect_binary(env, argv[0], &hash)) {
        output = enif_make_badarg(env);
    } else if (bcrypt_valid_hash(&hash) && bcrypt_parse_hash(&hash, &cost)) {
        ERL_NIF_TERM options;
        ERL_NIF_TERM keys[_BCRYPT_OPTIONS_COUNT], values[_BCRYPT_OPTIONS_COUNT];

        keys[BCRYPT_OPTIONS_COST] = atom_cost;
        values[BCRYPT_OPTIONS_COST] = enif_make_int(env, cost);
        enif_make_map_from_arrays(env, keys, values, _BCRYPT_OPTIONS_COUNT, &options);

        output = enif_make_tuple2(env, atom_ok, options);
    } else {
        output = enif_make_tuple2(env, atom_error, atom_invalid);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_needs_rehash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int new_cost;
    ErlNifBinary hash;
    ERL_NIF_TERM output;

    if (
        2 == argc
        && enif_inspect_binary(env, argv[0], &hash)
        && enif_is_map(env, argv[1])
        && extract_options_from_erlang_map(env, argv[1], &new_cost)
    ) {
        int old_cost;

        if (bcrypt_valid_hash(&hash) && bcrypt_parse_hash(&hash, &old_cost)) {
            // OK, NOP
        } else {
            old_cost = 0;
        }
        output = old_cost != new_cost ? atom_true : atom_false;
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

#if 0
static ERL_NIF_TERM expassword_bcrypt_encode_base64_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM output;
    ErlNifBinary unencoded;

    if (1 == argc && enif_inspect_binary(env, argv[0], &unencoded)) {
        uint8_t *p, encoded[(unencoded.size * 4 + 2) / 3];

        if (NULL == (p = encode_base64(unencoded.data, unencoded.data + unencoded.size, encoded, encoded + STR_SIZE(encoded)))) {
            output = enif_make_badarg(env);
        } else {
            unsigned char *buffer;

            if (NULL == (buffer = enif_make_new_binary(env, p - encoded, &output))) {
                output = enif_make_badarg(env); // TODO: better
            } else {
                memcpy(buffer, encoded, p - encoded);
            }
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_bcrypt_decode_base64_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM output;
    ErlNifBinary encoded;

    if (1 == argc && enif_inspect_binary(env, argv[0], &encoded)) {
        uint8_t *p, decoded[encoded.size];

        if (NULL == (p = decode_base64(encoded.data, encoded.data + encoded.size, decoded, decoded + STR_SIZE(decoded)))) {
            output = enif_make_badarg(env);
        } else {
            unsigned char *buffer;

            if (NULL == (buffer = enif_make_new_binary(env, p - decoded, &output))) {
                output = enif_make_badarg(env); // TODO: better
            } else {
                memcpy(buffer, decoded, p - decoded);
            }
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}
#endif

static ErlNifFunc expassword_bcrypt_nif_funcs[] =
{
    {"generate_salt_nif", 2, expassword_bcrypt_generate_salt_nif, 0},
    {"hash_nif", 2, expassword_bcrypt_hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_nif", 2, expassword_bcrypt_verify_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"get_options_nif", 1, expassword_bcrypt_get_options_nif, 0},
    {"needs_rehash_nif", 2, expassword_bcrypt_needs_rehash_nif, 0},
    {"valid_nif", 1, expassword_bcrypt_valid_nif, 0},
#if 0
    {"encode_base64_nif", 1, expassword_bcrypt_encode_base64_nif, 0},
    {"decode_base64_nif", 1, expassword_bcrypt_decode_base64_nif, 0},
#endif
};

static int expassword_bcrypt_nif_load(ErlNifEnv *env, void **UNUSED(priv_data), ERL_NIF_TERM UNUSED(load_info))
{
#define ATOM(x) \
    atom_##x = enif_make_atom_len(env, #x, STR_LEN(#x));
#include "atoms.h"
#undef ATOM

    return 0;
}

ERL_NIF_INIT(Elixir.ExPassword.Bcrypt.Base, expassword_bcrypt_nif_funcs, expassword_bcrypt_nif_load, NULL, NULL, NULL)
#endif /* !STANDALONE */
