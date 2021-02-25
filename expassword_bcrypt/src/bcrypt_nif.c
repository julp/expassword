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
#include "common.h"

#define BCRYPT_MINOR 'b'
#define BCRYPT_VERSION '2'
#define BCRYPT_WORDS 6		/* Ciphertext words */
#define BCRYPT_MINLOGROUNDS 4	/* we have log2(rounds) in salt */

#define BCRYPT_PREFIX "$2*$"
#define BCRYPT_MAXLOGROUNDS 31
#define BCRYPT_MAX_KEY_LEN 72

#ifndef STANDALONE
# define ATOM(x) \
    static ERL_NIF_TERM atom_##x;
# include "atoms.h"
# undef ATOM
# define EXPORT_IF_STANDALONE static
#else
# define EXPORT_IF_STANDALONE /* NOP */
#endif /* !STANDALONE */

static const uint8_t Base64Code[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static const uint8_t index_64[] = {
    /*       x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
    /* 0x */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 1x */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 2x */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
    /* 3x */ 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 4x */ 0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    /* 5x */ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 6x */ 0xFF, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
    /* 7x */ 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 8x */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* 9x */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Ax */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Bx */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Cx */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Dx */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Ex */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Fx */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

EXPORT_IF_STANDALONE uint8_t *encode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    int state; // the (n + 1)th decoded byte to write into buffer
    uint8_t *w;
    const uint8_t *r;
    const int states[] = {1, 2, 3, 0}; // replace a counter and % 4

    state = 0;
    w = buffer;
    r = data - 1;
    if (data < data_end) {
        do {
            int x, y;

            x = state << 1;
            y = 6 - x;
            *w++ = Base64Code[(uint8_t) (0b111111 & ((0 == x ? 0 : (r[0] << y)) | (0 == y || r + 1 >= data_end ? 0 : (r[1] >> (8 - y)))))];
            state = states[state];
            if (0 != state) {
                r++;
            }
        } while (w < buffer_end && r < data_end);
    }
    if (r < data_end && w >= buffer_end) {
        // buffer is too small to fully convert data
        return NULL;
    }

    return w;
}

EXPORT_IF_STANDALONE uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    int state;
    uint8_t *w;
    const uint8_t *r;
    const int states[] = {1, 2, 3, 0};

    state = 0;
    for (w = buffer, r = data; r < data_end && w < buffer_end; r++) {
        if (3 != state) {
            int x, y;
            uint8_t c1, c2;

            c1 = index_64[r[0]];
            c2 = (r + 1) < data_end ? index_64[r[1]] : 0;
            if (0xFF == (c1 | c2)) {
                // invalid character found
                return NULL;
            }
            y = (state + 1) << 1;
            x = 8 - y;
            *w++ = (c1 & (0xFF >> y)) << y | (c2 >> (6 - y));
        }
        state = states[state];
    }
    if (r + 1 < data_end && w >= buffer_end) {
        // buffer is too small to fully convert data
        return NULL;
    }

    return w;
}

static uint8_t *write_prefix(uint8_t *buffer, const uint8_t * const buffer_end, int minor, int cost)
{
    if (buffer > buffer_end || ((size_t) (buffer_end - buffer)) < STR_LEN("$vm$cc$")) {
        return NULL; // OUT_PTR_MISMATCH || OUTPUT_TOO_SHORT
    }

    *buffer++ = '$';
    *buffer++ = BCRYPT_VERSION;
    *buffer++ = minor;
    *buffer++ = '$';
    *buffer++ = '0' + (cost / 10);
    *buffer++ = '0' + (cost % 10);
    *buffer++ = '$';

    return buffer;
}

#ifndef STANDALONE
EXPORT_IF_STANDALONE bool bcrypt_valid_hash(const ErlNifBinary *hash)
{
    return
           hash->size == (BCRYPT_HASHSPACE - 1)
        && '$' == hash->data[0]
        && BCRYPT_VERSION == hash->data[1]
        && ('a' == hash->data[2] || 'b' == hash->data[2] || 'y' == hash->data[2])
//         && '$' == hash->data[3]
    ;
}

static bool extract_options_from_erlang_map(ErlNifEnv *env, ERL_NIF_TERM map, int *cost)
{
    ERL_NIF_TERM value;

    if (enif_get_map_value(env, map, atom_cost, &value) && enif_get_int(env, value, cost)) {
        // ok
    } else {
        *cost = 0;
    }

    return *cost >= BCRYPT_MINLOGROUNDS && *cost <= BCRYPT_MAXLOGROUNDS;
}
#endif /* !STANDALONE */

EXPORT_IF_STANDALONE uint8_t *bcrypt_init_salt(int minor, int cost, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *buffer, const uint8_t * const buffer_end)
{
    uint8_t *w;

    if (raw_salt > raw_salt_end || ((size_t) (raw_salt_end - raw_salt)) < BCRYPT_MAXSALT) {
        // salt is too short
        return NULL; // SALT_PTR_MISMATCH || SALT_TOO_SHORT
    }

    if ('a' != minor && 'b' != minor && 'y' != minor) {
        return NULL;
    }

    if (cost < BCRYPT_MINLOGROUNDS) {
        cost = BCRYPT_MINLOGROUNDS;
    } else if (cost > BCRYPT_MAXLOGROUNDS) {
        cost = BCRYPT_MAXLOGROUNDS;
    }

    if (NULL == (w = write_prefix(buffer, buffer_end, minor, cost))) {
        return NULL; // ENCODING_FAIL
    }
    if (NULL == (w = encode_base64(raw_salt, raw_salt + BCRYPT_MAXSALT, w, buffer_end))) {
        return NULL; // ENCODING_FAIL
    }

    return w;
}

// salt here means prefix "$vm$cc$" + base64 encoded salt
// raw_salt is the real unencoded (base64) hash
EXPORT_IF_STANDALONE const uint8_t *bcrypt_full_parse_hash(const uint8_t *salt, const uint8_t *salt_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end)
{
    uint8_t d1, d2;
    const uint8_t *r;

    r = salt;
    if (salt > salt_end || ((size_t) (salt_end - salt)) < BCRYPT_SALTSPACE) {
        return NULL; // SALT_PTR_MISMATCH || SALT_TOO_SHORT
    }
    if ('$' != *r++) {
        return NULL; // DECODING_FAIL
    }
    if (BCRYPT_VERSION != *r++) {
        return NULL; // DECODING_FAIL
    }
    *minor = *r++;
    if ('a' != *minor && 'b' != *minor && 'y' != *minor) {
        return NULL; // INCORRECT_TYPE
    }
    if ('$' != *r++) {
        return NULL; // DECODING_FAIL
    }
    if (!isdigit(d1 = *r++) || !isdigit(d2 = *r++)) {
        return NULL; // DECODING_FAIL
    }
    *cost = (d2 - '0') + ((d1 - '0') * 10);
    if (*cost < BCRYPT_MINLOGROUNDS || *cost > BCRYPT_MAXLOGROUNDS) {
        return NULL; // DECODING_FAIL
    }
    if ('$' != *r++) {
        return NULL; // DECODING_FAIL
    }
    if (NULL == (r = decode_base64(r, salt + BCRYPT_SALTSPACE, raw_salt, raw_salt_end))) {
        return NULL; // DECODING_FAIL
    }

    return r;
}

#ifndef STANDALONE
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
#endif /* !STANDALONE */

EXPORT_IF_STANDALONE uint8_t *bcrypt_hash(
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
        return NULL;
    }
    if (password > password_end) {
        return NULL; // PWD_PTR_MISMATCH
    }
    // REMINDER: password_len counts \0
    password_len = (password_end - password);
    if ('a' == minor) {
        password_len = (uint8_t) (password_len);
    } else if ('b' == minor || 'y' == minor) {
        if (password_len > 73) {
            password_len = 73;
        }
    } else {
        assert(false);
        return NULL; // INCORRECT_TYPE
    }

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

    do {
        if (NULL == (w = write_prefix(hash, hash_end, minor, cost))) {
            break; // ENCODING_FAIL
        }
        if (NULL == (w = encode_base64(raw_salt, raw_salt_end, w, hash_end))) {
            break; // ENCODING_FAIL
        }
        if (NULL == (w = encode_base64(ciphertext, ciphertext + STR_LEN(ciphertext), w, hash_end))) {
            break; // ENCODING_FAIL
        }
    } while (false);
    explicit_bzero(cdata, sizeof(cdata));
    explicit_bzero(&state, sizeof(state));
    explicit_bzero(raw_salt, sizeof(raw_salt));
    explicit_bzero(ciphertext, sizeof(ciphertext));

    return w;
}

#ifndef STANDALONE
static bool c_string_to_erlang_binary(ErlNifEnv *env, ERL_NIF_TERM *output, const uint8_t * const data, size_t data_len)
{
    unsigned char *buffer;

    assert(NULL != data);
    if (NULL == (buffer = enif_make_new_binary(env, data_len, output))) {
        *output = enif_make_badarg(env); // TODO: something better/more explicit?
    } else {
        memcpy(buffer, data, data_len);
    }

    return NULL != buffer;
}

static ERL_NIF_TERM expassword_bcrypt_generate_salt_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int cost;
    ERL_NIF_TERM output;
    ErlNifBinary raw_salt;

    if (
           2 == argc
        && enif_inspect_binary(env, argv[0], &raw_salt)
        && enif_is_map(env, argv[1])
        && extract_options_from_erlang_map(env, argv[1], &cost)
    ) {
        uint8_t salt[BCRYPT_SALTSPACE];

        if (NULL == bcrypt_init_salt(BCRYPT_MINOR, cost, raw_salt.data, raw_salt.data + raw_salt.size, salt, salt + STR_SIZE(salt))) {
            output = enif_make_badarg(env);
        } else {
            c_string_to_erlang_binary(env, &output, salt, STR_SIZE(salt));
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static uint8_t *memcpy_l(const uint8_t *from, const uint8_t * const from_end, uint8_t *to, const uint8_t * const to_end)
{
    while (to < to_end && from < from_end) {
        *to++ = *from++;
    }
    if (to < to_end) {
      *to++ = '\0';
    }

    return to;
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
        uint8_t hash[BCRYPT_HASHSPACE - 1], password0[BCRYPT_MAX_KEY_LEN], *password0_end;

        password0_end = memcpy_l(password.data, password.data + password.size, password0, password0 + STR_SIZE(password0));
        if (NULL != bcrypt_hash(password0, password0_end, salt.data, salt.data + salt.size, hash, hash + STR_SIZE(hash))) {
            c_string_to_erlang_binary(env, &output, hash, STR_SIZE(hash));
        } else {
            output = enif_make_badarg(env);
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
        uint8_t *p, hash[BCRYPT_HASHSPACE - 1], password0[BCRYPT_MAX_KEY_LEN], *password0_end;

        password0_end = memcpy_l(password.data, password.data + password.size, password0, password0 + STR_SIZE(password0));
        if (NULL != (p = bcrypt_hash(password0, password0_end, goodhash.data, goodhash.data + goodhash.size, hash, hash + STR_SIZE(hash)))) {
            output = p > hash && goodhash.size == ((size_t) (p - hash)) && 0 == timingsafe_bcmp(goodhash.data, hash, STR_SIZE(hash)) ? atom_true : atom_false;
        } else {
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
    ErlNifBinary hash;
    ERL_NIF_TERM output;
    int old_cost, new_cost;

    if (
           2 == argc
        && enif_inspect_binary(env, argv[0], &hash)
        && enif_is_map(env, argv[1])
        && extract_options_from_erlang_map(env, argv[1], &new_cost)
        && bcrypt_valid_hash(&hash)
        && bcrypt_parse_hash(&hash, &old_cost)
    ) {
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
            c_string_to_erlang_binary(env, &output, encoded, p - encoded);
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
            c_string_to_erlang_binary(env, &output, decoded, p - decoded);
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
