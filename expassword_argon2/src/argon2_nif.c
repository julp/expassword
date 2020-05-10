#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include <argon2.h>
#include <erl_nif.h>

#include "parsenum.h"

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof((array)[0]))

#define STR_LEN(str) \
    (ARRAY_SIZE(str) - 1)

#define STR_SIZE(str) \
    (ARRAY_SIZE(str))

#define ARGON2I_PREFIX "$argon2i$"
#define ARGON2ID_PREFIX "$argon2id$"

#define ATOM(/*ErlNifEnv **/env, /*const char **/ string) \
    enif_make_atom_len(env, string, STR_LEN(string))

#define enif_get_uint32(/*ErlNifEnv **/ env, /*ERL_NIF_TERM*/ input, /*uint32_t **/ output) \
    enif_get_uint(env, input, output)

#define enif_make_uint32(/*ErlNifEnv **/ env, /*uint32_t **/ input) \
    enif_make_uint(env, input)

#define MEMCMP(/*const char **/ haystack, /*const char **/ needle) \
    memcmp(haystack, needle, STR_LEN(needle))

static bool extract_options_from_erlang_map(ErlNifEnv *env, ERL_NIF_TERM map, argon2_type *type, uint32_t *version, uint32_t *threads, uint32_t *time_cost, uint32_t *memory_cost)
{
    ERL_NIF_TERM value;

    if (enif_get_map_value(env, map, ATOM(env, "version"), &value) && enif_get_uint32(env, value, version)) {
        // ok
    } else {
        *version = ARGON2_VERSION_NUMBER;
    }

    *type = Argon2_id;
    if (enif_get_map_value(env, map, ATOM(env, "type"), &value)) {
        if (enif_is_identical(value, ATOM(env, "argon2i"))) {
            *type = Argon2_i;
        }/* else if (enif_is_identical(value, ATOM(env, "argon2id"))) {
            *type = Argon2_id;
        }*/
    }

    return
           enif_get_map_value(env, map, ATOM(env, "threads"), &value) && enif_get_uint32(env, value, threads)
        && enif_get_map_value(env, map, ATOM(env, "time_cost"), &value) && enif_get_uint32(env, value, time_cost)
        && enif_get_map_value(env, map, ATOM(env, "memory_cost"), &value) && enif_get_uint32(env, value, memory_cost)
    ;
}

static bool argon2_valid_hash(const ErlNifBinary *hash, argon2_type *type)
{
    int at;

    at = -1;
    if (hash->size >= STR_LEN(ARGON2ID_PREFIX)) {
        if (0 == MEMCMP(hash->data, ARGON2ID_PREFIX)) {
            at = Argon2_id;
        } else if (0 == MEMCMP(hash->data, ARGON2I_PREFIX)) {
            at = Argon2_i;
        }
    }
    if (NULL != type) {
        *type = at;
    }

    return -1 != at;
}

static bool argon2_parse_hash(const ErlNifBinary *hash, argon2_type *type, uint32_t *version, uint32_t *threads, uint32_t *time_cost, uint32_t *memory_cost)
{
    char *end;
    const char *r = (const char *) hash->data;
    const char * const hash_end = (const char *) hash->data + hash->size;

    if (hash->size < STR_LEN(ARGON2ID_PREFIX)) {
        return false;
    }
    if (0 == MEMCMP(hash->data, ARGON2ID_PREFIX)) {
        *type = Argon2_id;
        r += STR_LEN(ARGON2ID_PREFIX);
    } else if (0 == MEMCMP(hash->data, ARGON2I_PREFIX)) {
        *type = Argon2_i;
        r += STR_LEN(ARGON2I_PREFIX);
    } else {
        return false;
    }
    if (0 == MEMCMP(r, "v=")) {
        r += STR_LEN("v=");
        if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, version) || 0 != MEMCMP(end, "$m=")) {
            return false;
        }
        r = end + STR_LEN("$m=");
    } else if (0 == MEMCMP(r, "m=")) {
        *version = ARGON2_VERSION_10;
        r += STR_LEN("m=");
    } else {
        return false;
    }
    if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, memory_cost) || 0 != MEMCMP(end, ",t=")) {
        return false;
    }
    r = end + STR_LEN(",t=");
    if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, time_cost) || 0 != MEMCMP(end, ",p=")) {
        return false;
    }
    r = end + STR_LEN(",p=");
    if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, threads) || '$' != *end) {
        return false;
    }

    return true;
}

static ERL_NIF_TERM expassword_argon2_hash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    argon2_type type;
    ERL_NIF_TERM output;
    ErlNifBinary password, salt;
    uint32_t version, threads, time_cost, memory_cost;

    if (
        3 == argc
        && enif_inspect_binary(env, argv[0], &password)
        && enif_inspect_binary(env, argv[1], &salt)
        && enif_is_map(env, argv[2])
        && extract_options_from_erlang_map(env, argv[2], &type, &version, &threads, &time_cost, &memory_cost)
// && printf("threads = %" PRIu32 " time_cost = %" PRIu32 ", memory_cost = %" PRIu32 "\n", threads, time_cost, memory_cost)
        && threads >= ARGON2_MIN_THREADS && threads <= ARGON2_MAX_THREADS
        && time_cost >= ARGON2_MIN_TIME && time_cost <= ARGON2_MAX_TIME
        && memory_cost >= ARGON2_MIN_MEMORY && memory_cost <= ARGON2_MAX_MEMORY
    ) {
        char out[32];
        size_t encoded_len;
        unsigned char *encoded;
        argon2_error_codes status;

        encoded_len = argon2_encodedlen(time_cost, memory_cost, threads, salt.size, STR_SIZE(out), type);
        if (NULL == (encoded = enif_make_new_binary(env, encoded_len - 1, &output))) {
            return enif_make_badarg(env); // TODO: better
        }
        status = argon2_hash(
            time_cost,
            memory_cost,
            threads,
            password.data,
            password.size,
            salt.data,
            salt.size,
            out,
            STR_SIZE(out),
            (char *) encoded,
            encoded_len,
            type,
            version
        );
        if (ARGON2_OK == status) {
            //
        } else {
            // TODO: output is invalid, shoud we have to free/release encoded?
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_argon2_verify_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    argon2_type type;
    ERL_NIF_TERM output;
    ErlNifBinary hash, password;

    if (
        2 == argc
        && enif_inspect_binary(env, argv[0], &hash)
        && enif_inspect_binary(env, argv[1], &password)
        && argon2_valid_hash(&hash, &type)
    ) {
        char buffer[hash.size + 1];

        memcpy(buffer, (const char *) hash.data, hash.size);
        buffer[hash.size] = '\0';
        output = ARGON2_OK == argon2_verify(buffer, password.data, password.size, type) ? ATOM(env, "true") : ATOM(env, "false");
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

enum {
    ARGON2_OPTIONS_TYPE,
    ARGON2_OPTIONS_VERSION,
    ARGON2_OPTIONS_THREADS,
    ARGON2_OPTIONS_TIME_COST,
    ARGON2_OPTIONS_MEMORY_COST,
    _ARGON2_OPTIONS_COUNT,
};

static ERL_NIF_TERM expassword_argon2_get_options_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    argon2_type type;
    ErlNifBinary hash;
    ERL_NIF_TERM output;
    uint32_t version, time_cost, threads, memory_cost;

    if (1 != argc || !enif_inspect_binary(env, argv[0], &hash)) {
        output = enif_make_badarg(env);
    } else if (argon2_valid_hash(&hash, NULL) && argon2_parse_hash(&hash, &type, &version, &threads, &time_cost, &memory_cost)) {
        ERL_NIF_TERM options;
        const char *argon_type;
        ERL_NIF_TERM pairs[2][_ARGON2_OPTIONS_COUNT];

        argon_type = argon2_type2string(type, 0);
        pairs[0][ARGON2_OPTIONS_TYPE] = ATOM(env, "type");
        pairs[1][ARGON2_OPTIONS_TYPE] = enif_make_atom(env, argon_type);
        pairs[0][ARGON2_OPTIONS_VERSION] = ATOM(env, "version");
        pairs[1][ARGON2_OPTIONS_VERSION] = enif_make_uint32(env, version);
        pairs[0][ARGON2_OPTIONS_THREADS] = ATOM(env, "threads");
        pairs[1][ARGON2_OPTIONS_THREADS] = enif_make_uint32(env, threads);
        pairs[0][ARGON2_OPTIONS_TIME_COST] = ATOM(env, "time_cost");
        pairs[1][ARGON2_OPTIONS_TIME_COST] = enif_make_uint32(env, time_cost);
        pairs[0][ARGON2_OPTIONS_MEMORY_COST] = ATOM(env, "memory_cost");
        pairs[1][ARGON2_OPTIONS_MEMORY_COST] = enif_make_uint32(env, memory_cost);
        enif_make_map_from_arrays(env, pairs[0], pairs[1], _ARGON2_OPTIONS_COUNT, &options);

        output = enif_make_tuple2(env, ATOM(env, "ok"), options);
    } else {
        output = enif_make_tuple2(env, ATOM(env, "error"), ATOM(env, "invalid"));
    }

    return output;
}

static ERL_NIF_TERM expassword_argon2_needs_rehash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary hash;
    ERL_NIF_TERM output;
    argon2_type new_type, old_type;
    uint32_t new_version, old_version, new_time_cost, old_time_cost, new_threads, old_threads, new_memory_cost, old_memory_cost;

    if (
        2 == argc
        && enif_inspect_binary(env, argv[0], &hash)
        && enif_is_map(env, argv[1])
        && extract_options_from_erlang_map(env, argv[1], &new_type, &new_version, &new_threads, &new_time_cost, &new_memory_cost)
        && argon2_parse_hash(&hash, &old_type, &old_version, &old_threads, &old_time_cost, &old_memory_cost)
    ) {
        output = new_type != old_type || new_version != old_version || new_threads != old_threads || new_memory_cost != old_memory_cost || new_time_cost != old_time_cost ? ATOM(env, "true") : ATOM(env, "false");
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_argon2_valid_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary hash;
    ERL_NIF_TERM output;

    if (1 == argc && enif_inspect_binary(env, argv[0], &hash)) {
      output = argon2_valid_hash(&hash, NULL) ? ATOM(env, "true") : ATOM(env, "false");
    } else {
      output = enif_make_badarg(env);
    }

    return output;
}

static ErlNifFunc expassword_argon2_nif_funcs[] =
{
    {"hash_nif", 3, expassword_argon2_hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_nif", 2, expassword_argon2_verify_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"get_options_nif", 1, expassword_argon2_get_options_nif, 0},
    {"needs_rehash_nif", 2, expassword_argon2_needs_rehash_nif, 0},
    {"valid_nif", 1, expassword_argon2_valid_nif, 0},
};

ERL_NIF_INIT(Elixir.ExPassword.Argon2.Base, expassword_argon2_nif_funcs, NULL, NULL, NULL, NULL)
