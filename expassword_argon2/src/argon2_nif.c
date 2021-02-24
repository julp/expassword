#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include <argon2.h>
#include <erl_nif.h>

#include "parsenum.h"

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

#define ARGON2I_PREFIX "$argon2i$"
#define ARGON2ID_PREFIX "$argon2id$"
#define ARGUMENT_ERROR_MODULE "Elixir.ArgumentError"

#define enif_get_uint32(/*ErlNifEnv **/ env, /*ERL_NIF_TERM*/ input, /*uint32_t **/ output) \
    enif_get_uint(env, input, output)

#define enif_make_uint32(/*ErlNifEnv **/ env, /*uint32_t **/ input) \
    enif_make_uint(env, input)

#define MEMCMP(/*const char **/ haystack, /*const char **/ needle) \
    memcmp(haystack, needle, STR_LEN(needle))

#define ATOM(x) \
    static ERL_NIF_TERM atom_##x;
#include "atoms.h"
#undef ATOM

static bool extract_options_from_erlang_map(ErlNifEnv *env, ERL_NIF_TERM map, argon2_type *type, uint32_t *version, uint32_t *threads, uint32_t *time_cost, uint32_t *memory_cost)
{
    bool ok;

    ok = false;
    do {
        ERL_NIF_TERM value;

        if (enif_get_map_value(env, map, atom_type, &value)) {
            if (enif_is_identical(value, atom_argon2i)) {
                *type = Argon2_i;
            } else if (enif_is_identical(value, atom_argon2id)) {
                *type = Argon2_id;
            } else {
                break;
            }
        } else {
            break;
        }

        if (enif_get_map_value(env, map, atom_version, &value) && enif_get_uint32(env, value, version)) {
            // ok but we let argon2 decide if the value is valid or not
        } else {
            *version = ARGON2_VERSION_NUMBER;
        }

        if (enif_get_map_value(env, map, atom_threads, &value) && enif_get_uint32(env, value, threads)) {
            // ok but we let argon2 decide if the value is valid or not
        } else {
            break;
        }

        if (enif_get_map_value(env, map, atom_time_cost, &value) && enif_get_uint32(env, value, time_cost)) {
            // ok but we let argon2 decide if the value is valid or not
        } else {
            break;
        }

        if (enif_get_map_value(env, map, atom_memory_cost, &value) && enif_get_uint32(env, value, memory_cost)) {
            // ok but we let argon2 decide if the value is valid or not
        } else {
            break;
        }
        ok = true;
    } while (false);

    return ok;
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
    bool parsed;

    parsed = false;
    do {
        char *end;
        const char *r = (const char *) hash->data;
        const char * const hash_end = (const char *) hash->data + hash->size;

        if (hash->size < STR_LEN(ARGON2ID_PREFIX)) {
            break;
        }
        if (0 == MEMCMP(hash->data, ARGON2ID_PREFIX)) {
            *type = Argon2_id;
            r += STR_LEN(ARGON2ID_PREFIX);
        } else if (0 == MEMCMP(hash->data, ARGON2I_PREFIX)) {
            *type = Argon2_i;
            r += STR_LEN(ARGON2I_PREFIX);
        } else {
            break;
        }
        if (0 == MEMCMP(r, "v=")) {
            r += STR_LEN("v=");
            if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, version) || 0 != MEMCMP(end, "$m=")) {
                break;
            }
            r = end + STR_LEN("$m=");
        } else if (0 == MEMCMP(r, "m=")) {
            *version = ARGON2_VERSION_10;
            r += STR_LEN("m=");
        } else {
            break;
        }
        if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, memory_cost) || 0 != MEMCMP(end, ",t=")) {
            break;
        }
        r = end + STR_LEN(",t=");
        if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, time_cost) || 0 != MEMCMP(end, ",p=")) {
            break;
        }
        r = end + STR_LEN(",p=");
        if (PARSE_NUM_ERR_NON_DIGIT_FOUND != strntouint32_t(r, hash_end, &end, 10, NULL, NULL, threads) || '$' != *end) {
            break;
        }
        parsed = true;
    } while (false);

    return parsed;
}

static ERL_NIF_TERM make_elixir_exception(ErlNifEnv *env, const char *module, const char *error)
{
    enum {
        ERROR_STRUCT,
        ERROR_EXCEPTION,
        ERROR_MESSAGE,
        _ERROR_COUNT,
    };
    size_t error_len;
    unsigned char *buffer;
    ERL_NIF_TERM reason, exception, keys[_ERROR_COUNT], values[_ERROR_COUNT];

    error_len = strlen(error);
    buffer = enif_make_new_binary(env, error_len, &reason);
    memcpy(buffer, error, error_len);
    keys[ERROR_STRUCT] = atom___struct__;
    values[ERROR_STRUCT] = enif_make_atom(env, module);
    keys[ERROR_EXCEPTION] = atom___exception__;
    values[ERROR_EXCEPTION] = atom_true;
    keys[ERROR_MESSAGE] = atom_message;
    values[ERROR_MESSAGE] = reason;
    enif_make_map_from_arrays(env, keys, values, _ERROR_COUNT, &exception);

    return exception;
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
    ) {
        char out[32];
        size_t encoded_len;
        argon2_error_codes status;

        encoded_len = argon2_encodedlen(time_cost, memory_cost, threads, salt.size, STR_SIZE(out), type);
        {
            char buffer[encoded_len];

            status = argon2_hash(time_cost, memory_cost, threads, password.data, password.size, salt.data, salt.size, out, STR_SIZE(out), buffer, encoded_len, type, version);
            if (ARGON2_OK == status) {
                unsigned char *encoded;

                if (NULL == (encoded = enif_make_new_binary(env, encoded_len - 1, &output))) {
                    output = enif_make_badarg(env); // TODO: something better/more explicit?
                } else {
                    memcpy(encoded, buffer, encoded_len - 1);
                }
            } else {
                output = enif_raise_exception(env, make_elixir_exception(env, ARGUMENT_ERROR_MODULE, argon2_error_message(status)));
            }
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
    ErlNifBinary password, hash;

    if (
        2 == argc
        && enif_inspect_binary(env, argv[0], &password)
        && enif_inspect_binary(env, argv[1], &hash)
        && argon2_valid_hash(&hash, &type)
    ) {
        argon2_error_codes status;
        char buffer[hash.size + 1];

        memcpy(buffer, (const char *) hash.data, hash.size);
        buffer[hash.size] = '\0';
        status = argon2_verify(buffer, password.data, password.size, type);
        if (ARGON2_VERIFY_MISMATCH == status || ARGON2_OK == status) {
            output = ARGON2_OK == status ? atom_true : atom_false;
        } else {
            output = enif_raise_exception(env, make_elixir_exception(env, ARGUMENT_ERROR_MODULE, argon2_error_message(status)));
        }
    } else {
        output = enif_make_badarg(env);
    }

    return output;
}

static ERL_NIF_TERM expassword_argon2_get_options_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    enum {
        ARGON2_OPTIONS_TYPE,
        ARGON2_OPTIONS_VERSION,
        ARGON2_OPTIONS_THREADS,
        ARGON2_OPTIONS_TIME_COST,
        ARGON2_OPTIONS_MEMORY_COST,
        _ARGON2_OPTIONS_COUNT,
    };
    argon2_type type;
    ErlNifBinary hash;
    ERL_NIF_TERM output;
    uint32_t version, time_cost, threads, memory_cost;

    if (1 != argc || !enif_inspect_binary(env, argv[0], &hash)) {
        output = enif_make_badarg(env);
    } else if (argon2_valid_hash(&hash, NULL) && argon2_parse_hash(&hash, &type, &version, &threads, &time_cost, &memory_cost)) {
        ERL_NIF_TERM options;
        const char *argon_type;
        ERL_NIF_TERM keys[_ARGON2_OPTIONS_COUNT], values[_ARGON2_OPTIONS_COUNT];

        argon_type = argon2_type2string(type, 0);
        keys[ARGON2_OPTIONS_TYPE] = atom_type;
        values[ARGON2_OPTIONS_TYPE] = enif_make_atom(env, argon_type);
        keys[ARGON2_OPTIONS_VERSION] = atom_version;
        values[ARGON2_OPTIONS_VERSION] = enif_make_uint32(env, version);
        keys[ARGON2_OPTIONS_THREADS] = atom_threads;
        values[ARGON2_OPTIONS_THREADS] = enif_make_uint32(env, threads);
        keys[ARGON2_OPTIONS_TIME_COST] = atom_time_cost;
        values[ARGON2_OPTIONS_TIME_COST] = enif_make_uint32(env, time_cost);
        keys[ARGON2_OPTIONS_MEMORY_COST] = atom_memory_cost;
        values[ARGON2_OPTIONS_MEMORY_COST] = enif_make_uint32(env, memory_cost);
        enif_make_map_from_arrays(env, keys, values, _ARGON2_OPTIONS_COUNT, &options);

        output = enif_make_tuple2(env, atom_ok, options);
    } else {
        output = enif_make_tuple2(env, atom_error, atom_invalid);
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
        output = new_type != old_type || new_version != old_version || new_threads != old_threads || new_memory_cost != old_memory_cost || new_time_cost != old_time_cost ? atom_true : atom_false;
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
      output = argon2_valid_hash(&hash, NULL) ? atom_true : atom_false;
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

static int expassword_argon2_nif_load(ErlNifEnv *env, void **UNUSED(priv_data), ERL_NIF_TERM UNUSED(load_info))
{
#define ATOM(x) \
    atom_##x = enif_make_atom_len(env, #x, STR_LEN(#x));
#include "atoms.h"
#undef ATOM

    return 0;
}

ERL_NIF_INIT(Elixir.ExPassword.Argon2.Base, expassword_argon2_nif_funcs, expassword_argon2_nif_load, NULL, NULL, NULL)
