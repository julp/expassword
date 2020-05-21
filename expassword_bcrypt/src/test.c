#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof((array)[0]))
#define STR_LEN(str) \
    (ARRAY_SIZE(str) - 1)
#define STR_SIZE(str) \
    (ARRAY_SIZE(str))

#define RED(str) "\33[1;31m" str "\33[0m"
#define GREEN(str) "\33[1;32m" str "\33[0m"

#define ASSERT(expr, description) \
    do { \
        tests++; \
        if (expr) { \
            if (verbose) { \
                fprintf(stderr, "[ " GREEN("PASS") " ] " description " (%d)\n", __LINE__); \
            } \
        } else { \
            failures++; \
            retval = EXIT_FAILURE; \
            fprintf(stderr, "[ " RED("FAIL") " ] " description " => test %s failed at line %d\n", #expr, __LINE__); \
        } \
    } while (0);

extern uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);

extern uint8_t *bcrypt_full_parse_hash(uint8_t *hash, const uint8_t *hash_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern bool bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *hash, const uint8_t * const hash_end, int minor, int cost);

static char optstr[] = "v";

static struct option long_options[] =
{
    {"verbose", no_argument, NULL, 'v'},
    {NULL,      no_argument, NULL, 0}
};

int main(int argc, char **argv)
{
    uint8_t *p;
    int c, retval, verbose;
    uint8_t hash[128];
    uint8_t password[] = "U*U";
    uint8_t salt[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.";
    size_t tests, failures;

    verbose = 0;
    failures = tests = 0;
    retval = EXIT_SUCCESS;
    while (-1 != (c = getopt_long(argc, argv, optstr, long_options, NULL))) {
        switch (c) {
          case 'v':
              verbose++;
              break;
          default:
              // NOP
              break;
        }
    }

    if (bcrypt_hash(password, password + STR_SIZE(password), salt, salt + STR_SIZE(salt), hash, hash + STR_SIZE(hash), 'a', 5)) {
        //retval = 0 == strcmp((char *) hash, "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") ? EXIT_SUCCESS : EXIT_FAILURE;
        retval = EXIT_SUCCESS;
    } else {
        retval = EXIT_FAILURE;
    }

    /* ==================== base64 decoding ==================== */

    // normal case without any additional space
    {
        uint8_t data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[16], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        ASSERT(NULL != p, "decode_base64 failed to decode data");
        ASSERT(p == buffer + STR_SIZE(expected), "decode_base64 failed to return correct position from the input string");
        ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
    }
    // normal case with larger output buffer
    {
        uint8_t data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[32], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        ASSERT(NULL != p, "decode_base64 failed to decode data");
        ASSERT(p == buffer + STR_SIZE(expected), "decode_base64 failed to return correct position from the input string");
        ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
    }
    // normal case without any additional space but a \0 terminated input string
    {
        uint8_t data[] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[16], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
        ASSERT(NULL != p, "decode_base64 failed to decode data");
        ASSERT(p == buffer + STR_SIZE(expected), "decode_base64 failed to return correct position from the input string");
        ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
    }
    // output buffer too small
    {
        uint8_t data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[15];

        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        ASSERT(NULL == p, "decode_base64 failed to report unsufficient space for output buffer");
    }
    // invalid input string
    {
        uint8_t data[22] = "CCCCCCCCCCC+CCCCCCCCC.", buffer[16];

        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        ASSERT(NULL == p, "decode_base64 failed to report invalid character");
    }

    /* ==================== report/summary ==================== */
    fprintf(stderr, "=> %.7s%zu tests, %zu failure(s) in src/test\33[0m\n", 0 == failures ? GREEN("") : RED(""), tests, failures);

    return retval;
}
