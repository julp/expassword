#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include "common.h"

#define MAX_RAW_SALT_LEN BCRYPT_MAXSALT
#define MAX_ENCODED_SALT_LEN (BCRYPT_SALTSPACE - STR_LEN("$vm$cc$"))

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

extern uint8_t *encode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);
extern uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);

extern uint8_t *bcrypt_full_parse_hash(uint8_t *hash, const uint8_t *hash_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern bool bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *hash, const uint8_t * const hash_end, int minor, int cost);

#define D(a, b) { .raw = (const uint8_t *) a, .raw_size = STR_LEN(a), .encoded = (const uint8_t *) b, .encoded_size = STR_LEN(b) }

typedef struct {
    const uint8_t *raw, *encoded;
    size_t raw_size, encoded_size;
} test_case_t;

const test_case_t goodvalues[] = {
    D("......................", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    D("9999999999999999999999", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
    D("CCCCCCCCCCCCCCCCCCCCC.", "\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10"),
    D("9t9899599t9899599t989.", "\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF"),
    D("99599t9899599t9899599.", "\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE"),
};

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
    size_t i, tests, failures;

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

#if 0
    if (bcrypt_hash(password, password + STR_SIZE(password), salt, salt + STR_SIZE(salt), hash, hash + STR_SIZE(hash), 'a', 5)) {
        //retval = 0 == strcmp((char *) hash, "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") ? EXIT_SUCCESS : EXIT_FAILURE;
        retval = EXIT_SUCCESS;
    } else {
        retval = EXIT_FAILURE;
    }
#endif

    /* ==================== base64 encoding ==================== */

    {
        // empty non-null terminated string encoding
        {
            uint8_t data[0] = "", buffer[4] = {0}, expected[4] = {0};

            p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "encode_base64 failed to encode data");
            ASSERT(p == buffer, "encode_base64 failed to return correct position from the input string");
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "encode_base64 failed to correctly encode input string");
        }
        // empty null terminated string encoding
        {
            uint8_t data[] = "", buffer[4] = {0}, expected[4] = {0};

            p = encode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "encode_base64 failed to encode data");
            ASSERT(p == buffer, "encode_base64 failed to return correct position from the input string");
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "encode_base64 failed to correctly encode input string");
        }
        // output buffer too small
        {
            uint8_t data[MAX_ENCODED_SALT_LEN] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[MAX_ENCODED_SALT_LEN];

            p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL == p, "encode_base64 failed to report unsufficient space for output buffer");
        }
        // normal case without any additional space
        {
            uint8_t buffer[MAX_ENCODED_SALT_LEN];

            for (i = 0; i < ARRAY_SIZE(goodvalues); i++) {
                p = encode_base64(goodvalues[i].encoded, goodvalues[i].encoded + goodvalues[i].encoded_size, buffer, buffer + STR_SIZE(buffer));
                ASSERT(NULL != p, "encode_base64 failed to encode data");
                ASSERT(p == buffer + goodvalues[i].encoded_size, "encode_base64 failed to return correct position from the input string");
//                 printf("buffer = >%.*s<\n", STR_SIZE(buffer), buffer);
                ASSERT(0 == memcmp(buffer, goodvalues[i].raw, goodvalues[i].raw_size), "encode_base64 failed to correctly decode input string");
            }
        }
    }

    /* ==================== base64 decoding ==================== */

    {
        // empty non-null terminated string decoding
        {
            uint8_t data[0] = "", buffer[4] = {0}, expected[4] = {0};

            p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "decode_base64 failed to decode data");
            ASSERT(p == buffer, "decode_base64 failed to return correct position from the input string");
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
        }
        // empty null terminated string decoding
        {
            uint8_t data[] = "", buffer[4] = {0}, expected[4] = {0};

            p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "decode_base64 failed to decode data");
            ASSERT(p == buffer, "decode_base64 failed to return correct position from the input string");
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
        }
        // normal case without any additional space
        {
            uint8_t buffer[MAX_RAW_SALT_LEN];

            for (i = 0; i < ARRAY_SIZE(goodvalues); i++) {
                p = decode_base64(goodvalues[i].raw, goodvalues[i].raw + goodvalues[i].raw_size, buffer, buffer + STR_SIZE(buffer));
                ASSERT(NULL != p, "decode_base64 failed to decode data");
                ASSERT(p == buffer + goodvalues[i].encoded_size, "decode_base64 failed to return correct position from the input string");
                ASSERT(0 == memcmp(buffer, goodvalues[i].encoded, goodvalues[i].encoded_size), "decode_base64 failed to correctly decode input string");
            }
        }
        // normal case with larger output buffer
        {
            uint8_t data[MAX_ENCODED_SALT_LEN] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[32], expected[MAX_RAW_SALT_LEN] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

            p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "decode_base64 failed to decode data");
            ASSERT(p == buffer + STR_SIZE(expected), "decode_base64 failed to return correct position from the input string");
// printf("written = %ld\n", p - buffer);
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
        }
        // normal case without any additional space but a \0 terminated input string
        {
            uint8_t data[] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[MAX_RAW_SALT_LEN], expected[MAX_RAW_SALT_LEN] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

            p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL != p, "decode_base64 failed to decode data");
            ASSERT(p == buffer + STR_SIZE(expected), "decode_base64 failed to return correct position from the input string");
            ASSERT(0 == memcmp(buffer, expected, STR_SIZE(expected)), "decode_base64 failed to correctly decode input string");
        }
        // output buffer too small
        {
            uint8_t data[MAX_ENCODED_SALT_LEN] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[MAX_RAW_SALT_LEN - 1];

            p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL == p, "decode_base64 failed to report unsufficient space for output buffer");
        }
        // invalid input string
        {
            // TODO: place wrong character on byte 0, 1, 2, 3 and 4
            uint8_t data[MAX_ENCODED_SALT_LEN] = "CCCCCCCCCCC+CCCCCCCCC.", buffer[MAX_RAW_SALT_LEN];

            p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
            ASSERT(NULL == p, "decode_base64 failed to report invalid character");
        }
#if 0
        // TODO truncated
        {
            uint8_t buffer[MAX_RAW_SALT_LEN];
            uint8_t data[MAX_ENCODED_SALT_LEN] = "CCCCCCCCCCCCCCCCCCCCC.";
            const uint8_t alphabet[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            for (i = 0; i < STR_LEN(alphabet); i++) {
                data[21] = alphabet[i];
//                 printf(">%.*s<\n", (int) ARRAY_SIZE(data),data);
                p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
//                 p = decode_base64(alphabet + i, alphabet + i + 1, buffer, buffer + STR_SIZE(buffer));
//                 ASSERT(NULL != p, "decode_base64 failed to decode data");
//                 ASSERT(p == buffer + 1, "decode_base64 failed to return correct position from the input string");
                printf("%c = 0x%02" PRIX8 " %zu\n", buffer[15], buffer[15], ((i / MAX_RAW_SALT_LEN) * MAX_RAW_SALT_LEN));
//                 printf("%c = 0x%02" PRIX8 " <> 0x%02" PRIX8 " %ld\n", alphabet[i], *buffer, i & 0b111100, p - buffer);
//                 ASSERT(*buffer == ((i / MAX_RAW_SALT_LEN) * MAX_RAW_SALT_LEN), "decode_base64 failed to correctly decode input string");
//                 printf("%zu = %zu %c = %c\n", i, (i / MAX_RAW_SALT_LEN) * MAX_RAW_SALT_LEN, alphabet[i], alphabet[(i / MAX_RAW_SALT_LEN) * MAX_RAW_SALT_LEN]);
//                 printf("%c = 0x%02" PRIX8 " <> %c 0x%02" PRIX8 " %ld\n", alphabet[i], data[21], alphabet[(uint8_t) (i & 8)], (uint8_t) (i & 8), p - buffer);
            }
        }
#endif
    }

    /* ==================== report/summary ==================== */
    fprintf(stderr, "=> %.7s%zu assertions, %zu failure(s) in src/test\33[0m\n", 0 == failures ? GREEN("") : RED(""), tests, failures);

    return retval;
}
