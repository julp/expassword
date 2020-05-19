#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof((array)[0]))
#define STR_LEN(str) \
    (ARRAY_SIZE(str) - 1)
#define STR_SIZE(str) \
    (ARRAY_SIZE(str))

extern uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);

extern uint8_t *bcrypt_full_parse_hash(uint8_t *hash, const uint8_t *hash_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern bool bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *hash, const uint8_t * const hash_end, int minor, int cost);

int main(void)
{
    int retval;
    uint8_t hash[128];
    uint8_t password[] = "U*U";
    uint8_t salt[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.";

    retval = EXIT_SUCCESS;

    if (bcrypt_hash(password, password + STR_SIZE(password), salt, salt + STR_SIZE(salt), hash, hash + STR_SIZE(hash), 'a', 5)) {
        //retval = 0 == strcmp((char *) hash, "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") ? EXIT_SUCCESS : EXIT_FAILURE;
        retval = EXIT_FAILURE;
    } else {
        retval = EXIT_FAILURE;
    }

    /* ==================== base64 decoding ==================== */

    // normal case without any additional space
    {
        uint8_t *p, data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[16], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        if (NULL == (p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer)))) {
            retval = EXIT_FAILURE;
            fprintf(stderr, "decode_base64 failed to decode data (%d)\n", __LINE__);
        } else {
            if (p != buffer + STR_SIZE(buffer)) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to return correct position from the input string (%d)\n", __LINE__);
            }
            if (0 != memcmp(buffer, expected, STR_SIZE(expected))) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to correctly decode input string (%d)\n", __LINE__);
            }
        }
    }
    // normal case with larger output buffer
    {
        uint8_t *p, data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[32], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        if (NULL == (p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer)))) {
            retval = EXIT_FAILURE;
            fprintf(stderr, "decode_base64 failed to decode data (%d)\n", __LINE__);
        } else {
            if (p != buffer + STR_SIZE(expected)) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to return correct position from the input string (%d)\n", __LINE__);
            }
            if (0 != memcmp(buffer, expected, STR_SIZE(expected))) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to correctly decode input string (%d)\n", __LINE__);
            }
        }
    }
    // normal case without any additional space but a \0 terminated input string
    {
        uint8_t *p, data[] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[16], expected[16] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

        if (NULL == (p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer)))) {
            retval = EXIT_FAILURE;
            fprintf(stderr, "decode_base64 failed to decode data (%d)\n", __LINE__);
        } else {
            if (p != buffer + STR_SIZE(expected)) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to return correct position from the input string (%d)\n", __LINE__);
            }
            if (0 != memcmp(buffer, expected, STR_SIZE(expected))) {
                retval = EXIT_FAILURE;
                fprintf(stderr, "decode_base64 failed to correctly decode input string (%d)\n", __LINE__);
            }
        }
    }
    // output buffer too small
    {
        uint8_t data[22] = "CCCCCCCCCCCCCCCCCCCCC.", buffer[15];

        if (NULL != decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer))) {
            retval = EXIT_FAILURE;
            fprintf(stderr, "decode_base64 failed to report unsufficient space for output buffer (%d)\n", __LINE__);
        }
    }
    // invalid input string
    {
        uint8_t data[22] = "CCCCCCCCCCC+CCCCCCCCC.", buffer[16];

        if (NULL != decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer))) {
            retval = EXIT_FAILURE;
            fprintf(stderr, "decode_base64 failed to report invalid character (%d)\n", __LINE__);
        }
    }

    return retval;
}
