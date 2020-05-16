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

extern uint8_t *bcrypt_full_parse_hash(uint8_t *hash, const uint8_t *hash_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern bool bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *hash, const uint8_t * const hash_end, int minor, int cost);

int main(void)
{
    int retval;
    uint8_t hash[128];
    uint8_t password[] = "U*U";
    uint8_t salt[] = {0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10, 0x41, 0x04, 0x10};

    if (bcrypt_hash(password, password + STR_SIZE(password), salt, salt + STR_SIZE(salt), hash, hash + STR_SIZE(hash), 'a', 5)) {
        //retval = 0 == strcmp((char *) hash, "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW") ? EXIT_SUCCESS : EXIT_FAILURE;
        retval = EXIT_FAILURE;
    } else {
        retval = EXIT_FAILURE;
    }

    return retval;
}
