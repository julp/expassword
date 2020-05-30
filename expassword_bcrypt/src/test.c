#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#include "common.h"
#include "unity.h"

#define MAX_RAW_SALT_LEN BCRYPT_MAXSALT
#define MAX_ENCODED_SALT_LEN (BCRYPT_SALTSPACE - STR_LEN("$vm$cc$"))

extern uint8_t *encode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);
extern uint8_t *decode_base64(const uint8_t *data, const uint8_t * const data_end, uint8_t *buffer, const uint8_t * const buffer_end);

extern uint8_t *bcrypt_full_parse_hash(uint8_t *hash, const uint8_t *hash_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern bool bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *hash, const uint8_t * const hash_end, int minor, int cost);

#define D(e, r) { .raw = (const uint8_t *) r, .raw_size = STR_LEN(r), .encoded = (const uint8_t *) e, .encoded_size = STR_LEN(e) }

typedef struct {
    const uint8_t *raw, *encoded;
    size_t raw_size, encoded_size;
} test_case_t;

#define REFERENCE_RAW "\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10\x41\x04\x10"
#define REFERENCE_ENCODED "CCCCCCCCCCCCCCCCCCCCC."

static const test_case_t goodvalues[] = {
    D(REFERENCE_ENCODED,        REFERENCE_RAW),
    D("......................", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    D("999999999999999999999u", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
    D("9t9899599t9899599t989u", "\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF"),
    D("99599t9899599t9899599e", "\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE\xFF\xFE"),
};

void setUp(void) {
    // NOP
}

void tearDown(void) {
    // NOP
}

// to avoid declaring one in each function or so
static size_t i;
static uint8_t *p;

static void print_raw_salt(const uint8_t *raw_salt, const uint8_t * const raw_salt_end)
{
    const uint8_t *r;

    for (r = raw_salt; r < raw_salt_end; r++) {
        printf("0x%02" PRIX8 " ", *r);
    }
    printf("\n");
}

static void erase_buffer(uint8_t *buffer, const uint8_t * const buffer_end)
{
    uint8_t *w;

    for (w = buffer; w < buffer_end; w++) {
        *w = '+';
    }
}

/* ==================== base64 decoding ==================== */

// empty non-null terminated string decoding
void decode_base64_non_null_terminated_string_test(void)
{
    uint8_t data[0] = "", buffer[4] = {0}, expected[4] = {0};

    p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer, p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// empty null terminated string decoding
void decode_base64_null_terminated_string_test(void)
{
    uint8_t data[] = "", buffer[4] = {0}, expected[4] = {0};

    p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer, p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// normal case without any additional space
void decode_base64_normal_case_without_additional_space_test(void)
{
    uint8_t data[MAX_ENCODED_SALT_LEN], buffer[MAX_RAW_SALT_LEN];

    for (i = 0; i < ARRAY_SIZE(goodvalues); i++) {
        memcpy(data, goodvalues[i].encoded, STR_SIZE(data));
        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_PTR(buffer + STR_SIZE(buffer), p);
        TEST_ASSERT_EQUAL_MEMORY(goodvalues[i].raw, buffer, goodvalues[i].raw_size);
    }
}

// normal case with larger output buffer
void decode_base64_normal_case_with_larger_buffer_test(void)
{
    uint8_t data[MAX_ENCODED_SALT_LEN] = REFERENCE_ENCODED, buffer[32], expected[MAX_RAW_SALT_LEN] = REFERENCE_RAW;

    // NOTE: even if buffer is bigger than 16, we need to limit it to 16 else a 17th byte will be decoded from the input
    p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(expected));
    TEST_ASSERT_NOT_NULL(p);
//     printf("p = %p (%ld/%ld), buffer = %p, buffer_end = %p\n", p, p - buffer, buffer + STR_SIZE(data) - buffer, buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_EQUAL_PTR(buffer + STR_SIZE(expected), p);
    TEST_ASSERT_EQUAL_MEMORY(buffer, expected, STR_SIZE(expected));
}

// normal case without any additional space but a \0 terminated input string
void decode_base64_normal_case_without_additional_space_but_null_terminated_test(void)
{
    uint8_t data[] = REFERENCE_ENCODED, buffer[MAX_RAW_SALT_LEN], expected[MAX_RAW_SALT_LEN] = REFERENCE_RAW;

    p = decode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer + STR_SIZE(expected), p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// output buffer too small
void decode_base64_output_buffer_too_small_test(void)
{
    uint8_t data[MAX_ENCODED_SALT_LEN] = REFERENCE_ENCODED, buffer[MAX_RAW_SALT_LEN - 1];

    p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NULL(p);
}

// invalid input string
void decode_base64_invalid_input_test(void)
{
    uint8_t data[MAX_ENCODED_SALT_LEN], buffer[MAX_RAW_SALT_LEN];

    for (i = 0; i < STR_SIZE(data); i++) {
        memcpy(data, REFERENCE_ENCODED, STR_SIZE(data));
        data[i] = '+';
        p = decode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NULL(p);
    }
}

// truncation of input string on the 1st of group of 4
void decode_base64_first_input_byte_truncation(void)
{
    uint8_t buffer[MAX_RAW_SALT_LEN];
    const test_case_t truncated[] = {
        D("t", "\xBC"),
    };

    for (i = 0; i < ARRAY_SIZE(truncated); i++) {
        p = decode_base64(truncated[i].encoded, truncated[i].encoded + truncated[i].encoded_size, buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_PTR(buffer + truncated[i].raw_size, p);
        TEST_ASSERT_EQUAL_MEMORY(truncated[i].raw, buffer, truncated[i].raw_size);
    }
}

// truncation of input string on the 2nd or 3rd of group of 4
void decode_base64_second_or_third_input_byte_truncation(void)
{
    uint8_t buffer[MAX_RAW_SALT_LEN];
    const test_case_t truncated[] = {
        D("9t", "\xFE\xF0"),
        D("99t", "\xFF\xFB\xC0"),
    };

    for (i = 0; i < ARRAY_SIZE(truncated); i++) {
        erase_buffer(buffer, buffer + STR_SIZE(buffer));
        p = decode_base64(truncated[i].encoded, truncated[i].encoded + truncated[i].raw_size, buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_PTR(buffer + truncated[i].raw_size, p);
        TEST_ASSERT_EQUAL_MEMORY(truncated[i].raw, buffer, truncated[i].raw_size);
    }
}

/* ==================== base64 encoding ==================== */

// empty non-null terminated string encoding
void encode_base64_non_null_terminated_string_test(void)
{
    uint8_t data[0] = "", buffer[4] = {0}, expected[4] = {0};

    p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer, p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// empty null terminated string encoding
void encode_base64_null_terminated_string_test(void)
{
    uint8_t data[] = "", buffer[4] = {0}, expected[4] = {0};

    p = encode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer, p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// normal case without any additional space
void encode_base64_normal_case_without_additional_space_test(void)
{
    uint8_t data[MAX_RAW_SALT_LEN], buffer[MAX_ENCODED_SALT_LEN];

    for (i = 0; i < ARRAY_SIZE(goodvalues); i++) {
        memcpy(data, goodvalues[i].raw, STR_SIZE(data));
        p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
//         printf("p = %p (%ld/%ld), buffer = %p, buffer_end = %p\n", p, p - buffer, buffer + STR_SIZE(buffer) - buffer, buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_EQUAL_PTR(buffer + goodvalues[i].encoded_size, p);
        TEST_ASSERT_EQUAL_MEMORY(goodvalues[i].encoded, buffer, goodvalues[i].encoded_size);
    }
}

// normal case with larger output buffer
void encode_base64_normal_case_with_larger_buffer_test(void)
{
    uint8_t data[MAX_RAW_SALT_LEN] = REFERENCE_RAW, buffer[64], expected[MAX_ENCODED_SALT_LEN] = REFERENCE_ENCODED;

    p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer + STR_SIZE(expected), p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// normal case without any additional space but a \0 terminated input string
void encode_base64_normal_case_without_additional_space_but_null_terminated_test(void)
{
    uint8_t data[] = REFERENCE_RAW, buffer[MAX_ENCODED_SALT_LEN], expected[MAX_ENCODED_SALT_LEN] = REFERENCE_ENCODED;

    p = encode_base64(data, data + STR_LEN(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NOT_NULL(p);
    TEST_ASSERT_EQUAL_PTR(buffer + STR_SIZE(expected), p);
    TEST_ASSERT_EQUAL_MEMORY(expected, buffer, STR_SIZE(expected));
}

// output buffer too small
void encode_base64_output_buffer_too_small_test(void)
{
    uint8_t data[MAX_ENCODED_SALT_LEN] = REFERENCE_RAW, buffer[MAX_ENCODED_SALT_LEN];

    p = encode_base64(data, data + STR_SIZE(data), buffer, buffer + STR_SIZE(buffer));
    TEST_ASSERT_NULL(p);
}

// truncation of input string a non multiple of 3 bytes
void encode_base64_non_3_group_truncation_test(void)
{
    uint8_t buffer[MAX_ENCODED_SALT_LEN];
    const test_case_t truncated[] = {
        D("5u", "\xEF"),
        D("586", "\xEF\xEF"),
    };

    for (i = 0; i < ARRAY_SIZE(truncated); i++) {
        p = encode_base64(truncated[i].raw, truncated[i].raw + truncated[i].raw_size, buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
//         printf("p - buffer = %ld\n", p - buffer);
        TEST_ASSERT_EQUAL_PTR(buffer + truncated[i].encoded_size, p);
        TEST_ASSERT_EQUAL_MEMORY(truncated[i].encoded, buffer, truncated[i].encoded_size);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(decode_base64_non_null_terminated_string_test);
    RUN_TEST(decode_base64_null_terminated_string_test);
    RUN_TEST(decode_base64_normal_case_without_additional_space_test);
    RUN_TEST(decode_base64_normal_case_with_larger_buffer_test);
    RUN_TEST(decode_base64_normal_case_without_additional_space_but_null_terminated_test);
    RUN_TEST(decode_base64_output_buffer_too_small_test);
    RUN_TEST(decode_base64_first_input_byte_truncation);
    RUN_TEST(decode_base64_second_or_third_input_byte_truncation);
    UNITY_PRINT_EOL();
    RUN_TEST(encode_base64_non_null_terminated_string_test);
    RUN_TEST(encode_base64_null_terminated_string_test);
    RUN_TEST(encode_base64_normal_case_without_additional_space_test);
    RUN_TEST(encode_base64_normal_case_with_larger_buffer_test);
    RUN_TEST(encode_base64_normal_case_without_additional_space_but_null_terminated_test);
    RUN_TEST(encode_base64_output_buffer_too_small_test);
    RUN_TEST(encode_base64_non_3_group_truncation_test);

    return UNITY_END();
}
