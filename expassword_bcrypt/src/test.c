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

extern uint8_t *bcrypt_init_salt(int minor, int cost, const uint8_t *raw_salt, const uint8_t * const raw_salt_end, uint8_t *buffer, const uint8_t * const buffer_end);
extern const uint8_t *bcrypt_full_parse_hash(const uint8_t *salt, const uint8_t *salt_end, int *minor, int *cost, uint8_t *raw_salt, const uint8_t * const raw_salt_end);
extern uint8_t *bcrypt_hash(const uint8_t *password, const uint8_t * const password_end, const uint8_t *salt, const uint8_t * const salt_end, uint8_t *hash, const uint8_t * const hash_end);

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
static const uint8_t *p;

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

/* ==================== bcrypt hashing ==================== */

#define E(k, c, s, h) \
    { \
        .cost = c, \
        .hash = (const uint8_t *) h, \
        .hash_end = (const uint8_t * const) h + STR_LEN(h), \
        .password = (const uint8_t *) k, \
        .password_size = STR_SIZE(k), \
        .password_end = (const uint8_t * const) k + STR_SIZE(k), \
        .encoded_salt = (const uint8_t * const) s, \
        .encoded_salt_end = (const uint8_t * const) s + STR_LEN(s), \
    }

typedef struct {
    int cost;
    size_t password_size;
    const uint8_t *password, *hash, *encoded_salt;
    const uint8_t * const hash_end;
    const uint8_t * const password_end;
    const uint8_t * const encoded_salt_end;
} test_vector_t;

static const test_vector_t vectors[] = {
    // https://github.com/patrickfav/bcrypt/wiki/Published-Test-Vectors
    E("", 4, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy"),
    E("", 5, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy"),
    E("", 6, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO"),
    E("", 7, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi"),
    E("", 8, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO"),
    E("<.S.2K(Zq'", 4, "VYAclAMpaXY/oqAo9yUpku", "$2a$04$VYAclAMpaXY/oqAo9yUpkuWmoYywaPzyhu56HxXpVltnBIfmO9tgu"),
    E("5.rApO%5jA", 5, "kVNDrnYKvbNr5AIcxNzeIu", "$2a$05$kVNDrnYKvbNr5AIcxNzeIuRcyIF5cZk6UrwHGxENbxP5dVv.WQM/G"),
    E("oW++kSrQW^", 6, "QLKkRMH9Am6irtPeSKN5sO", "$2a$06$QLKkRMH9Am6irtPeSKN5sObJGr3j47cO6Pdf5JZ0AsJXuze0IbsNm"),
    E("ggJ\\KbTnDG", 7, "4H896R09bzjhapgCPS/LYu", "$2a$07$4H896R09bzjhapgCPS/LYuMzAQluVgR5iu/ALF8L8Aln6lzzYXwbq"),
    E("49b0:;VkH/", 8, "hfvO2retKrSrx5f2RXikWe", "$2a$08$hfvO2retKrSrx5f2RXikWeFWdtSesPlbj08t/uXxCeZoHRWDz/xFe"),
    E(">9N^5jc##'", 9, "XZLvl7rMB3EvM0c1.JHivu", "$2a$09$XZLvl7rMB3EvM0c1.JHivuIDPJWeNJPTVrpjZIEVRYYB/mF6cYgJK"),
    E("\\$ch)s4WXp", 10, "aIjpMOLK5qiS9zjhcHR5TO", "$2a$10$aIjpMOLK5qiS9zjhcHR5TOU7v2NFDmcsBmSFDt5EHOgp/jeTF3O/q"),
    E("RYoj\\_>2P7", 12, "esIAHiQAJNNBrsr5V13l7.", "$2a$12$esIAHiQAJNNBrsr5V13l7.RFWWJI2BZFtQlkFyiWXjou05GyuREZa"),
    E("^Q&\"]A`%/A(BVGt>QaX0M-#<Q148&f", 4, "vrRP5vQxyD4LrqiLd/oWRO", "$2a$04$vrRP5vQxyD4LrqiLd/oWROgrrGINsw3gb4Ga5x2sn01jNmiLVECl6"),
    E("nZa!rRf\\U;OL;R?>1ghq_+\":Y0CRmY", 5, "YuQvhokOGVnevctykUYpKu", "$2a$05$YuQvhokOGVnevctykUYpKutZD2pWeGGYn3auyLOasguMY3/0BbIyq"),
    E("F%uN/j>[GuB7-jB'_Yj!Tnb7Y!u^6)", 6, "5L3vpQ0tG9O7k5gQ8nAHAe", "$2a$06$5L3vpQ0tG9O7k5gQ8nAHAe9xxQiOcOLh8LGcI0PLWhIznsDt.S.C6"),
    E("Z>BobP32ub\"Cfe*Q<<WUq3rc=[GJr-", 7, "hp8IdLueqE6qFh1zYycUZ.", "$2a$07$hp8IdLueqE6qFh1zYycUZ.twmUH8eSTPQAEpdNXKMlwms9XfKqfea"),
    E("Ik&8N['7*[1aCc1lOm8\\jWeD*H$eZM", 8, "2ANDTYCB9m7vf0Prh7rSru", "$2a$08$2ANDTYCB9m7vf0Prh7rSrupqpO3jJOkIz2oW/QHB4lCmK7qMytGV6"),
    E("O)=%3[E$*q+>-q-=tRSjOBh8\\mLNW.", 9, "nArqOfdCsD9kIbVnAixnwe", "$2a$09$nArqOfdCsD9kIbVnAixnwe6s8QvyPYWtQBpEXKir2OJF9/oNBsEFe"),
    E("/MH51`!BP&0tj3%YCA;Xk%e3S`o\\EI", 10, "ePiAc.s.yoBi3B6p1iQUCe", "$2a$10$ePiAc.s.yoBi3B6p1iQUCezn3mraLwpVJ5XGelVyYFKyp5FZn/y.u"),
    E("ptAP\"mcg6oH.\";c0U2_oll.OKi<!ku", 12, "aroG/pwwPj1tU5fl9a9pkO", "$2a$12$aroG/pwwPj1tU5fl9a9pkO4rydAmkXRj/LqfHZOSnR6LGAZ.z.jwa"),
    E("Q/A:k3DP;X@=<0\"hg&9c", 4, "wbgDTvLMtyjQlNK7fjqwyO", "$2a$04$wbgDTvLMtyjQlNK7fjqwyOakBoACQuYh11.VsKNarF4xUIOBWgD6S"),
    E("Q/A:k3DP;X@=<0\"hg&9c", 5, "zbAaOmloOhxiKItjznRqru", "$2a$05$zbAaOmloOhxiKItjznRqrunRqHlu3MAa7pMGv26Rr3WwyfGcwoRm6"),
    E("Q/A:k3DP;X@=<0\"hg&9c", 6, "aOK0bWUvLI0qLkc3ti5jyu", "$2a$06$aOK0bWUvLI0qLkc3ti5jyuAIQoqRzuqoK09kQqQ6Ou/YKDhW50/qa"),
    E("o<&+X'F4AQ8H,LU,N`&r", 4, "BK5u.QHk1Driey7bvnFTH.", "$2a$04$BK5u.QHk1Driey7bvnFTH.3smGwxd91PtoK2GxH5nZ7pcBsYX4lMq"),
    E("o<&+X'F4AQ8H,LU,N`&r", 5, "BK5u.QHk1Driey7bvnFTH.", "$2a$05$BK5u.QHk1Driey7bvnFTH.t5P.jZvFBMzDB1IY4PwkkRPOyVbEtFG"),
    E("o<&+X'F4AQ8H,LU,N`&r", 6, "BK5u.QHk1Driey7bvnFTH.", "$2a$06$BK5u.QHk1Driey7bvnFTH.6Ea1Z5db2p25CPXZbxb/3OyKQagg3pa"),
    E("o<&+X'F4AQ8H,LU,N`&r", 7, "BK5u.QHk1Driey7bvnFTH.", "$2a$07$BK5u.QHk1Driey7bvnFTH.sruuQi8Lhv/0LWKDvNp3AGFk7ltdkm6"),
    E("o<&+X'F4AQ8H,LU,N`&r", 8, "BK5u.QHk1Driey7bvnFTH.", "$2a$08$BK5u.QHk1Driey7bvnFTH.IE7KsaUzc4m7gzAMlyUPUeiYyACWe0q"),
    E("o<&+X'F4AQ8H,LU,N`&r", 9, "BK5u.QHk1Driey7bvnFTH.", "$2a$09$BK5u.QHk1Driey7bvnFTH.1v4Xj1dwkp44QNg0cVAoQt4FQMMrvnS"),
    E("o<&+X'F4AQ8H,LU,N`&r", 10, "BK5u.QHk1Driey7bvnFTH.", "$2a$10$BK5u.QHk1Driey7bvnFTH.ESINe9YntUMcVgFDfkC.Vbhc9vMhNX2"),
    E("o<&+X'F4AQ8H,LU,N`&r", 12, "BK5u.QHk1Driey7bvnFTH.", "$2a$12$BK5u.QHk1Driey7bvnFTH.QM1/nnGe/f5cTzb6XTTi/vMzcAnycqG"),
    E("g*3Q45=\"8NNgpT&mbMJ$Omfr.#ZeW?FP=CE$#roHd?97uL0F-]`?u73c\"\\[.\"*)qU34@VG", 4, "T2XJ5MOWvHQZRijl8LIKkO", "$2a$04$T2XJ5MOWvHQZRijl8LIKkOQKIyX75KBfuLsuRYOJz5OjwBNF2lM8a"),
    E("\\M+*8;&QE=Ll[>5?Ui\"^ai#iQH7ZFtNMfs3AROnIncE9\"BNNoEgO[[*Yk8;RQ(#S,;I+aT", 5, "wgkOlGNXIVE2fWkT3gyRoO", "$2a$05$wgkOlGNXIVE2fWkT3gyRoOqWi4gbi1Wv2Q2Jx3xVs3apl1w.Wtj8C"),
    E("M.E1=dt<.L0Q&p;94NfGm_Oo23+Kpl@M5?WIAL.[@/:'S)W96G8N^AWb7_smmC]>7#fGoB", 6, "W9zTCl35nEvUukhhFzkKMe", "$2a$06$W9zTCl35nEvUukhhFzkKMekjT9/pj7M0lihRVEZrX3m8/SBNZRX7i"),
    E("a", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.l4WvgHIVg17ZawDIrDM2IjlE64GDNQS"),
    E("aa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.AyUxBk.ThHlsLvRTH7IqcG7yVHJ3SXq"),
    E("aaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.BxOVac5xPB6XFdRc/ZrzM9FgZkqmvbW"),
    E("aaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.Qbr209bpCtfl5hN7UQlG/L4xiD3AKau"),
    E("aaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.oWszihPjDZI0ypReKsaDOW1jBl7oOii"),
    E("aaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ./k.Xxn9YiqtV/sxh3EHbnOHd0Qsq27K"),
    E("aaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.PYJqRFQbgRbIjMd5VNKmdKS4sBVOyDe"),
    E("aaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ..VMYfzaw1wP/SGxowpLeGf13fxCCt.q"),
    E("aaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.5B0p054nO5WgAD1n04XslDY/bqY9RJi"),
    E("aaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.INBTgqm7sdlBJDg.J5mLMSRK25ri04y"),
    E("aaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.s3y7CdFD0OR5p6rsZw/eZ.Dla40KLfm"),
    E("aaaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.Jx742Djra6Q7PqJWnTAS.85c28g.Siq"),
    E("aaaaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.oKMXW3EZcPHcUV0ib5vDBnh9HojXnLu"),
    E("aaaaaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.w6nIjWpDPNSH5pZUvLjC1q25ONEQpeS"),
    E("aaaaaaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.k1b2/r9A/hxdwKEKurg6OCn4MwMdiGq"),
    E("aaaaaaaaaaaaaaaa", 4, "5DCebwootqWMCp59ISrMJ.", "$2a$04$5DCebwootqWMCp59ISrMJ.3prCNHVX1Ws.7Hm2bJxFUnQOX9f7DFa"),
    E("àèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝðÐ", 4, "D3qS2aoTVyqM7z8v8crLm.", "$2a$04$D3qS2aoTVyqM7z8v8crLm.3nKt4CzBZJbyFB.ZebmfCvRw7BGs.Xm"),
    E("àèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝðÐ", 5, "VA1FujiOCMPkUHQ8kF7IaO", "$2a$05$VA1FujiOCMPkUHQ8kF7IaOg7NGaNvpxwWzSluQutxEVmbZItRTsAa"),
    E("àèìòùÀÈÌÒÙáéíóúýÁÉÍÓÚÝðÐ", 6, "TXiaNrPeBSz5ugiQlehRt.", "$2a$06$TXiaNrPeBSz5ugiQlehRt.gwpeDQnXWteQL4z2FulouBr6G7D9KUi"),
    E("âêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿ", 4, "YTn1Qlvps8e1odqMn6G5x.", "$2a$04$YTn1Qlvps8e1odqMn6G5x.85pqKql6w773EZJAExk7/BatYAI4tyO"),
    E("âêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿ", 5, "C.8k5vJKD2NtfrRI9o17DO", "$2a$05$C.8k5vJKD2NtfrRI9o17DOfIW0XnwItA529vJnh2jzYTb1QdoY0py"),
    E("âêîôûÂÊÎÔÛãñõÃÑÕäëïöüÿ", 6, "xqfRPj3RYAgwurrhcA6uRO", "$2a$06$xqfRPj3RYAgwurrhcA6uROtGlXDp/U6/gkoDYHwlubtcVcNft5.vW"),
    E("ÄËÏÖÜŸåÅæÆœŒßçÇøØ¢¿¡€", 4, "y8vGgMmr9EdyxP9rmMKjH.", "$2a$04$y8vGgMmr9EdyxP9rmMKjH.wv2y3r7yRD79gykQtmb3N3zrwjKsyay"),
    E("ÄËÏÖÜŸåÅæÆœŒßçÇøØ¢¿¡€", 5, "iYH4XIKAOOm/xPQs7xKP1u", "$2a$05$iYH4XIKAOOm/xPQs7xKP1upD0cWyMn3Jf0ZWiizXbEkVpS41K1dcO"),
    E("ÄËÏÖÜŸåÅæÆœŒßçÇøØ¢¿¡€", 6, "wCOob.D0VV8twafNDB2ape", "$2a$06$wCOob.D0VV8twafNDB2apegiGD5nqF6Y1e6K95q6Y.R8C4QGd265q"),
    E("ΔημοσιεύθηκεστηνΕφημερίδατης", 4, "E5SQtS6P4568MDXW7cyUp.", "$2a$04$E5SQtS6P4568MDXW7cyUp.18wfDisKZBxifnPZjAI1d/KTYMfHPYO"),
    E("АБбВвГгДдЕеЁёЖжЗзИиЙйКкЛлМмН", 4, "03e26gQFHhQwRNf81/ww9.", "$2a$04$03e26gQFHhQwRNf81/ww9.p1UbrNwxpzWjLuT.zpTLH4t/w5WhAhC"),
    E("нОоПпРрСсТтУуФфХхЦцЧчШшЩщЪъЫыЬьЭэЮю", 4, "PHNoJwpXCfe32nUtLv2Upu", "$2a$04$PHNoJwpXCfe32nUtLv2UpuhJXOzd4k7IdFwnEpYwfJVCZ/f/.8Pje"),
    E("電电電島岛島兔兔兎龜龟亀國国国區区区", 4, "wU4/0i1TmNl2u.1jIwBX.u", "$2a$04$wU4/0i1TmNl2u.1jIwBX.uZUaOL3Rc5ID7nlQRloQh6q5wwhV/zLW"),
    E("诶比伊艾弗豆贝尔维吾艾尺开艾丝维贼德", 4, "P4kreGLhCd26d4WIy7DJXu", "$2a$04$P4kreGLhCd26d4WIy7DJXusPkhxLvBouzV6OXkL5EB0jux0osjsry"),
    E("-O_=*N!2JP", 4, "......................", "$2a$04$......................JjuKLOX9OOwo5PceZZXSkaLDvdmgb82"),
    E("7B[$Q<4b>U", 5, "......................", "$2a$05$......................DRiedDQZRL3xq5A5FL8y7/6NM8a2Y5W"),
    E(">d5-I_8^.h", 6, "......................", "$2a$06$......................5Mq1Ng8jgDY.uHNU4h5p/x6BedzNH2W"),
    E(")V`/UM/]1t", 4, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$04$.OC/.OC/.OC/.OC/.OC/.OQIvKRDAam.Hm5/IaV/.hc7P8gwwIbmi"),
    E(":@t2.bWuH]", 5, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$05$.OC/.OC/.OC/.OC/.OC/.ONDbUvdOchUiKmQORX6BlkPofa/QxW9e"),
    E("b(#KljF5s\"", 6, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$06$.OC/.OC/.OC/.OC/.OC/.OHfTd9e7svOu34vi1PCvOcAEq07ST7.K"),
    E("@3YaJ^Xs]*", 4, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$04$eGA.eGA.eGA.eGA.eGA.e.stcmvh.R70m.0jbfSFVxlONdj1iws0C"),
    E("'\"5\\!k*C(p", 5, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$05$eGA.eGA.eGA.eGA.eGA.e.vR37mVSbfdHwu.F0sNMvgn8oruQRghy"),
    E("edEu7C?$'W", 6, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$06$eGA.eGA.eGA.eGA.eGA.e.tSq0FN8MWHQXJXNFnHTPQKtA.n2a..G"),
    E("N7dHmg\\PI^", 4, "999999999999999999999u", "$2a$04$999999999999999999999uCZfA/pLrlyngNDMq89r1uUk.bQ9icOu"),
    E("\"eJuHh!)7*", 5, "999999999999999999999u", "$2a$05$999999999999999999999uj8Pfx.ufrJFAoWFLjapYBS5vVEQQ/hK"),
    E("ZeDRJ:_tu:", 6, "999999999999999999999u", "$2a$06$999999999999999999999u6RB0P9UmbdbQgjoQFEJsrvrKe.BoU6q"),
    // https://github.com/patrickfav/bcrypt/blob/master/modules/bcrypt/src/test/java/at/favre/lib/crypto/bcrypt/BcryptTest.java
    // see: https://stackoverflow.com/a/12761326/774398
    E("ππππππππ", 10, ".TtQJ4Jr6isd4Hp.mVfZeu", "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle"),
    // see: http://openwall.info/wiki/john/sample-hashes
    E("password", 5, "bvIG6Nmid91Mu9RcmmWZfO", "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"),
    // see: http://cvsweb.openwall.com/cgi/cvsweb.cgi/Owl/packages/glibc/crypt_blowfish/wrapper.c?rev=HEAD
    E("U*U", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
    E("U*U*", 5, "CCCCCCCCCCCCCCCCCCCCC.", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"),
    E("U*U*U", 5, "XXXXXXXXXXXXXXXXXXXXXO", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"),
    E("", 6, "DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."),
    // see: https://bitbucket.org/vadim/bcrypt.net/src/464c41416dc9/BCrypt.Net.Test/TestBCrypt.cs?fileviewer=file-view-default
    E("", 8, "HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"),
    E("", 10, "k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"),
    E("", 12, "k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"),
    E("a", 6, "m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"),
    E("a", 8, "cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."),
    E("a", 10, "k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"),
    E("a", 12, "8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"),
    E("abc", 6, "If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"),
    E("abc", 8, "Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"),
    E("abc", 10, "WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"),
    E("abc", 12, "EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"),
    E("abcdefghijklmnopqrstuvwxyz", 6, ".rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"),
    E("abcdefghijklmnopqrstuvwxyz", 8, "aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."),
    E("abcdefghijklmnopqrstuvwxyz", 10, "fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"),
    E("abcdefghijklmnopqrstuvwxyz", 12, "D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"),
    E("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 6, "fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"),
    E("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 8, "Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"),
    E("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 10, "LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"),
    E("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", 12, "WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"),
};

void bcrypt_known_vectors_test(void)
{
    uint8_t raw_salt[MAX_RAW_SALT_LEN], hash[BCRYPT_HASHSPACE - 1], encoded_salt[BCRYPT_SALTSPACE];

    const uint8_t * const hash_end = hash + STR_SIZE(hash);
    const uint8_t * const raw_salt_end = raw_salt + STR_SIZE(raw_salt);
    const uint8_t * const encoded_salt_end = encoded_salt + STR_SIZE(encoded_salt);

    for (i = 0; i < ARRAY_SIZE(vectors); i++) {
        int minor, cost;
        uint8_t salt[MAX_RAW_SALT_LEN];

        erase_buffer(hash, hash_end);
        p = bcrypt_hash(vectors[i].password, vectors[i].password_end, vectors[i].hash, vectors[i].hash_end, hash, hash_end);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_MEMORY(vectors[i].hash, hash, STR_SIZE(hash));

        erase_buffer(encoded_salt, encoded_salt_end);
        p = decode_base64(vectors[i].encoded_salt, vectors[i].encoded_salt_end, raw_salt, raw_salt_end);
        TEST_ASSERT_NOT_NULL(p);
        p = bcrypt_init_salt('a', vectors[i].cost, raw_salt, raw_salt_end, encoded_salt, encoded_salt_end);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_MEMORY(vectors[i].hash, encoded_salt, STR_SIZE(encoded_salt));

        erase_buffer(hash, hash_end);
        p = bcrypt_hash(vectors[i].password, vectors[i].password_end, encoded_salt, encoded_salt_end, hash, hash_end);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_MEMORY(vectors[i].hash, hash, STR_SIZE(hash));

        p = bcrypt_full_parse_hash(encoded_salt, encoded_salt_end, &minor, &cost, salt, salt + STR_SIZE(salt));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_PTR(p, salt + BCRYPT_MAXSALT);
        TEST_ASSERT_EQUAL('a', minor);
        TEST_ASSERT_EQUAL(vectors[i].cost, cost);
        TEST_ASSERT_EQUAL_MEMORY(raw_salt, salt, STR_SIZE(salt));
    }
}

// password truncation to 72 bytes
void bcrypt_hash_72th_key_truncation_test(void)
{
    size_t j;
    uint8_t /*previous[BCRYPT_HASHSPACE - 1], */buffer[BCRYPT_HASHSPACE - 1];
    const char *hashes[] = {
        "$2a$04$chZnvt4tXyL8nFE7ZtwHXuBRjkLxlMSIjuVYNJ2qFowacMerZyQGu",
        "$2y$04$chZnvt4tXyL8nFE7ZtwHXuBRjkLxlMSIjuVYNJ2qFowacMerZyQGu",
        "$2b$04$chZnvt4tXyL8nFE7ZtwHXuBRjkLxlMSIjuVYNJ2qFowacMerZyQGu",
    };
    const char *passwords[] = {
        "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", // 72
        "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890a", // 73
        "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    };
//     const uint8_t *salt2a = (const uint8_t *) "$2a$04$......................";
    char password71[] = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";

    for (i = 0; i < ARRAY_SIZE(hashes); i++) {
        for (j = 0; j < ARRAY_SIZE(passwords); j++) {
            erase_buffer(buffer, buffer + sizeof(buffer));
            p = bcrypt_hash((const uint8_t *) passwords[j], (const uint8_t * const) (passwords[j] + strlen(passwords[j]) + 1), (const uint8_t *) hashes[i], (const uint8_t * const) (hashes[i] + strlen(hashes[i])), buffer, buffer + STR_SIZE(buffer));
            TEST_ASSERT_NOT_NULL(p);
            TEST_ASSERT_EQUAL_MEMORY(hashes[i], buffer, strlen(hashes[i]));
        }

        erase_buffer(buffer, buffer + sizeof(buffer));
        p = bcrypt_hash((const uint8_t *) password71, (const uint8_t * const) (password71 + STR_SIZE(password71)), (const uint8_t *) hashes[i], (const uint8_t * const) (hashes[i] + strlen(hashes[i])), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT(0 != memcmp(buffer, hashes[i], STR_SIZE(buffer)));
    }
#if 0
    erase_buffer(previous, previous + sizeof(previous));
    for (j = 0; j < ARRAY_SIZE(passwords); j++) {
        erase_buffer(buffer, buffer + sizeof(buffer));
        p = bcrypt_hash((const uint8_t *) passwords[j], (const uint8_t * const) (passwords[j] + strlen(passwords[j]) + 1), salt2a, salt2a + strlen(salt2a), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
//         printf(">%.*s<\n", STR_SIZE(buffer), buffer);
        TEST_ASSERT(0 != memcmp(buffer, previous, STR_SIZE(buffer)));
        memcpy(previous, buffer, STR_SIZE(previous));
    }
#endif
}

void bcrypt_hash_72th_key_truncation_test_bis(void)
{
    size_t j;
    uint8_t buffer[BCRYPT_HASHSPACE - 1];
    const char *hashes[] = {
        "$2a$04$......................UaUp2CqHXn14N7RprrzoDsNv91ahi36",
        "$2b$04$......................UaUp2CqHXn14N7RprrzoDsNv91ahi36",
    };
    const char *passwords[] = {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 72
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 73
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 254
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 255
    };
    char password71[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 71

    for (i = 0; i < ARRAY_SIZE(hashes); i++) {
        erase_buffer(buffer, buffer + sizeof(buffer));
        p = bcrypt_hash((const uint8_t *) password71, (const uint8_t * const) (password71 + STR_SIZE(password71)), (const uint8_t *) hashes[i], (const uint8_t * const) (hashes[i] + strlen(hashes[i])), buffer, buffer + STR_SIZE(buffer));
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT(0 != memcmp(buffer, password71, STR_SIZE(password71)));
        for (j = 0; j < ARRAY_SIZE(passwords); j++) {
            erase_buffer(buffer, buffer + sizeof(buffer));
            p = bcrypt_hash((const uint8_t *) passwords[j], (const uint8_t * const) (passwords[j] + strlen(passwords[j]) + 1), (const uint8_t *) hashes[i], (const uint8_t * const) (hashes[i] + strlen(hashes[i])), buffer, buffer + STR_SIZE(buffer));
            TEST_ASSERT_NOT_NULL(p);
            TEST_ASSERT_EQUAL_MEMORY(hashes[i], buffer, strlen(hashes[i]));
        }
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
    UNITY_PRINT_EOL();
    RUN_TEST(bcrypt_known_vectors_test);
    RUN_TEST(bcrypt_hash_72th_key_truncation_test);
    RUN_TEST(bcrypt_hash_72th_key_truncation_test_bis);

    return UNITY_END();
}
