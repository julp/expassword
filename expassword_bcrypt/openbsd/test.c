#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>

char *a(size_t length) {
    size_t i;
    char *w, *string;

    string = malloc(sizeof(*string) * (length + 1));
    for (i = 0, w = string; i < length; i++, w++) {
        *w = 'a';
    }
    *w = '\0';

    return string;
}

void test(size_t length, const char *salt)
{
    char *h, *pwd;

    pwd = a(length);
    h = bcrypt(pwd, salt);
    printf("%zu 'a' (+ 0) = >%s<\n", length, h);
    free(pwd);
}

void test_by_range(size_t min, size_t max, const char *salt)
{
    size_t i;

    for (i = min; i <= max; i++) {
        test(i, salt);
    }
}

int main(int argc, char **argv)
{
    if (2 != argc) {
        fprintf(stderr, "expected salt as (only) argument\n");
        return EXIT_FAILURE;
    }

    test_by_range(71, 74, argv[1]);
    test_by_range(253, 256, argv[1]);

    return EXIT_SUCCESS;
}
