#pragma once

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

#define BCRYPT_MAXSALT 16	/* Precomputation is just so nice */
// NOTE: "+ 1" is commented because we don't count the \0
#define	BCRYPT_SALTSPACE	(STR_LEN("$vm$cc$") + (BCRYPT_MAXSALT * 4 + 2) / 3/* + 1*/)
#define	BCRYPT_HASHSPACE	61
