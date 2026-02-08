#include "crypto.h"

#include <crypt.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

/* Wipe a buffer using a compiler-resistant zeroing method. */
void crypto_secure_bzero(void *ptr, size_t len)
{
    /* Zero sensitive buffers in a way the compiler should not optimize out. */
#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
#endif
}

/* Compare two strings in a timing-safe way when lengths match. */
static int timing_safe_equal(const char *a, const char *b)
{
    size_t la;
    size_t lb;
    size_t max_len;
    size_t i;
    unsigned char diff = 0;

    /* Constant-time style compare for equal-length strings. */
    if (a == NULL || b == NULL) {
        return 0;
    }

    la = strlen(a);
    lb = strlen(b);
    max_len = (la > lb) ? la : lb;

    for (i = 0; i < max_len; ++i) {
        unsigned char ca = (i < la) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < lb) ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }

    return diff == 0 && la == lb;
}

/* Validate that a PIN is numeric and within configured bounds. */
int crypto_pin_format_valid(const char *pin, int min_len, int max_len)
{
    size_t i;
    size_t len;
    int ok = 1;

    /* Accept only decimal digits within configured length bounds. */
    if (pin == NULL) {
        return 0;
    }

    len = strlen(pin);
    if (len < (size_t)min_len || len > (size_t)max_len) {
        ok = 0;
    }

    for (i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)pin[i])) {
            ok = 0;
        }
    }

    return ok;
}

/* Verify a PIN against a stored hash using crypt(3). */
int crypto_verify_pin_hash(const char *pin, const char *stored_hash)
{
    struct crypt_data data;
    char *computed;
    int ok;

    /* Re-hash the candidate PIN using the hash's own algorithm/salt prefix. */
    if (pin == NULL || stored_hash == NULL || *stored_hash == '\0') {
        return 0;
    }

    memset(&data, 0, sizeof(data));
    computed = crypt_r(pin, stored_hash, &data);
    if (computed == NULL) {
        crypto_secure_bzero(&data, sizeof(data));
        return 0;
    }

    ok = timing_safe_equal(computed, stored_hash);
    /* Wipe crypt_r working data regardless of verification result. */
    crypto_secure_bzero(&data, sizeof(data));
    return ok;
}
