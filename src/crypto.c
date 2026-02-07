#include "crypto.h"

#include <crypt.h>
#include <ctype.h>
#include <stddef.h>
#include <string.h>

void crypto_secure_bzero(void *ptr, size_t len)
{
#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
#endif
}

static int timing_safe_equal(const char *a, const char *b)
{
    size_t la;
    size_t lb;
    size_t i;
    unsigned char diff = 0;

    if (a == NULL || b == NULL) {
        return 0;
    }

    la = strlen(a);
    lb = strlen(b);
    if (la != lb) {
        return 0;
    }

    for (i = 0; i < la; ++i) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }

    return diff == 0;
}

int crypto_pin_format_valid(const char *pin, int min_len, int max_len)
{
    size_t i;
    size_t len;

    if (pin == NULL) {
        return 0;
    }

    len = strlen(pin);
    if (len < (size_t)min_len || len > (size_t)max_len) {
        return 0;
    }

    for (i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)pin[i])) {
            return 0;
        }
    }

    return 1;
}

int crypto_verify_pin_hash(const char *pin, const char *stored_hash)
{
    struct crypt_data data;
    char *computed;
    int ok;

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
    crypto_secure_bzero(&data, sizeof(data));
    return ok;
}
