#ifndef PAM_PIN_CRYPTO_H
#define PAM_PIN_CRYPTO_H

#include <stddef.h>

void crypto_secure_bzero(void *ptr, size_t len);
int crypto_pin_format_valid(const char *pin, int min_len, int max_len);
int crypto_verify_pin_hash(const char *pin, const char *stored_hash);

#endif
