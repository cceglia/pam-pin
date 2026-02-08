#ifndef PAM_PIN_RETRY_STORE_H
#define PAM_PIN_RETRY_STORE_H

int retry_store_read(const char *retry_dir, const char *username, int *count_out);
int retry_store_increment(const char *retry_dir, const char *username, int *count_out);
int retry_store_clear(const char *retry_dir, const char *username);

#endif
