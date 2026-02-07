#ifndef PAM_PIN_STORE_H
#define PAM_PIN_STORE_H

int pin_store_lookup_hash(const char *db_path, const char *username, char **hash_out);

#endif
