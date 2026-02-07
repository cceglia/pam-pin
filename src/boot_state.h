#ifndef PAM_PIN_BOOT_STATE_H
#define PAM_PIN_BOOT_STATE_H

#include <sys/types.h>

int boot_state_should_use_pin(uid_t uid, const char *state_dir, int *use_pin);
int boot_state_mark_session(uid_t uid, const char *state_dir);

#endif
