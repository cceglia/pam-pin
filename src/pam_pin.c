#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "crypto.h"
#include "options.h"
#include "pin_store.h"
#include "retry_store.h"

#define PAM_PIN_RETRY_CLEANUP_KEY "pam_pin_retry_cleanup"

typedef struct retry_cleanup_data {
    char retry_dir[PATH_MAX];
    char username[256];
    int debug;
} retry_cleanup_data;

static void maybe_log_debug(pam_handle_t *pamh, const module_options *opts, const char *msg)
{
    /* Emit debug logs only when the module is explicitly configured with debug. */
    if (opts->debug) {
        pam_syslog(pamh, LOG_DEBUG, "%s", msg);
    }
}

static void retry_cleanup(pam_handle_t *pamh, void *data, int pam_status)
{
    retry_cleanup_data *info = (retry_cleanup_data *)data;

    (void)pamh;

    if (info == NULL) {
        return;
    }

    if (pam_status == PAM_SUCCESS) {
        (void)retry_store_clear(info->retry_dir, info->username);
    }

    free(info);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    module_options opts;
    const char *user = NULL;
    const char *token = NULL;
    int pam_rc;
    int lookup_rc;
    char *stored_hash = NULL;
    int attempt;
    int retry_count = 0;

    (void)flags;

    /* Load module defaults first, then override them with PAM arguments. */
    options_set_defaults(&opts);
    options_parse(&opts, argc, argv);

    pam_rc = pam_get_user(pamh, &user, NULL);
    if (pam_rc != PAM_SUCCESS || user == NULL || *user == '\0') {
        maybe_log_debug(pamh, &opts, "pam_pin: no valid user, fallback to next module");
        return PAM_IGNORE;
    }

    lookup_rc = pin_store_lookup_hash(opts.pin_db, user, &stored_hash);
    if (lookup_rc <= 0) {
        maybe_log_debug(pamh, &opts, "pam_pin: no PIN entry or db issue, fallback to next module");
        return PAM_IGNORE;
    }

    {
        const void *existing = NULL;
        if (pam_get_data(pamh, PAM_PIN_RETRY_CLEANUP_KEY, &existing) != PAM_SUCCESS) {
            retry_cleanup_data *info = (retry_cleanup_data *)calloc(1, sizeof(*info));
            if (info != NULL) {
                (void)strncpy(info->retry_dir, opts.retry_dir, sizeof(info->retry_dir) - 1);
                info->retry_dir[sizeof(info->retry_dir) - 1] = '\0';
                (void)strncpy(info->username, user, sizeof(info->username) - 1);
                info->username[sizeof(info->username) - 1] = '\0';
                info->debug = opts.debug;
                if (pam_set_data(pamh, PAM_PIN_RETRY_CLEANUP_KEY, info, retry_cleanup) != PAM_SUCCESS) {
                    free(info);
                }
            }
        }
    }

    if (retry_store_read(opts.retry_dir, user, &retry_count) != 0) {
        maybe_log_debug(pamh, &opts, "pam_pin: retry store unavailable, fallback to next module");
        free(stored_hash);
        return PAM_IGNORE;
    }

    {
        int remaining = opts.max_tries - retry_count;
        if (remaining < 0) {
            remaining = 0;
        }

        if (remaining == 0) {
            maybe_log_debug(pamh, &opts, "pam_pin: retry limit reached, fallback to password");
            free(stored_hash);
            return PAM_IGNORE;
        }

        /*
         * Prompt once per remaining attempt using a shared "PIN or Password" field.
         * If the token is not a numeric PIN, immediately fall through so the next
         * module (typically pam_unix with try_first_pass) can treat it as password.
         */
        for (attempt = 1; attempt <= remaining; ++attempt) {
            int verified;

            pam_rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, "PIN or Password");
            if (pam_rc != PAM_SUCCESS || token == NULL) {
                maybe_log_debug(pamh, &opts, "pam_pin: prompt failed, fallback to next module");
                free(stored_hash);
                return PAM_IGNORE;
            }

            if (!crypto_pin_format_valid(token, opts.pin_min_len, opts.pin_max_len)) {
                maybe_log_debug(pamh, &opts, "pam_pin: non-PIN token, fallback to password module");
                free(stored_hash);
                return PAM_IGNORE;
            }

            verified = crypto_verify_pin_hash(token, stored_hash);

            if (verified) {
                maybe_log_debug(pamh, &opts, "pam_pin: PIN accepted");
                (void)retry_store_clear(opts.retry_dir, user);
                free(stored_hash);
                return PAM_SUCCESS;
            }

            if (retry_store_increment(opts.retry_dir, user, &retry_count) != 0) {
                maybe_log_debug(pamh, &opts, "pam_pin: failed to persist retry count, fallback to password");
                free(stored_hash);
                return PAM_IGNORE;
            }

            /* Clear cached authtok so a wrong PIN is not reused by downstream modules. */
            if (pam_set_item(pamh, PAM_AUTHTOK, NULL) != PAM_SUCCESS) {
                free(stored_hash);
                return PAM_IGNORE;
            }

            /* Apply a linear backoff delay to slow down online brute-force attempts. */
            if (opts.fail_delay_ms > 0) {
                uint64_t delay_us64 = (uint64_t)opts.fail_delay_ms * (uint64_t)retry_count * 1000ULL;
                unsigned int delay_us = (delay_us64 > (uint64_t)UINT_MAX) ? UINT_MAX : (unsigned int)delay_us64;
                pam_fail_delay(pamh, delay_us);
            }
        }
    }

    maybe_log_debug(pamh, &opts, "pam_pin: PIN attempts exceeded, fallback to password");
    free(stored_hash);
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    module_options opts;
    const char *user = NULL;
    const void *retry_data = NULL;
    const char *retry_user = NULL;

    (void)flags;

    options_set_defaults(&opts);
    options_parse(&opts, argc, argv);

    if (pam_get_data(pamh, PAM_PIN_RETRY_CLEANUP_KEY, &retry_data) == PAM_SUCCESS && retry_data != NULL) {
        const retry_cleanup_data *info = (const retry_cleanup_data *)retry_data;
        if (info->username[0] != '\0') {
            retry_user = info->username;
        }
    }

    if (retry_user == NULL) {
        if (pam_get_user(pamh, &user, NULL) == PAM_SUCCESS && user != NULL && *user != '\0') {
            retry_user = user;
        }
    }

    if (retry_user != NULL) {
        if (retry_store_clear(opts.retry_dir, retry_user) != 0) {
            maybe_log_debug(pamh, &opts, "pam_pin: retry cleanup failed in setcred");
        }
    }
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;
    (void)pamh;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
