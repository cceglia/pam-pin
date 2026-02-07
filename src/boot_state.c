#include "boot_state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"

static int read_boot_id(char *buf, size_t len)
{
    FILE *fp;

    if (len < 8) {
        return -1;
    }

    fp = fopen(BOOT_ID_PATH, "re");
    if (fp == NULL) {
        return -1;
    }

    if (fgets(buf, (int)len, fp) == NULL) {
        (void)fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    buf[strcspn(buf, "\r\n")] = '\0';
    if (buf[0] == '\0') {
        return -1;
    }

    return 0;
}

static int ensure_state_dir(const char *state_dir)
{
    struct stat st;

    if (lstat(state_dir, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            return -1;
        }

        if (!S_ISDIR(st.st_mode)) {
            return -1;
        }

        if (st.st_uid != 0) {
            return -1;
        }

        if ((st.st_mode & 0777) != 0700 && chmod(state_dir, 0700) != 0) {
            return -1;
        }

        return 0;
    }

    if (errno != ENOENT) {
        return -1;
    }

    if (mkdir(state_dir, 0700) != 0) {
        return -1;
    }

    if (lstat(state_dir, &st) != 0) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode) || st.st_uid != 0) {
        return -1;
    }

    if ((st.st_mode & 0777) != 0700 && chmod(state_dir, 0700) != 0) {
        return -1;
    }

    return 0;
}

static int build_state_path(char *out, size_t out_len, const char *state_dir, uid_t uid)
{
    int n = snprintf(out, out_len, "%s/%lu.state", state_dir, (unsigned long)uid);
    if (n < 0 || (size_t)n >= out_len) {
        return -1;
    }
    return 0;
}

int boot_state_should_use_pin(uid_t uid, const char *state_dir, int *use_pin)
{
    char boot_id[128];
    char state_path[PATH_MAX];
    FILE *fp;
    char line[128];

    *use_pin = 0;

    if (read_boot_id(boot_id, sizeof(boot_id)) != 0) {
        return -1;
    }

    if (build_state_path(state_path, sizeof(state_path), state_dir, uid) != 0) {
        return -1;
    }

    fp = fopen(state_path, "re");
    if (fp == NULL) {
        if (errno == ENOENT) {
            *use_pin = 0;
            return 0;
        }
        return -1;
    }

    if (fgets(line, (int)sizeof(line), fp) == NULL) {
        (void)fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, boot_id) == 0) {
        *use_pin = 1;
    }

    return 0;
}

int boot_state_mark_session(uid_t uid, const char *state_dir)
{
    char boot_id[128];
    char final_path[PATH_MAX];
    char temp_template[PATH_MAX];
    int fd;
    ssize_t wr;
    size_t len;

    if (read_boot_id(boot_id, sizeof(boot_id)) != 0) {
        return -1;
    }

    if (ensure_state_dir(state_dir) != 0) {
        return -1;
    }

    if (build_state_path(final_path, sizeof(final_path), state_dir, uid) != 0) {
        return -1;
    }

    if (snprintf(temp_template, sizeof(temp_template), "%s/.%lu.tmpXXXXXX",
                 state_dir, (unsigned long)uid) >= (int)sizeof(temp_template)) {
        return -1;
    }

    fd = mkstemp(temp_template);
    if (fd < 0) {
        return -1;
    }

    if (fchmod(fd, 0600) != 0) {
        (void)close(fd);
        (void)unlink(temp_template);
        return -1;
    }

    len = strlen(boot_id);
    wr = write(fd, boot_id, len);
    if (wr < 0 || (size_t)wr != len) {
        (void)close(fd);
        (void)unlink(temp_template);
        return -1;
    }

    wr = write(fd, "\n", 1);
    if (wr != 1) {
        (void)close(fd);
        (void)unlink(temp_template);
        return -1;
    }

    if (fsync(fd) != 0) {
        (void)close(fd);
        (void)unlink(temp_template);
        return -1;
    }

    if (close(fd) != 0) {
        (void)unlink(temp_template);
        return -1;
    }

    if (rename(temp_template, final_path) != 0) {
        (void)unlink(temp_template);
        return -1;
    }

    return 0;
}
