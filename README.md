# PAM_PIN module

## Project Overview

`pam_pin.so` is a custom PAM authentication module that allows users to log in with a numeric PIN.
It is designed to work together with standard password authentication (`pam_unix`) using a single prompt.

The module is intended for Linux systems and can be integrated into PAM stacks such as:

- GDM login (`/etc/pam.d/gdm-password`)
- SDDM login (`/etc/pam.d/sddm`)
- `sudo` authentication (`/etc/pam.d/sudo`)

## What It Does

- Prompts with a single auth field: `PIN or Password`
- If the input is a valid PIN format and the PIN hash matches the user entry in the PIN DB, authentication succeeds immediately
- If the input is not a PIN (or PIN attempts are exhausted), it falls back to the next PAM module (typically password via `pam_unix`)
- Supports configurable options such as `max_tries`, `fail_delay_ms`, `pin_min_len`, and `pin_max_len`

Recommended PAM lines:

```pam
auth    [success=done default=ignore]   pam_pin.so max_tries=3 pin_db=/etc/security/pam_pin.db fail_delay_ms=500
auth    sufficient                       pam_unix.so try_first_pass
```

## Installation

### 1) Prerequisites (Any Distribution)

Install the required build tools and PAM development headers using your distro package manager.

`gcc` and `make` are always required. You also need Linux-PAM development files and `libcrypt` development files.

Examples:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install build-essential libpam0g-dev libxcrypt-dev whois

# Fedora/RHEL/CentOS/Alma/Rocky
sudo dnf install gcc make pam-devel libxcrypt-devel whois

# Arch Linux
sudo pacman -S --needed base-devel pam libxcrypt whois

# openSUSE
sudo zypper install gcc make pam-devel libxcrypt-devel whois
```

If `mkpasswd` is not available on your distro, you can still generate hashes with `openssl passwd` (see section 7).

### 2) Build the Module

From the repository root:

```bash
make
```

### 3) Detect PAM Module Directory

The PAM module path is distro-dependent. Common values are:

- `/usr/lib/security`
- `/usr/lib64/security`
- `/lib/security`
- `/lib64/security`

Detect it automatically:

```bash
PAM_MODULE_DIR="$(pkg-config --variable=securedir pam 2>/dev/null)"
if [ -z "$PAM_MODULE_DIR" ]; then
  for d in /usr/lib/security /usr/lib64/security /lib/security /lib64/security; do
    [ -d "$d" ] && PAM_MODULE_DIR="$d" && break
  done
fi
echo "$PAM_MODULE_DIR"
```

If the command prints nothing, check where your system stores other PAM modules (`pam_unix.so`) and use that directory.

### 4) Install the Compiled PAM Module

```bash
sudo install -m 0755 -o root -g root pam_pin.so "$PAM_MODULE_DIR/pam_pin.so"
```

### 5) Create the PIN Database File

Create an empty, protected database file:

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/security/pam_pin.db
```

### 6) Configure PAM Services

PAM file layouts differ across distros and desktop environments. The integration rule is always the same:

1. Add `pam_pin.so` in the `auth` section before the main password stack
2. Keep `pam_unix.so try_first_pass` (or distro equivalent include) immediately after, so password fallback works

Use this `pam_pin.so` line:

```pam
auth    [success=done default=ignore]   pam_pin.so max_tries=3 pin_db=/etc/security/pam_pin.db fail_delay_ms=500
```

Then ensure the next auth rule is your password handler, for example:

```pam
auth    sufficient                       pam_unix.so try_first_pass
```

or distro includes like:

```pam
auth    include      system-auth
auth    substack     common-auth
@include common-auth
```

Below are common service files.

#### A) GDM

File:

- `/etc/pam.d/gdm-password`

Backup:

```bash
sudo cp /etc/pam.d/gdm-password /etc/pam.d/gdm-password.bak
```

Edit:

```bash
sudoedit /etc/pam.d/gdm-password
```

In the `auth` section, add `pam_pin.so` before `pam_unix` (or before `include/substack system-auth`), then ensure `pam_unix.so try_first_pass` is immediately after it.

#### B) SDDM (KDE Plasma login)

File:

- `/etc/pam.d/sddm`

Backup:

```bash
sudo cp /etc/pam.d/sddm /etc/pam.d/sddm.bak
```

Edit:

```bash
sudoedit /etc/pam.d/sddm
```

In the `auth` section, add `pam_pin.so` before `pam_unix` (or before `include/substack system-auth`), then ensure `pam_unix.so try_first_pass` is immediately after it.

Note: for Plasma session lock/unlock (not only SDDM login), some setups also require updating the locker PAM service (for example `/etc/pam.d/kde`, if present).

#### C) `sudo`

File:

- `/etc/pam.d/sudo`

Backup:

```bash
sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
```

Edit:

```bash
sudoedit /etc/pam.d/sudo
```

In the `auth` section, insert the `pam_pin.so` line before:

```pam
auth       include      system-auth
```

or before distro-specific equivalents such as `@include common-auth`.

Then ensure password fallback follows it (`pam_unix.so try_first_pass` or your distro's included auth stack).

Quick test:

```bash
sudo -k
sudo true
```

If your distro does not use one of the files above, apply the same rule to the relevant service under `/etc/pam.d/`.

### 7) Add User PIN Hashes

`/etc/security/pam_pin.db` format:

```text
username:hash
```

Example:

```text
cristiano:$y$j9T$...
```

Generate a PIN hash (recommended: yescrypt):

```bash
mkpasswd -m yescrypt 123456
```

Alternative when `mkpasswd` is unavailable:

```bash
openssl passwd -6 123456
```

Note: this generates a SHA-512 hash instead of yescrypt, but it is still compatible with `crypt(3)` and works with this module.

Update the DB:

```bash
sudoedit /etc/security/pam_pin.db
```

Add or update line:

```text
cristiano:<generated_hash>
```

Reinforce file permissions:

```bash
sudo chown root:root /etc/security/pam_pin.db
sudo chmod 600 /etc/security/pam_pin.db
```

## Behavior Check

1. Reboot the machine.
2. Enter a valid PIN: immediate login.
3. Enter a password in the same field: fallback to password module and login.
4. After too many wrong PIN attempts (default: 3), fallback to password.

## Quick Recovery

If PAM configuration causes login issues, restore backups:

```bash
sudo cp /etc/pam.d/gdm-password.bak /etc/pam.d/gdm-password
sudo cp /etc/pam.d/sddm.bak /etc/pam.d/sddm
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
```

It is strongly recommended to test first in a VM or with an already-open root console.

## Uninstallation

1. Restore PAM files from backups:

```bash
sudo cp /etc/pam.d/gdm-password.bak /etc/pam.d/gdm-password
sudo cp /etc/pam.d/sddm.bak /etc/pam.d/sddm
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
```

If a backup file does not exist on your system, skip that file.

2. Remove the installed PAM module:

If `PAM_MODULE_DIR` is not set in your current shell, detect it again first:

```bash
PAM_MODULE_DIR="$(pkg-config --variable=securedir pam 2>/dev/null)"
if [ -z "$PAM_MODULE_DIR" ]; then
  for d in /usr/lib/security /usr/lib64/security /lib/security /lib64/security; do
    [ -d "$d" ] && PAM_MODULE_DIR="$d" && break
  done
fi
```

```bash
sudo rm -f "$PAM_MODULE_DIR/pam_pin.so"
```

3. Optional: remove the PIN database file:

```bash
sudo rm -f /etc/security/pam_pin.db
```

4. Optional: clean local build artifacts in this repository:

```bash
make clean
```

After uninstallation, authentication returns to the previous PAM behavior (standard password), assuming the original PAM files were correctly restored.
