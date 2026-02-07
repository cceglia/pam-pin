# Guida installazione `pam_pin.so` per Fedora

Questa guida copre:
1. Installazione per GDM
2. Installazione per SDDM
3. Installazione per `sudo`
4. Creazione del file DB PIN

## Prerequisiti

Installa dipendenze di build:

```bash
sudo dnf install pam-devel libxcrypt-devel gcc make
```

Compila il modulo:

```bash
make
```

Installa il modulo PAM compilato:

```bash
sudo install -m 0755 -o root -g root pam_pin.so /usr/lib64/security/pam_pin.so
```

Crea il DB PIN (vuoto e protetto):

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/security/pam_pin.db
```

Configurazione modulo consigliata:

```pam
auth    [success=done default=ignore]   pam_pin.so max_tries=3 pin_db=/etc/security/pam_pin.db state_dir=/run/pam-pin fail_delay_ms=500
auth    sufficient                       pam_unix.so try_first_pass
```

Con questa modalita il campo di autenticazione e unico: inserisci `PIN or Password`.

## 1) Installazione per GDM

File PAM:
- `/etc/pam.d/gdm-password`

Backup:

```bash
sudo cp /etc/pam.d/gdm-password /etc/pam.d/gdm-password.bak
```

Modifica con `sudoedit`:

```bash
sudoedit /etc/pam.d/gdm-password
```

In sezione `auth`, aggiungi la riga `pam_pin.so` **prima** di `pam_unix` o prima di `include/substack system-auth`.

In sezione `auth`, assicurati che subito dopo `pam_pin.so` ci sia `pam_unix.so try_first_pass`.

## 2) Installazione per SDDM (login KDE Plasma)

File PAM:
- `/etc/pam.d/sddm`

Backup:

```bash
sudo cp /etc/pam.d/sddm /etc/pam.d/sddm.bak
```

Modifica:

```bash
sudoedit /etc/pam.d/sddm
```

In sezione `auth`, aggiungi la riga `pam_pin.so` **prima** di `pam_unix` o prima di `include/substack system-auth`.

In sezione `auth`, assicurati che subito dopo `pam_pin.so` ci sia `pam_unix.so try_first_pass`.

Nota: per lock/unlock della sessione Plasma (non solo login SDDM), su alcune installazioni va aggiornato anche il servizio PAM del locker (`/etc/pam.d/kde` o equivalente).

## 3) Installazione per `sudo`

File PAM:
- `/etc/pam.d/sudo`

Backup:

```bash
sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak
```

Modifica:

```bash
sudoedit /etc/pam.d/sudo
```

In sezione `auth`, inserisci la riga `pam_pin.so` **prima** di:

```pam
auth       include      system-auth
```

In sezione `auth`, assicurati che subito dopo `pam_pin.so` ci sia `pam_unix.so try_first_pass`.

Test rapido:

```bash
sudo -k
sudo true
```

## 4) Creazione file DB con i PIN

Formato del file `/etc/security/pam_pin.db`:

```text
username:hash
```

Esempio:

```text
cristiano:$y$j9T$...   # hash yescrypt (compatibile crypt)
```

### Generare hash PIN (consigliato: yescrypt)

Installa `mkpasswd` se manca:

```bash
sudo dnf install whois
```

Genera hash (sostituisci `123456`):

```bash
mkpasswd -m yescrypt 123456
```

Aggiorna il DB:

```bash
sudoedit /etc/security/pam_pin.db
```

Aggiungi o aggiorna la riga:

```text
cristiano:<hash_generato>
```

Rinforza permessi:

```bash
sudo chown root:root /etc/security/pam_pin.db
sudo chmod 600 /etc/security/pam_pin.db
```

## Verifica del comportamento

1. Riavvia la macchina.
2. Inserisci un PIN valido: login immediato.
3. Inserisci password nel campo unico: fallback al modulo password e login.
4. Dopo 3 PIN errati: fallback a password.

## Recovery rapida

Se una configurazione PAM crea problemi, ripristina i backup:

```bash
sudo cp /etc/pam.d/gdm-password.bak /etc/pam.d/gdm-password
sudo cp /etc/pam.d/sddm.bak /etc/pam.d/sddm
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
```

Consigliato testare prima in VM o con una console root già aperta.

## Disinstallazione

1. Ripristina i file PAM dai backup:

```bash
sudo cp /etc/pam.d/gdm-password.bak /etc/pam.d/gdm-password
sudo cp /etc/pam.d/sddm.bak /etc/pam.d/sddm
sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo
```

2. Rimuovi il modulo installato:

```bash
sudo rm -f /usr/lib64/security/pam_pin.so
```

3. (Opzionale) rimuovi il DB PIN:

```bash
sudo rm -f /etc/security/pam_pin.db
```

4. (Opzionale) pulisci artefatti di build locali nel repository:

```bash
make clean
```

Dopo la disinstallazione, il sistema torna al comportamento PAM precedente (password standard), assumendo che i file PAM siano stati ripristinati correttamente.
