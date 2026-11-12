# safe_trash 🛡️

A fast, lightweight Rust CLI utility that replaces standard `rm` with a fail-safe backup vault workflow on Linux. Deleted files, directories, and symlinks are verified via **SHA-256** and moved to an external **LUKS-encrypted** drive with full path metadata, ready to be inspected with `list` or recovered anytime via `unrm` with a `.restored_from_deleted` extension.

```bash
   .--.      ____        __        _____               _
  |o_o |    / ___|  __ _/ _| ___  |_   _| __ __ _  ___| |__
  |:_/ |    \___ \ / _` | |_ / _ \   | || '__/ _` |/ __| '_ \
 //   \ \    ___) | (_| |  _|  __/   | || | | (_| |\__ \ | | |
(|     | )  |____/ \__,_|_|  \___|   |_||_|  \__,_||___/_| |_|
/'\_   _/`\  [ LUKS Encrypted Vault | rm -> SHA-256 -> unrm ]
\___)=(___/
```
## Features

- **Fail-Safe Mount Protection:** Verifies the presence of a `.luks_vault_ready` marker file on your external encrypted drive before performing any deletion. If the drive is unmounted, `safe_trash` aborts immediately so you never accidentally write backups to your local root filesystem or lose data.
- **End-to-End SHA-256 Integrity Verification:** Computes streaming SHA-256 checksums before and after copying files to the vault—and verifies them again upon restoration—ensuring zero silent data corruption over USB connections.
- **Symlink-Safe Handling:** Detects symbolic links without dereferencing them, moving only the symlink itself while leaving its target untouched.
- **Atomic Metadata Persistence:** Writes `metadata.json` via a synced temporary file (`fsync` + atomic `rename`) so sudden power loss or cable disconnects cannot corrupt your vault index.
- **Non-Destructive Recovery (`unrm`):** Restores files, directories, or symlinks back to their exact original paths with `.restored_from_deleted` appended to prevent accidental overwrites of newer files.
- **Vault Inspection (`safe_trash list`):** Displays all stored items sorted from newest to oldest alongside deletion timestamps and SHA-256 digests.
- **Zero Kernel Risk:** Runs entirely in user space, delegating hardware-accelerated block encryption to Linux's native `dm-crypt` / LUKS subsystem.

---

## Prerequisites

- **Linux** with `cryptsetup` (LUKS)
- **Rust & Cargo** (`1.70+` recommended)

---

## Setup Guide

### 1. Prepare Your External LUKS Drive (One-Time Setup)

> **Warning:** `luksFormat` will erase all existing data on the target partition (`/dev/sdX1`). Double-check your device name with `lsblk`.

```bash
# 1. Encrypt the external partition
sudo cryptsetup luksFormat /dev/sdX1

# 2. Unlock the encrypted container
sudo cryptsetup open /dev/sdX1 backup_vault

# 3. Format with ext4
sudo mkfs.ext4 /dev/mapper/backup_vault

# 4. Mount and initialize the vault marker
sudo mkdir -p /mnt/encrypted_backup
sudo mount /dev/mapper/backup_vault /mnt/encrypted_backup
sudo chown -R $USER:$USER /mnt/encrypted_backup
mkdir -p /mnt/encrypted_backup/trash_vault
touch /mnt/encrypted_backup/trash_vault/.luks_vault_ready
```

### 2. Build and Install `safe_trash`

Clone this repository and compile the release binary:

```bash
git clone https://github.com
cd safe_trash
cargo build --release
sudo cp target/release/safe_trash /usr/local/bin/
```

### 3. Configure Shell Aliases & Optional Custom Mount Path

Add the following aliases to your `~/.bashrc` or `~/.zshrc`:

```bash
alias rm='safe_trash delete'
alias unrm='safe_trash restore'

# Optional: override the default vault path (/mnt/encrypted_backup/trash_vault)
export SAFE_TRASH_VAULT="/mnt/encrypted_backup/trash_vault"
```

Reload your shell configuration:

```bash
source ~/.bashrc
```

---

## Usage

### Deleting Files Safely
Use `rm` just like you normally would (standard flags like `-r`, `-f`, `-rf` are accepted):

```bash
rm project_notes.txt
rm -rf old_build_folder/
```
Files are hashed (SHA-256), timestamped, copied and verified on your encrypted vault, and logged atomically in `metadata.json` before the local copy is removed.

### Listing Vault Contents (`safe_trash list`)
Inspect everything currently stored in your encrypted vault:

```bash
safe_trash list
```
Example output:
```text
DELETED AT                   | TYPE / SHA256  | ORIGINAL PATH
-------------------------------------------------------------------------------------
2026-11-12T18:15:04.123+00:00 | 9f86d08188...  | /home/user/projects/cnc_simulation.mp4
2026-11-12T17:42:19.891+00:00 | DIRECTORY      | /home/user/projects/old_build_folder
2026-11-12T16:10:02.440+00:00 | SYMLINK        | /home/user/bin/current_tool
```

### Restoring Files (`unrm`)
- **Restore the last deleted item:**
  ```bash
  unrm
  ```
- **Search and restore by filename fragment:**
  ```bash
  unrm simulation
  ```
  If multiple matches exist, an interactive prompt lets you select the exact timestamped version. The file is verified against its stored SHA-256 digest and restored to `/original/path/filename.ext.restored_from_deleted`.

### Bypassing the Vault (Permanent Delete)
To permanently delete a file using the system's native `/bin/rm` without backing it up, prefix the command with a backslash:

```bash
\(\rm\) temporary_file.tmp
```

### Unmounting Safely
Before unplugging your external drive:

```bash
sudo umount /mnt/encrypted_backup
sudo cryptsetup close backup_vault
```

---

## Running Tests

Run the integration test suite (simulates LUKS mount checks, SHA-256 corruption detection, symlink protection, and atomic metadata persistence using isolated temporary directories):

```bash
cargo test
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
