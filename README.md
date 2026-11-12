# safe_trash 🛡️

A fast, lightweight Rust CLI utility that replaces standard `rm` with a fail-safe backup vault workflow on Linux. Deleted files and directories are securely moved to an external **LUKS-encrypted** drive with full path metadata, and can be recovered anytime via `unrm` with a `.restored_from_deleted` extension.

## Features

- **Fail-Safe Mount Protection:** Verifies the presence of a `.luks_vault_ready` marker file on your external encrypted drive before performing any deletion. If the drive is unmounted, `safe_trash` aborts immediately so you never accidentally write backups to your local root filesystem or lose data.
- **Non-Destructive Recovery (`unrm`):** Restores files or directories back to their exact original paths with `.restored_from_deleted` appended to prevent accidental overwrites of newer files.
- **Interactive History Search:** Restore the most recently deleted item with a single command, or filter deleted items by name fragment.
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
sudo chown -R USER:USER /mnt/encrypted_backup
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

*(Optional)* If you mounted your LUKS drive somewhere other than `/mnt/encrypted_backup/trash_vault`, update the `BACKUP_MOUNT_POINT` constant in `src/main.rs` before building.

### 3. Configure Shell Aliases

Add the following aliases to your `~/.bashrc` or `~/.zshrc`:

```bash
alias rm='safe_trash delete'
alias unrm='safe_trash restore'
```

Reload your shell configuration:

```bash
source ~/.bashrc
```

---

## Usage

### Deleting Files Safely
Use `rm` just like you normally would:

```bash
rm project_notes.txt
rm -rf old_build_folder/
```
Files are timestamped, moved to your encrypted vault, and logged in `metadata.json`.

### Restoring Files (`unrm`)
- **Restore the last deleted item:**
  ```bash
  unrm
  ```
- **Search and restore by filename fragment:**
  ```bash
  unrm simulation
  ```
  If multiple matches exist, an interactive prompt lets you select the exact timestamped version. The file is restored to `/original/path/filename.ext.restored_from_deleted`.

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

## License

MIT License — feel free to use, modify, and distribute.
