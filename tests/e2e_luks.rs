//! End-to-end CLI tests against a real LUKS2 volume stored on ramfs.
//!
//! The container image lives in RAM (`mount -t ramfs`). `cryptsetup` formats it
//! as LUKS2, maps it through dm-crypt, and the test mounts the ext4 filesystem
//! from that mapper device. Every check below runs the `safe_trash` binary.

use safe_trash::{TrashVault, VAULT_MARKER_FILE};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_safe_trash");

struct RamfsLuks {
    base: PathBuf,
    ram_dir: PathBuf,
    image: PathBuf,
    mount_dir: PathBuf,
    vault_dir: PathBuf,
    mapper: String,
    ram_mounted: bool,
    opened: bool,
    mounted: bool,
}

impl RamfsLuks {
    fn provision() -> Self {
        ensure_privileges();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = PathBuf::from(format!(
            "/tmp/safe_trash_e2e_{}_{}",
            std::process::id(),
            nanos
        ));
        let ram_dir = base.join("ram");
        let mount_dir = base.join("mnt");
        let mapper = format!("safe_trash_e2e_{}_{}", std::process::id(), nanos);
        let image = ram_dir.join("vault.img");
        let key = ram_dir.join("vault.key");
        let vault_dir = mount_dir.join("trash_vault");

        fs::create_dir_all(&ram_dir).expect("create ram dir");
        fs::create_dir_all(&mount_dir).expect("create mount dir");

        let mut fx = Self {
            base,
            ram_dir,
            image,
            mount_dir,
            vault_dir,
            mapper,
            ram_mounted: false,
            opened: false,
            mounted: false,
        };

        expect_root(
            &["modprobe", "dm-crypt"],
            "load dm-crypt (continuing if the module is built-in)",
            true,
        );
        expect_root(
            &[
                "mount",
                "-t",
                "ramfs",
                "ramfs",
                fx.ram_dir.to_str().unwrap(),
            ],
            "mount ramfs",
            false,
        );
        fx.ram_mounted = true;
        expect_root(
            &["chmod", "1777", fx.ram_dir.to_str().unwrap()],
            "make ramfs writable for the test user",
            false,
        );

        let fstype = findmnt_field(&fx.ram_dir, "FSTYPE");
        assert_eq!(fstype, "ramfs", "backing store must be ramfs, got {fstype}");

        expect_root(
            &[
                "dd",
                "if=/dev/zero",
                &format!("of={}", fx.image.display()),
                "bs=1M",
                "count=64",
                "status=none",
                "conv=fsync",
            ],
            "allocate 64MiB image on ramfs",
            false,
        );

        write_key_file(&key);
        expect_root(
            &[
                "cryptsetup",
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--key-file",
                key.to_str().unwrap(),
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                fx.image.to_str().unwrap(),
            ],
            "luksFormat ramfs image",
            false,
        );
        expect_root(
            &[
                "cryptsetup",
                "open",
                "--batch-mode",
                "--key-file",
                key.to_str().unwrap(),
                fx.image.to_str().unwrap(),
                &fx.mapper,
            ],
            "cryptsetup open",
            false,
        );
        fx.opened = true;

        let status = root_output(&["cryptsetup", "status", &fx.mapper]);
        expect_status(&status, "cryptsetup status");
        let status_text = stdout_of(&status);
        assert!(
            status_text.contains("LUKS"),
            "mapper is not LUKS:\n{status_text}"
        );
        assert!(
            status_text.contains(&fx.image.display().to_string()),
            "LUKS device does not point at the ramfs image:\n{status_text}"
        );

        let mapper_dev = format!("/dev/mapper/{}", fx.mapper);
        expect_root(
            &["mkfs.ext4", "-q", "-F", &mapper_dev],
            "mkfs.ext4 on LUKS mapper",
            false,
        );
        expect_root(
            &["mount", &mapper_dev, fx.mount_dir.to_str().unwrap()],
            "mount decrypted ext4",
            false,
        );
        fx.mounted = true;

        let mounted_type = findmnt_field(&fx.mount_dir, "FSTYPE");
        assert_eq!(
            mounted_type, "ext4",
            "vault fs must be ext4, got {mounted_type}"
        );
        let mounted_src = findmnt_field(&fx.mount_dir, "SOURCE");
        assert_eq!(
            mounted_src, mapper_dev,
            "vault must be mounted from the LUKS mapper"
        );

        let (uid, gid) = current_ids();
        expect_root(
            &[
                "chown",
                &format!("{uid}:{gid}"),
                fx.mount_dir.to_str().unwrap(),
            ],
            "chown mounted vault to the test user",
            false,
        );
        fs::create_dir_all(&fx.vault_dir).expect("create trash_vault");
        fx
    }

    fn unmount_filesystem(&mut self) {
        if !self.mounted {
            return;
        }
        expect_root(
            &["umount", self.mount_dir.to_str().unwrap()],
            "umount ext4",
            false,
        );
        self.mounted = false;
    }
}

impl Drop for RamfsLuks {
    fn drop(&mut self) {
        if self.mounted {
            let _ = root_output(&["umount", self.mount_dir.to_str().unwrap()]);
            self.mounted = false;
        }
        if self.opened {
            let _ = root_output(&["cryptsetup", "close", &self.mapper]);
            self.opened = false;
        }
        if self.ram_mounted {
            let _ = root_output(&["umount", self.ram_dir.to_str().unwrap()]);
            self.ram_mounted = false;
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn e2e_cli_on_ramfs_luks_vault() {
    let mut luks = RamfsLuks::provision();
    let vault = luks.vault_dir.clone();
    let work = luks.base.join("work");
    fs::create_dir_all(&work).expect("work dir");

    let notes = work.join("notes.txt");
    fs::write(&notes, b"project notes").unwrap();

    let missing_marker = run_app(&vault, &["delete", notes.to_str().unwrap()]);
    assert!(
        !missing_marker.status.success(),
        "delete must abort when the LUKS marker is absent\n{}",
        dump(&missing_marker)
    );
    assert!(
        stderr_of(&missing_marker).contains(VAULT_MARKER_FILE),
        "error should name the marker file\n{}",
        dump(&missing_marker)
    );
    assert!(
        notes.exists(),
        "original file must survive an aborted delete"
    );

    fs::write(vault.join(VAULT_MARKER_FILE), b"").unwrap();

    let empty_list = run_app(&vault, &["list"]);
    expect_status(&empty_list, "list on empty vault");
    assert!(stdout_of(&empty_list).contains("Vault is empty."));

    assert!(
        !run_app(&vault, &["clean"]).status.success(),
        "clean without days"
    );
    assert!(
        !run_app(&vault, &["clean", "-1"]).status.success(),
        "clean rejects a negative age"
    );
    assert!(
        !run_app(&vault, &["clean", "nope"]).status.success(),
        "clean rejects a non-numeric age"
    );

    let deleted = run_app(&vault, &["delete", notes.to_str().unwrap()]);
    expect_status(&deleted, "delete notes.txt");
    assert!(!notes.exists(), "delete must remove the original file");

    let store = TrashVault::new(&vault).load_metadata();
    let notes_entry = store
        .values()
        .find(|e| e.original_path == notes)
        .expect("metadata must record notes.txt");
    let notes_hash = notes_entry.sha256.clone().expect("sha256 stored");
    let vault_notes = vault.join(&notes_entry.vault_filename);
    assert_eq!(
        safe_trash::compute_sha256(&vault_notes).unwrap(),
        notes_hash,
        "bytes on the LUKS volume must match the stored digest"
    );
    assert!(
        findmnt_field(&vault_notes, "SOURCE").ends_with(&luks.mapper),
        "vaulted file must reside on the LUKS mapper"
    );

    let listed = run_app(&vault, &["list"]);
    expect_status(&listed, "list after delete");
    let listed_out = stdout_of(&listed);
    assert!(listed_out.contains(&notes.display().to_string()));
    assert!(listed_out.contains(&notes_hash[..10]));

    let build = work.join("old_build");
    fs::create_dir_all(build.join("nested")).unwrap();
    fs::write(build.join("nested").join("data.txt"), b"nested-data").unwrap();
    let removed_dir = run_app(&vault, &["delete", "-rf", build.to_str().unwrap()]);
    expect_status(&removed_dir, "delete -rf old_build");
    assert!(
        !build.exists(),
        "directory must be removed after a verified copy"
    );

    let store = TrashVault::new(&vault).load_metadata();
    let dir_entry = store
        .values()
        .find(|e| e.original_path == build)
        .expect("metadata must record old_build");
    assert!(dir_entry.sha256.is_none());
    let nested = vault
        .join(&dir_entry.vault_filename)
        .join("nested")
        .join("data.txt");
    assert_eq!(fs::read(&nested).unwrap(), b"nested-data");

    let keep = work.join("keep_me.txt");
    fs::write(&keep, b"must survive").unwrap();
    let link = work.join("shortcut_to_target");
    unix_fs::symlink(&keep, &link).unwrap();
    let removed_link = run_app(&vault, &["delete", link.to_str().unwrap()]);
    expect_status(&removed_link, "delete symlink");
    assert!(fs::symlink_metadata(&link).is_err());
    assert_eq!(fs::read(&keep).unwrap(), b"must survive");

    let listed = stdout_of(&run_ok(&vault, &["list"], "list three items"));
    assert!(listed.contains("DIRECTORY"));
    assert!(listed.contains("SYMLINK"));
    assert!(listed.contains(&build.display().to_string()));
    assert!(listed.contains(&link.display().to_string()));

    let restored = run_ok(
        &vault,
        &["restore", "notes.txt"],
        "restore notes.txt by fragment",
    );
    let restored_notes = notes.with_file_name("notes.txt.restored_from_deleted");
    assert!(
        stdout_of(&restored).contains(&restored_notes.display().to_string()),
        "restore output should name the destination\n{}",
        dump(&restored)
    );
    assert_eq!(fs::read(&restored_notes).unwrap(), b"project notes");
    assert!(
        !notes.exists(),
        "restore must not overwrite the original path"
    );
    assert!(
        !TrashVault::new(&vault)
            .load_metadata()
            .values()
            .any(|e| e.original_path == notes),
        "restored file must leave the vault index"
    );

    let mut store = TrashVault::new(&vault).load_metadata();
    store
        .get_mut(&dir_entry.vault_filename)
        .expect("directory still vaulted")
        .deleted_at = "2000-01-01T00:00:00+00:00".to_string();
    TrashVault::new(&vault)
        .save_metadata(&store)
        .expect("age directory timestamp");

    let dry = run_ok(&vault, &["clean", "30", "--dry-run"], "clean dry-run");
    let dry_out = stdout_of(&dry);
    assert!(dry_out.contains("[DRY-RUN]"));
    assert!(dry_out.contains("old_build"), "{dry_out}");
    assert!(
        vault.join(&dir_entry.vault_filename).exists(),
        "dry-run must not delete the vaulted directory"
    );
    assert_eq!(TrashVault::new(&vault).load_metadata().len(), 2);

    let purged = run_ok(&vault, &["clean", "30"], "clean 30");
    assert!(stdout_of(&purged).contains("Purged:"));
    assert!(stdout_of(&purged).contains("old_build"));
    assert!(
        !vault.join(&dir_entry.vault_filename).exists(),
        "clean must remove the old directory from the LUKS volume"
    );
    let remaining = TrashVault::new(&vault).load_metadata();
    assert_eq!(remaining.len(), 1);
    assert!(remaining.values().next().unwrap().is_symlink);

    let after_clean = stdout_of(&run_ok(&vault, &["list"], "list after clean"));
    assert!(!after_clean.contains("old_build"));
    assert!(after_clean.contains("SYMLINK"));

    let restored_link_out = run_ok(&vault, &["restore"], "restore newest remaining item");
    let restored_link = link
        .parent()
        .unwrap()
        .join("shortcut_to_target.restored_from_deleted");
    assert!(stdout_of(&restored_link_out).contains(&restored_link.display().to_string()));
    assert!(fs::symlink_metadata(&restored_link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&restored_link).unwrap(), keep);
    assert_eq!(fs::read(&keep).unwrap(), b"must survive");
    assert!(TrashVault::new(&vault).load_metadata().is_empty());

    let firmware = work.join("firmware.bin");
    fs::write(&firmware, b"valid firmware bytes").unwrap();
    expect_status(
        &run_app(&vault, &["delete", firmware.to_str().unwrap()]),
        "delete firmware.bin",
    );
    let fw_entry = TrashVault::new(&vault)
        .load_metadata()
        .values()
        .find(|e| e.original_path == firmware)
        .unwrap()
        .clone();
    let fw_vault = vault.join(&fw_entry.vault_filename);
    flip_first_byte(&fw_vault);
    let corrupt = run_app(&vault, &["restore", "firmware.bin"]);
    assert!(
        !corrupt.status.success(),
        "restore must reject a corrupted LUKS payload\n{}",
        dump(&corrupt)
    );
    assert!(
        stderr_of(&corrupt).contains("SHA-256"),
        "corruption must be reported as a checksum failure\n{}",
        dump(&corrupt)
    );
    let restored_fw = work.join("firmware.bin.restored_from_deleted");
    assert!(
        !restored_fw.exists(),
        "corrupted bytes must not be restored"
    );
    assert!(fw_vault.exists(), "rejected payload stays in the vault");

    luks.unmount_filesystem();
    let fresh = work.join("after_unmount.txt");
    fs::write(&fresh, b"still here").unwrap();
    let unmounted = run_app(&vault, &["delete", fresh.to_str().unwrap()]);
    assert!(
        !unmounted.status.success(),
        "delete must abort after umount"
    );
    assert!(
        fresh.exists(),
        "file must remain when the LUKS volume is unmounted"
    );
}

fn ensure_privileges() {
    if euid() == 0 {
        return;
    }
    let out = Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .expect("sudo is required to set up a LUKS volume");
    if !out.status.success() {
        panic!(
            "LUKS-on-ramfs end-to-end test needs root or passwordless sudo.\n\
             Re-run with: sudo -E cargo test --test e2e_luks -- --nocapture\n\
             sudo stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn write_key_file(path: &Path) {
    let mut key = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .expect("read key material");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create key file");
    file.write_all(&key).expect("write key file");
}

fn run_app(vault: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("SAFE_TRASH_VAULT", vault)
        .output()
        .expect("spawn safe_trash")
}

fn run_ok(vault: &Path, args: &[&str], what: &str) -> Output {
    let out = run_app(vault, args);
    expect_status(&out, what);
    out
}

fn root_output(args: &[&str]) -> Output {
    if euid() == 0 {
        Command::new(args[0])
            .args(&args[1..])
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", args[0]))
    } else {
        Command::new("sudo")
            .arg("-n")
            .arg("--")
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn sudo {}: {e}", args[0]))
    }
}

fn expect_root(args: &[&str], what: &str, allow_failure: bool) {
    let out = root_output(args);
    if allow_failure {
        return;
    }
    expect_status(&out, what);
}

fn expect_status(out: &Output, what: &str) {
    if !out.status.success() {
        panic!(
            "{what} failed ({})\n{}",
            status_code(&out.status),
            dump(out)
        );
    }
}

fn findmnt_field(path: &Path, field: &str) -> String {
    let out = Command::new("findmnt")
        .args(["-n", "-o", field, "-T"])
        .arg(path)
        .output()
        .expect("spawn findmnt");
    expect_status(&out, &format!("findmnt {field}"));
    stdout_of(&out).trim().to_string()
}

fn flip_first_byte(path: &Path) {
    let mut bytes = fs::read(path).expect("read vault payload");
    bytes[0] ^= 0xff;
    fs::write(path, bytes).expect("write corrupted payload");
}

fn current_ids() -> (u32, u32) {
    let uid = id_value("-u");
    let gid = id_value("-g");
    (uid, gid)
}

fn id_value(flag: &str) -> u32 {
    let out = Command::new("id").arg(flag).output().expect("id");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("parse id")
}

fn euid() -> u32 {
    id_value("-u")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn dump(out: &Output) -> String {
    format!("stdout:\n{}\nstderr:\n{}", stdout_of(out), stderr_of(out))
}

fn status_code(status: &ExitStatus) -> String {
    status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string())
}
