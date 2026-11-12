use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs as unix_fs;
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_BACKUP_MOUNT_POINT: &str = "/mnt/encrypted_backup/trash_vault";
pub const METADATA_FILE: &str = "metadata.json";
pub const VAULT_MARKER_FILE: &str = ".luks_vault_ready";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeletedEntry {
    pub original_path: PathBuf,
    pub vault_filename: String,
    pub deleted_at: String,
    #[serde(default)]
    pub is_symlink: bool,
    #[serde(default)]
    pub sha256: Option<String>,
}

pub type MetadataStore = HashMap<String, DeletedEntry>;

#[derive(Debug, Clone)]
pub struct TrashVault {
    pub mount_point: PathBuf,
}

impl TrashVault {
    pub fn new<P: AsRef<Path>>(mount_point: P) -> Self {
        Self {
            mount_point: mount_point.as_ref().to_path_buf(),
        }
    }

    pub fn get_metadata_path(&self) -> PathBuf {
        self.mount_point.join(METADATA_FILE)
    }

    pub fn is_ready(&self) -> bool {
        self.mount_point.join(VAULT_MARKER_FILE).exists()
    }

    pub fn ensure_ready(&self) -> Result<(), String> {
        if !self.is_ready() {
            return Err(format!(
                "CRITICAL ERROR: Encrypted LUKS drive is not mounted (missing marker file '{}' in {}).\nUnlock and mount the drive before using rm/unrm. Operation aborted to protect data.",
                VAULT_MARKER_FILE,
                self.mount_point.display()
            ));
        }
        Ok(())
    }

    pub fn load_metadata(&self) -> MetadataStore {
        let path = self.get_metadata_path();
        if !path.exists() {
            return HashMap::new();
        }
        let data = fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
        serde_json::from_str(&data).unwrap_or_default()
    }

    /// Atomically writes metadata via a synced temporary file + rename to prevent corruption
    pub fn save_metadata(&self, store: &MetadataStore) -> io::Result<()> {
        let json = serde_json::to_string_pretty(store)?;
        let final_path = self.get_metadata_path();
        let tmp_path = self.mount_point.join(format!("{}.tmp", METADATA_FILE));

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    pub fn safe_delete(&self, targets: &[String]) -> Result<Vec<PathBuf>, String> {
        self.ensure_ready()?;
        let mut store = self.load_metadata();
        let mut deleted_paths = Vec::new();

        for target in targets {
            // Ignore standard rm flags such as -rf, -r, -f
            if target.starts_with('-') {
                continue;
            }

            let path = Path::new(target);
            // Use symlink_metadata so broken symlinks are detected and targets are never followed
            let meta = match fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(_) => {
                    eprintln!("Error: File or directory '{}' does not exist.", target);
                    continue;
                }
            };

            let abs_path = match resolve_lexical_path(path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Could not resolve path for '{}': {}", target, e);
                    continue;
                }
            };

            let timestamp = Utc::now().format("%Y%m%d_%H%M%S_%f").to_string();
            let file_name = abs_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let vault_filename = format!("{}_{}", timestamp, file_name);
            let vault_dest = self.mount_point.join(&vault_filename);

            let is_symlink = meta.file_type().is_symlink();

            if is_symlink {
                let link_target = match fs::read_link(&abs_path) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Failed to read symlink '{}': {}", target, e);
                        continue;
                    }
                };

                if let Err(e) = unix_fs::symlink(&link_target, &vault_dest) {
                    eprintln!(
                        "Failed to replicate symlink '{}' to vault: {}. Original preserved.",
                        target, e
                    );
                    continue;
                }

                // Verify symlink target matches before removing original link
                if fs::read_link(&vault_dest).ok().as_ref() != Some(&link_target) {
                    eprintln!("Symlink verification failed for '{}'. Original preserved.", target);
                    let _ = fs::remove_file(&vault_dest);
                    continue;
                }

                if let Err(e) = fs::remove_file(&abs_path) {
                    eprintln!("Copied symlink to vault, but failed to remove original: {}", e);
                } else {
                    let entry = DeletedEntry {
                        original_path: abs_path.clone(),
                        vault_filename: vault_filename.clone(),
                        deleted_at: Utc::now().to_rfc3339(),
                        is_symlink: true,
                        sha256: None,
                    };
                    store.insert(vault_filename, entry);
                    println!("Secured and removed symlink: {:?}", abs_path);
                    deleted_paths.push(abs_path);
                }
            } else if meta.is_dir() {
                if let Err(e) = copy_dir_verified(&abs_path, &vault_dest) {
                    eprintln!(
                        "Failed verified directory copy for '{}': {}. Original preserved.",
                        target, e
                    );
                    let _ = fs::remove_dir_all(&vault_dest);
                    continue;
                }

                if let Err(e) = fs::remove_dir_all(&abs_path) {
                    eprintln!("Copied directory to vault, but failed to remove original: {}", e);
                } else {
                    let entry = DeletedEntry {
                        original_path: abs_path.clone(),
                        vault_filename: vault_filename.clone(),
                        deleted_at: Utc::now().to_rfc3339(),
                        is_symlink: false,
                        sha256: None,
                    };
                    store.insert(vault_filename, entry);
                    println!("Secured and removed directory: {:?}", abs_path);
                    deleted_paths.push(abs_path);
                }
            } else {
                // Regular file: copy + SHA-256 verification before deletion
                let src_hash = match compute_sha256(&abs_path) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Failed to hash '{}': {}. Original preserved.", target, e);
                        continue;
                    }
                };

                if let Err(e) = fs::copy(&abs_path, &vault_dest) {
                    eprintln!(
                        "Failed to copy '{}' to external drive: {}. Original preserved.",
                        target, e
                    );
                    continue;
                }

                let dst_hash = match compute_sha256(&vault_dest) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!(
                            "Failed to verify copied file hash for '{}': {}. Original preserved.",
                            target, e
                        );
                        let _ = fs::remove_file(&vault_dest);
                        continue;
                    }
                };

                if src_hash != dst_hash {
                    eprintln!(
                        "CRITICAL: SHA-256 mismatch after copying '{}'! Aborting deletion to protect data.",
                        target
                    );
                    let _ = fs::remove_file(&vault_dest);
                    continue;
                }

                if let Err(e) = fs::remove_file(&abs_path) {
                    eprintln!("Verified in vault, but failed to remove original: {}", e);
                } else {
                    let entry = DeletedEntry {
                        original_path: abs_path.clone(),
                        vault_filename: vault_filename.clone(),
                        deleted_at: Utc::now().to_rfc3339(),
                        is_symlink: false,
                        sha256: Some(src_hash),
                    };
                    store.insert(vault_filename, entry);
                    println!("Verified, secured, and removed: {:?}", abs_path);
                    deleted_paths.push(abs_path);
                }
            }
        }

        if let Err(e) = self.save_metadata(&store) {
            return Err(format!("Warning: Failed to save metadata file: {}", e));
        }

        Ok(deleted_paths)
    }

    /// Restores a deleted item. If `selected_index` is provided, skips interactive stdin prompt.
    pub fn restore_files(
        &self,
        query: Option<&str>,
        selected_index: Option<usize>,
    ) -> Result<Option<PathBuf>, String> {
        self.ensure_ready()?;
        let mut store = self.load_metadata();

        if store.is_empty() {
            println!("Vault is empty. No files to restore.");
            return Ok(None);
        }

        // Sort from newest to oldest
        let mut entries: Vec<DeletedEntry> = store.values().cloned().collect();
entries.sort_by(|a, b| b.deleted_at.cmp(&a.deleted_at));
// Filter by query if provided, otherwise pick the most recently deleted entry
let matches: Vec = match query {
Some(q) => entries
.into_iter()
.filter(|e| e.original_path.to_string_lossy().contains(q))
.collect(),
None => vec![entries[0].clone()],
};
if matches.is_empty() {
println!("No deleted files found matching your query.");
return Ok(None);
}
let target_entry = if matches.len() == 1 {
&matches[0]
} else {
let idx = match selected_index {
Some(i) => i,
None => {
println!("Found multiple matching files:");
for (i, entry) in matches.iter().enumerate() {
println!(
"[{}] {} (deleted at: {})",
i,
entry.original_path.display(),
entry.deleted_at
);
}
print!("Enter the number of the file to restore: ");
io::stdout().flush().map_err(|e| e.to_string())?;
let mut input = String::new();
io::stdin()
.read_line(&mut input)
.map_err(|e| e.to_string())?;
input
.trim()
.parse()
.map_err(|_| "Invalid selection.".to_string())?
}
};
matches
.get(idx)
.ok_or_else(|| "Selection out of range.".to_string())?
};
let vault_src = self.mount_point.join(&target_entry.vault_filename);
let vault_meta = match fs::symlink_metadata(&vault_src) {
Ok(m) => m,
Err(_) => return Err("Error: File is missing from the external vault!".to_string()),
};
// Build restored path with .restored_from_deleted suffix
let mut restored_path_os = target_entry.original_path.clone().into_os_string();
restored_path_os.push(".restored_from_deleted");
let restored_path = PathBuf::from(restored_path_os);
if let Some(parent) = restored_path.parent() {
let _ = fs::create_dir_all(parent);
}
if vault_meta.file_type().is_symlink() {
let link_target = fs::read_link(&vault_src)
.map_err(|e| format!("Failed to read symlink in vault: {}", e))?;
unix_fs::symlink(&link_target, &restored_path)
.map_err(|e| format!("Failed to restore symlink: {}", e))?;
let _ = fs::remove_file(&vault_src);
} else if vault_meta.is_dir() {
copy_dir_verified(&vault_src, &restored_path)
.map_err(|e| format!("Error restoring directory: {}", e))?;
let _ = fs::remove_dir_all(&vault_src);
} else {
// Verify stored SHA-256 before and after restoring
if let Some(expected_hash) = &target_entry.sha256 {
let vault_hash = compute_sha256(&vault_src)
.map_err(|e| format!("Failed to hash vault file: {}", e))?;
if &vault_hash != expected_hash {
return Err(
"CRITICAL: Vault file failed SHA-256 integrity check! Possible disk corruption."
.to_string(),
);
}
}
fs::copy(&vault_src, &restored_path)
.map_err(|e| format!("Error restoring file: {}", e))?;
if let Some(expected_hash) = &target_entry.sha256 {
let restored_hash = compute_sha256(&restored_path)
.map_err(|e| format!("Failed to hash restored file: {}", e))?;
if &restored_hash != expected_hash {
return Err("Error: Restored file checksum mismatch!".to_string());
}
}
let _ = fs::remove_file(&vault_src);
}
store.remove(&target_entry.vault_filename);
self.save_metadata(&store)
.map_err(|e| format!("Failed to update metadata: {}", e))?;
println!("Restored file as: {}", restored_path.display());
Ok(Some(restored_path))
}
}
/// Resolves an absolute path lexically without dereferencing symlinks
fn resolve_lexical_path(path: &Path) -> io::Result {
let abs = if path.is_absolute() {
path.to_path_buf()
} else {
env::current_dir()?.join(path)
};
let mut normalized = PathBuf::new();
for component in abs.components() {
match component {
Component::CurDir => {}
Component::ParentDir => {
normalized.pop();
}
c => normalized.push(c.as_os_str()),
}
}
Ok(normalized)
}
/// Computes streaming SHA-256 hex digest of a file
pub fn compute_sha256(path: &Path) -> io::Result {
let mut file = File::open(path)?;
let mut hasher = Sha256::new();
let mut buffer = [0u8; 65536];
loop {
let bytes_read = file.read(&mut buffer)?;
if bytes_read == 0 {
break;
}
hasher.update(&buffer[..bytes_read]);
}
Ok(format!("{:x}", hasher.finalize()))
}
/// Recursively copies directories while preserving symlinks and verifying SHA-256 of every file
pub fn copy_dir_verified(src: &Path, dst: &Path) -> io::Result<()> {
fs::create_dir_all(dst)?;
for entry in fs::read_dir(src)? {
let entry = entry?;
let ty = entry.file_type()?;
let src_entry_path = entry.path();
let dst_entry_path = dst.join(entry.file_name());
if ty.is_symlink() {
let link_target = fs::read_link(&src_entry_path)?;
unix_fs::symlink(&link_target, &dst_entry_path)?;
} else if ty.is_dir() {
copy_dir_verified(&src_entry_path, &dst_entry_path)?;
} else {
let src_hash = compute_sha256(&src_entry_path)?;
fs::copy(&src_entry_path, &dst_entry_path)?;
let dst_hash = compute_sha256(&dst_entry_path)?;
if src_hash != dst_hash {
return Err(io::Error::new(
io::ErrorKind::InvalidData,
format!("SHA-256 mismatch copying {:?}", src_entry_path),
));
}
}
}
Ok(())
}
    
