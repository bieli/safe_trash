use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const DEFAULT_BACKUP_MOUNT_POINT: &str = "/mnt/encrypted_backup/trash_vault";
pub const METADATA_FILE: &str = "metadata.json";
pub const VAULT_MARKER_FILE: &str = ".luks_vault_ready";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeletedEntry {
    pub original_path: PathBuf,
    pub vault_filename: String,
    pub deleted_at: String,
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

    pub fn save_metadata(&self, store: &MetadataStore) -> io::Result<()> {
        let json = serde_json::to_string_pretty(store)?;
        fs::write(self.get_metadata_path(), json)
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
            if !path.exists() {
                eprintln!("Error: File or directory '{}' does not exist.", target);
                continue;
            }

            let abs_path = match fs::canonicalize(path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Could not resolve full path for '{}': {}", target, e);
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

            let copy_res = if abs_path.is_dir() {
                copy_dir_all(&abs_path, &vault_dest)
            } else {
                fs::copy(&abs_path, &vault_dest).map(|_| ())
            };

            match copy_res {
                Ok(_) => {
                    let remove_res = if abs_path.is_dir() {
                        fs::remove_dir_all(&abs_path)
                    } else {
                        fs::remove_file(&abs_path)
                    };

                    if let Err(e) = remove_res {
                        eprintln!("Copied to vault, but failed to remove original: {}", e);
                    } else {
                        let entry = DeletedEntry {
                            original_path: abs_path.clone(),
                            vault_filename: vault_filename.clone(),
                            deleted_at: Utc::now().to_rfc3339(),
                        };
                        store.insert(vault_filename, entry);
                        println!("Secured and removed: {:?}", abs_path);
                        deleted_paths.push(abs_path);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Failed to copy '{}' to external drive: {}. Original preserved.",
                        target, e
                    );
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
        let matches: Vec<DeletedEntry> = match query {
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
        if !vault_src.exists() {
            return Err("Error: File is missing from the external vault!".to_string());
        }

        // Build restored path with .restored_from_deleted suffix
        let mut restored_path_os = target_entry.original_path.clone().into_os_string();
        restored_path_os.push(".restored_from_deleted");
        let restored_path = PathBuf::from(restored_path_os);

        if let Some(parent) = restored_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let copy_res = if vault_src.is_dir() {
            copy_dir_all(&vault_src, &restored_path)
        } else {
            fs::copy(&vault_src, &restored_path).map(|_| ())
        };

        match copy_res {
            Ok(_) => {
                let _ = if vault_src.is_dir() {
                    fs::remove_dir_all(&vault_src)
                } else {
                    fs::remove_file(&vault_src)
                };
                store.remove(&target_entry.vault_filename);
                self.save_metadata(&store)
                    .map_err(|e| format!("Failed to update metadata: {}", e))?;
                println!("Restored file as: {}", restored_path.display());
                Ok(Some(restored_path))
            }
            Err(e) => Err(format!("Error restoring file: {}", e)),
        }
    }
}

pub fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}
