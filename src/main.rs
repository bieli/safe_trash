use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

// CHANGE THIS PATH to the mount point of your encrypted external drive
const BACKUP_MOUNT_POINT: &str = "/mnt/encrypted_backup/trash_vault";
const METADATA_FILE: &str = "metadata.json";
const VAULT_MARKER_FILE: &str = ".luks_vault_ready";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeletedEntry {
    original_path: PathBuf,
    vault_filename: String,
    deleted_at: String,
}

type MetadataStore = HashMap<String, DeletedEntry>;

fn get_metadata_path() -> PathBuf {
    Path::new(BACKUP_MOUNT_POINT).join(METADATA_FILE)
}

fn load_metadata() -> MetadataStore {
    let path = get_metadata_path();
    if !path.exists() {
        return HashMap::new();
    }
    let data = fs::read_to_string(path).unwrap_or_else(|_| "{}".to_string());
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_metadata(store: &MetadataStore) -> io::Result<()> {
    let json = serde_json::to_string_pretty(store)?;
    fs::write(get_metadata_path(), json)
}

fn check_vault_ready() {
    let vault_path = Path::new(BACKUP_MOUNT_POINT);
    let marker_file = vault_path.join(VAULT_MARKER_FILE);

    if !marker_file.exists() {
        eprintln!(
            "CRITICAL ERROR: Encrypted LUKS drive is not mounted (missing marker file in {}).",
            BACKUP_MOUNT_POINT
        );
        eprintln!("Unlock and mount the drive before using rm/unrm. Operation aborted to protect data.");
        process::exit(1);
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
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

fn safe_delete(targets: &[String]) {
    check_vault_ready();
    let mut store = load_metadata();

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
        let vault_dest = Path::new(BACKUP_MOUNT_POINT).join(&vault_filename);

        // Move item (copy across partitions + remove original)
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

    if let Err(e) = save_metadata(&store) {
        eprintln!("Warning: Failed to save metadata file: {}", e);
    }
}

fn restore_files(query: Option<&String>) {
    check_vault_ready();
    let mut store = load_metadata();

    if store.is_empty() {
        println!("Vault is empty. No files to restore.");
        return;
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
        return;
    }

    let target_entry = if matches.len() == 1 {
        &matches[0]
    } else {
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
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let idx: usize = input.trim().parse().unwrap_or_else(|_| {
            eprintln!("Invalid selection.");
            process::exit(1);
        });

        matches.get(idx).unwrap_or_else(|| {
            eprintln!("Selection out of range.");
            process::exit(1);
        })
    };

    let vault_src = Path::new(BACKUP_MOUNT_POINT).join(&target_entry.vault_filename);
    if !vault_src.exists() {
        eprintln!("Error: File is missing from the external vault!");
        return;
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
            let _ = save_metadata(&store);
            println!("Restored file as: {}", restored_path.display());
        }
        Err(e) => eprintln!("Error restoring file: {}", e),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} delete <file1> [file2...]", args[0]);
        eprintln!("  {} restore [name_fragment]", args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "delete" => safe_delete(&args[2..]),
        "restore" => restore_files(args.get(2)),
        _ => eprintln!("Unknown command. Use 'delete' or 'restore'."),
    }
}
