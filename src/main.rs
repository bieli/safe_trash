use safe_trash::{TrashVault, DEFAULT_BACKUP_MOUNT_POINT};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} delete <file1> [file2...]", args);
        eprintln!("  {} restore [name_fragment]", args);
        eprintln!("  {} list", args);
        process::exit(1);
    }

    let mount_point =
        env::var("SAFE_TRASH_VAULT").unwrap_or_else(|_| DEFAULT_BACKUP_MOUNT_POINT.to_string());
    let vault = TrashVault::new(mount_point);

    match args.as_str() {
        "delete" => {
            if let Err(err) = vault.safe_delete(&args[2..]) {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
        "restore" => {
            let query = args.get(2).map(|s| s.as_str());
            if let Err(err) = vault.restore_files(query, None) {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
        "list" => {
            if let Err(err) = vault.list_entries() {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
        _ => {
            eprintln!("Unknown command. Use 'delete', 'restore', or 'list'.");
            process::exit(1);
        }
    }
}
