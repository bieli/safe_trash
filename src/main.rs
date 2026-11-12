use safe_trash::{TrashVault, DEFAULT_BACKUP_MOUNT_POINT};
use std::env;
use std::process;

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {} delete <file1> [file2...]", program);
    eprintln!("  {} restore [name_fragment]", program);
    eprintln!("  {} list", program);
    eprintln!("  {} clean <days> [--dry-run]", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let mount_point =
        env::var("SAFE_TRASH_VAULT").unwrap_or_else(|_| DEFAULT_BACKUP_MOUNT_POINT.to_string());
    let vault = TrashVault::new(mount_point);

    match args[1].as_str() {
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
        "clean" => {
            let days_str = match args.get(2) {
                Some(d) => d,
                None => {
                    eprintln!("Error: Missing <days> argument for 'clean'.");
                    print_usage(&args[0]);
                    process::exit(1);
                }
            };

            let days: i64 = match days_str.parse() {
                Ok(d) if d >= 0 => d,
                _ => {
                    eprintln!("Error: <days> must be a non-negative integer.");
                    process::exit(1);
                }
            };

            let dry_run = args.iter().skip(3).any(|arg| arg == "--dry-run");

            if let Err(err) = vault.clean_older_than(days, dry_run) {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
        _ => {
            eprintln!("Unknown command '{}'.", args[1]);
            print_usage(&args[0]);
            process::exit(1);
        }
    }
}
