use safe_trash::{TrashVault, VAULT_MARKER_FILE};
use std::fs;
use tempfile::TempDir;

/// Helper to create a simulated mounted LUKS vault with the marker file present
fn setup_ready_vault() -> (TempDir, TrashVault) {
    let vault_dir = TempDir::new().expect("Failed to create temp vault dir");
    fs::write(vault_dir.path().join(VAULT_MARKER_FILE), "")
        .expect("Failed to create marker file");
    let vault = TrashVault::new(vault_dir.path());
    (vault_dir, vault)
}

#[test]
fn test_aborts_when_luks_marker_missing() {
    let unmounted_dir = TempDir::new().unwrap();
    let work_dir = TempDir::new().unwrap();

    let victim_file = work_dir.path().join("important.txt");
    fs::write(&victim_file, "critical data").unwrap();

    let vault = TrashVault::new(unmounted_dir.path());
    let result = vault.safe_delete(&[victim_file.to_string_lossy().to_string()]);

    assert!(result.is_err(), "Should fail when marker file is absent");
    assert!(
        victim_file.exists(),
        "Original file must NOT be deleted when vault is unmounted"
    );
}

#[test]
fn test_delete_and_restore_single_file() {
    let (_vault_dir, vault) = setup_ready_vault();
    let work_dir = TempDir::new().unwrap();

    let original_file = work_dir.path().join("cnc_simulation.mp4");
    fs::write(&original_file, b"fake video binary data").unwrap();

    // 1. Delete file
    let deleted = vault
        .safe_delete(&[original_file.to_string_lossy().to_string()])
        .expect("safe_delete failed");

    assert_eq!(deleted.len(), 1);
    assert!(!original_file.exists(), "Original file should be removed");
    assert_eq!(vault.load_metadata().len(), 1);

    // 2. Restore latest file (unrm with no arguments)
    let restored_path = vault
        .restore_files(None, None)
        .expect("restore_files failed")
        .expect("Expected a restored path");

    let expected_restored = work_dir
        .path()
        .join("cnc_simulation.mp4.restored_from_deleted");
    assert_eq!(restored_path, expected_restored);
    assert!(expected_restored.exists());
    assert_eq!(
        fs::read(&expected_restored).unwrap(),
        b"fake video binary data"
    );
    assert!(
        vault.load_metadata().is_empty(),
        "Vault metadata should be empty after restoration"
    );
}

#[test]
fn test_delete_and_restore_directory_recursively() {
    let (_vault_dir, vault) = setup_ready_vault();
    let work_dir = TempDir::new().unwrap();

    let project_dir = work_dir.path().join("gcode_project");
    let sub_dir = project_dir.join("nested");
    fs::create_dir_all(&sub_dir).unwrap();
    fs::write(sub_dir.join("part1.nc"), "G01 X10 Y20").unwrap();

    // Delete directory while passing standard rm flags (-rf)
    vault
        .safe_delete(&[
            "-rf".to_string(),
            project_dir.to_string_lossy().to_string(),
        ])
        .expect("Failed to delete directory");

    assert!(!project_dir.exists());

    // Restore directory
    let restored_dir = vault
        .restore_files(Some("gcode_project"), None)
        .unwrap()
        .unwrap();

    let expected_dir = work_dir
        .path()
        .join("gcode_project.restored_from_deleted");
    assert_eq!(restored_dir, expected_dir);
    assert_eq!(
        fs::read_to_string(expected_dir.join("nested/part1.nc")).unwrap(),
        "G01 X10 Y20"
    );
}

#[test]
fn test_restore_multiple_matches_by_index() {
    let (_vault_dir, vault) = setup_ready_vault();
    let work_dir = TempDir::new().unwrap();

    let file_a = work_dir.path().join("report_v1.txt");
    let file_b = work_dir.path().join("report_v2.txt");
    fs::write(&file_a, "version 1").unwrap();
    fs::write(&file_b, "version 2").unwrap();

    vault
        .safe_delete(&[file_a.to_string_lossy().to_string()])
        .unwrap();
    // Slight sleep to ensure distinct microsecond timestamps & deterministic sorting
    std::thread::sleep(std::time::Duration::from_millis(5));
    vault
        .safe_delete(&[file_b.to_string_lossy().to_string()])
        .unwrap();

    // Index 0 is newest (report_v2.txt), index 1 is older (report_v1.txt)
    let restored = vault
        .restore_files(Some("report"), Some(1))
        .unwrap()
        .unwrap();

    assert!(restored.ends_with("report_v1.txt.restored_from_deleted"));
    assert_eq!(fs::read_to_string(&restored).unwrap(), "version 1");
    assert_eq!(
        vault.load_metadata().len(),
        1,
        "report_v2.txt should remain in vault"
    );
}

#[test]
fn test_list_entries_returns_sorted_items() {
    let (_vault_dir, vault) = setup_ready_vault();
    let work_dir = TempDir::new().unwrap();

    let first = work_dir.path().join("first.txt");
    let second = work_dir.path().join("second.txt");
    fs::write(&first, "1").unwrap();
    fs::write(&second, "2").unwrap();

    vault
        .safe_delete(&[first.to_string_lossy().to_string()])
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    vault
        .safe_delete(&[second.to_string_lossy().to_string()])
        .unwrap();

    let listed = vault.list_entries().expect("list_entries failed");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed.original_path.file_name().unwrap(), "second.txt");
    assert_eq!(listed.original_path.file_name().unwrap(), "first.txt");
}
