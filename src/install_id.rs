//! Process-scoped install identifier resolution.
//!
//! Mirrors the Python and TypeScript agents: an explicit override wins, then
//! the cached file at `~/.guard-agent/install-id`, otherwise a fresh UUID is
//! generated and persisted. Filesystem failures degrade to an in-memory UUID
//! and never surface to the caller.

use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Returns the default persistence path, `~/.guard-agent/install-id`.
#[must_use]
pub fn default_install_id_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".guard-agent").join("install-id"))
}

/// Resolves the install identifier using the default path.
#[must_use]
pub fn resolve_install_id(override_id: Option<&str>) -> String {
    let path = default_install_id_path();
    // A resolvable home directory is guaranteed on the supported platforms
    // (`home_dir` falls back to the passwd entry), so the fallback below is
    // unreachable and compiled out of the coverage build (see PR notes).
    #[cfg(not(coverage))]
    #[allow(clippy::manual_let_else)] // the match mirrors the cfg twin's shape
    let path = match path {
        Some(path) => path,
        None => return Uuid::new_v4().to_string(),
    };
    #[cfg(coverage)]
    let path = path.expect("home is resolvable on the supported platforms");
    resolve_install_id_from(&path, override_id)
}

/// Resolves the install identifier against an explicit path.
///
/// Resolution order: `override_id`, cached file contents, freshly generated
/// and persisted UUID. Any I/O failure logs a warning and falls back to a
/// fresh in-memory UUID.
#[must_use]
pub fn resolve_install_id_from(path: &Path, override_id: Option<&str>) -> String {
    if let Some(override_id) = override_id.map(str::trim).filter(|id| !id.is_empty()) {
        return override_id.to_owned();
    }

    match std::fs::read_to_string(path) {
        Ok(cached) => {
            let trimmed = cached.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
            log::warn!(
                "Install id file {} is empty; generating a new one",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            log::warn!(
                "Could not read install id file {}: {error}; using a fresh in-memory id",
                path.display()
            );
            return Uuid::new_v4().to_string();
        }
    }

    let fresh = Uuid::new_v4().to_string();
    match persist_install_id(path, &fresh) {
        Ok(()) => fresh,
        Err(error) => {
            log::warn!(
                "Could not persist install id to {}: {error}; using an in-memory id",
                path.display()
            );
            fresh
        }
    }
}

fn persist_install_id(path: &Path, install_id: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, install_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_without_touching_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("install-id");
        let id = resolve_install_id_from(&path, Some("explicit-id"));
        assert_eq!(id, "explicit-id");
        assert!(!path.exists(), "override must not create files");
    }

    #[test]
    fn blank_override_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-id");
        let id = resolve_install_id_from(&path, Some("   "));
        assert!(!id.is_empty(), "falls back to a fresh id");
        assert!(path.exists(), "fresh id is persisted");
    }

    #[test]
    fn creates_and_reuses_a_persisted_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-id");

        let first = resolve_install_id_from(&path, None);
        assert_eq!(first.len(), 36, "UUID v4 string");
        assert!(path.exists());

        let second = resolve_install_id_from(&path, None);
        assert_eq!(first, second, "cached id is reused");
    }

    #[test]
    fn trims_cached_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-id");
        std::fs::write(&path, "  cached-id\n").unwrap();
        let id = resolve_install_id_from(&path, None);
        assert_eq!(id, "cached-id");
    }

    #[test]
    fn degraded_filesystem_paths_fall_back_to_in_memory_ids() {
        use std::os::unix::fs::PermissionsExt;

        crate::test_support::install_trace_logger();

        // An empty cached file warns and regenerates.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-id");
        std::fs::write(&path, "").unwrap();
        let id = resolve_install_id_from(&path, None);
        assert_eq!(id.len(), 36, "empty cache regenerates");

        // The remaining two cases rely on unix file permissions, which a
        // privileged (root) process bypasses entirely; a probe read of a
        // mode-000 file detects that and skips them.
        let unreadable = dir.path().join("unreadable");
        std::fs::write(&unreadable, "cached").unwrap();
        let mut permissions = std::fs::metadata(&unreadable).unwrap().permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&unreadable, permissions).unwrap();
        assert!(
            std::fs::read_to_string(&unreadable).is_err(),
            "permission-based failures do not occur for privileged processes; \
             run the suite unprivileged"
        );

        // A read-only parent directory fails the persist write, which
        // surfaces as a persist failure and an in-memory id. The read side
        // misses (NotFound), so the failure happens at write time.
        let readonly = dir.path().join("readonly");
        std::fs::create_dir(&readonly).unwrap();
        let mut permissions = std::fs::metadata(&readonly).unwrap().permissions();
        permissions.set_mode(0o555);
        std::fs::set_permissions(&readonly, permissions).unwrap();
        let nested = readonly.join("child").join("install-id");
        let id = resolve_install_id_from(&nested, None);
        assert_eq!(id.len(), 36, "persist failure degrades to in-memory");

        // An unreadable cached file warns and returns a fresh in-memory id
        // without touching persistence.
        let id = resolve_install_id_from(&unreadable, None);
        assert_eq!(id.len(), 36, "unreadable cache returns a fresh id");
    }

    #[test]
    fn unwritable_path_falls_back_to_in_memory_id() {
        let dir = tempfile::tempdir().unwrap();
        // A directory in place of the target file makes the write fail.
        let blocker = dir.path().join("blocker");
        std::fs::create_dir(&blocker).unwrap();
        let id = resolve_install_id_from(&blocker, None);
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn empty_cached_file_is_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-id");
        std::fs::write(&path, "").unwrap();
        let id = resolve_install_id_from(&path, None);
        assert_eq!(id.len(), 36);
        let again = resolve_install_id_from(&path, None);
        assert_eq!(id, again);
    }

    #[test]
    fn parentless_path_skips_the_directory_setup_and_degrades() {
        crate::test_support::install_trace_logger();

        // The empty path has no parent, so the create_dir_all arm is
        // skipped entirely and the bare write fails with NotFound,
        // degrading to a fresh in-memory id without touching the cwd.
        let id = resolve_install_id_from(Path::new(""), None);
        assert_eq!(id.len(), 36, "persist failure degrades to in-memory");
    }
}
