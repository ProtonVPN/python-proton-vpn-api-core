// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------
//! Who may change the kill switch.
//!
//! The nftables rules are machine-wide, but the service takes calls from any
//! local user. Without a check, user B could remove the kill switch user A
//! turned on — or replace it with one that no longer protects A — and leak A's
//! real IP. So the uid that installed the kill switch is recorded, and only
//! that uid or root may change it afterwards. One owner covers both tables.
//!
//! # The rule
//!
//! See [`authorize`]:
//!
//! | caller   | table installed? | recorded owner    | result                |
//! |----------|------------------|-------------------|-----------------------|
//! | root     | any              | any               | allowed               |
//! | anyone   | no               | any (ignored)     | allowed               |
//! | A        | yes              | A                 | allowed               |
//! | B        | yes              | A                 | [`NotOwner::OwnedBy`] |
//! | non-root | yes              | none / unreadable | [`NotOwner::Unknown`] |
//!
//! # Why it is tied to the tables
//!
//! The rules live in kernel memory, the record on disk. After a reboot
//! non-permanent rules are gone, so a leftover record must not lock the next
//! user out; permanent rules are re-applied by the boot unit, so the record
//! counts again. The same goes for tables removed out of band (`nft flush`,
//! `fwks down`). Hence the record only counts while a table is installed.
//!
//! The record is never deleted when the tables go, since the boot unit may
//! bring them back. Whoever installs next overwrites it.
//!
//! # The boot unit
//!
//! It can outlive the tables (permanent rules that failed to come back), so
//! for it the record counts even with no table installed: see
//! [`may_change_boot_unit`]. Known gap: an `Enable` with no table installed
//! is allowed and makes the caller the owner, boot unit included.
//!
//! # Failing closed
//!
//! A table installed with no record, or with one that cannot be read, may
//! only be changed by root: a corrupt file must not hand the kill switch to
//! whoever asks first.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::super::error::{Result, StateError};

/// Where the state file lives.
pub const STATE_DIR: &str = "/var/lib/Proton/VPN";

const STATE_FILE: &str = "firewall-kill-switch.json";

/// Root may always change the kill switch, so an administrator can never be
/// locked out.
pub const ROOT_UID: u32 = 0;

// Searchable by everyone, but only root can create or replace files in them;
// the file's own mode keeps its contents private. Not 0700, so the directories
// stay usable by other root components that share them.
const DIR_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o600;

/// What is persisted about the kill switch.
///
/// Unknown fields are ignored rather than rejected, so a later version can
/// add some and a downgraded service still reads the file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// The uid that installed the kill switch.
    pub owner_uid: u32,
}

/// Why a caller may not change the kill switch.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotOwner {
    #[error(
        "the kill switch is owned by uid {0}; only that user or root may \
         change it"
    )]
    OwnedBy(u32),

    #[error("the kill switch has no known owner; only root may change it")]
    Unknown,
}

/// Whether `caller` may change the kill switch. See the [module docs](self).
///
/// `owner` is the recorded owner, `None` when there is no record or it could
/// not be read; `installed` is whether either kill switch table is in place.
pub fn authorize(
    caller: u32,
    owner: Option<u32>,
    installed: bool,
) -> std::result::Result<(), NotOwner> {
    if caller == ROOT_UID || !installed {
        return Ok(());
    }

    match owner {
        Some(owner) if owner == caller => Ok(()),
        Some(owner) => Err(NotOwner::OwnedBy(owner)),
        None => Err(NotOwner::Unknown),
    }
}

/// Whether `caller` may turn boot persistence off.
///
/// Unlike [`authorize`], the record counts even with no table installed: the
/// boot unit may still be the owner's, waiting to bring the tables back.
pub fn may_change_boot_unit(caller: u32, owner: Option<u32>) -> bool {
    caller == ROOT_UID || owner.is_none_or(|owner| owner == caller)
}

/// The state file, `firewall-kill-switch.json` in [`STATE_DIR`].
pub struct StateStore {
    dir: PathBuf,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new(STATE_DIR)
    }
}

impl StateStore {
    /// A store in `dir` rather than [`STATE_DIR`], for tests.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    fn tmp_path(&self) -> PathBuf {
        self.dir.join(format!("{STATE_FILE}.tmp"))
    }

    /// The recorded state, `None` when there is none.
    ///
    /// Never errors: a file that cannot be read or parsed is logged and
    /// treated as missing, which [`authorize`] turns into "only root".
    pub fn load(&self) -> Option<State> {
        let path = self.path();

        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                log::error!("Could not read {}: {e}", path.display());
                return None;
            }
        };

        serde_json::from_slice(&contents)
            .inspect_err(|e| log::error!("Corrupt {}: {e}", path.display()))
            .ok()
    }

    /// The recorded owner, `None` when there is none or it cannot be read.
    pub fn owner(&self) -> Option<u32> {
        self.load().map(|state| state.owner_uid)
    }

    /// Record `state`, atomically: a crash leaves either the old file or the
    /// new one, never a truncated one that would lock the owner out.
    pub fn save(&self, state: &State) -> Result<()> {
        self.write(state).map_err(|e| StateError::Write(e).into())
    }

    fn write(&self, state: &State) -> io::Result<()> {
        create_dirs(&self.dir)?;

        let tmp = self.tmp_path();
        let contents = serde_json::to_vec(state)?;

        // A leftover from an earlier crash may have any mode, and opening an
        // existing file does not change it, so start from scratch.
        remove_if_present(&tmp)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp)?;
        file.write_all(&contents)?;
        file.sync_all()?;

        fs::rename(&tmp, self.path())?;

        // The rename itself only survives a crash once the directory is
        // synced.
        File::open(&self.dir)?.sync_all()
    }

    /// Delete the record. Idempotent: succeeds when there is none.
    pub fn remove(&self) -> Result<()> {
        remove_if_present(&self.path())
            .map_err(|e| StateError::Remove(e).into())
    }

    /// Put back what [`load`](Self::load) returned earlier: save it, or remove
    /// the record when there was none.
    pub fn restore(&self, previous: Option<&State>) -> Result<()> {
        match previous {
            Some(state) => self.save(state),
            None => self.remove(),
        }
    }
}

/// Create `dir` and any missing parents with [`DIR_MODE`], leaving existing
/// ones alone.
fn create_dirs(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }

    if let Some(parent) = dir.parent() {
        create_dirs(parent)?;
    }

    match DirBuilder::new().mode(DIR_MODE).create(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        result => result?,
    }

    // The umask may have taken bits off.
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// A directory removed again on drop, for tests that need a real
/// [`StateStore`].
#[cfg(test)]
pub(super) struct TempDir(tempfile::TempDir);

#[cfg(test)]
impl TempDir {
    /// Randomly named and created private (0700, whatever the umask), so
    /// tests can run in parallel and nobody else can plant files in it.
    /// `test` only makes it recognisable.
    pub(super) fn new(test: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("proton-vpn-kill-switch-{test}-"))
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();

        Self(dir)
    }

    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u32 = 1000;
    const B: u32 = 1001;

    #[test]
    fn root_is_always_allowed() {
        for owner in [None, Some(A)] {
            for installed in [false, true] {
                assert_eq!(authorize(ROOT_UID, owner, installed), Ok(()));
            }
        }
    }

    #[test]
    fn anyone_is_allowed_when_no_table_is_installed() {
        // A stale record, e.g. from before a reboot, must not lock B out.
        assert_eq!(authorize(B, Some(A), false), Ok(()));
        assert_eq!(authorize(B, None, false), Ok(()));
    }

    #[test]
    fn the_owner_is_allowed() {
        assert_eq!(authorize(A, Some(A), true), Ok(()));
    }

    #[test]
    fn another_user_is_refused() {
        assert_eq!(authorize(B, Some(A), true), Err(NotOwner::OwnedBy(A)));
    }

    #[test]
    fn non_root_is_refused_when_the_owner_is_unknown() {
        // Fails closed: a table with no readable record is root's alone.
        assert_eq!(authorize(A, None, true), Err(NotOwner::Unknown));
    }

    #[test]
    fn the_boot_unit_stays_the_recorded_owners() {
        // Even with no table installed: it may be about to bring them back.
        assert!(!may_change_boot_unit(B, Some(A)));
        assert!(may_change_boot_unit(A, Some(A)));
        assert!(may_change_boot_unit(ROOT_UID, Some(A)));
        assert!(may_change_boot_unit(B, None));
    }

    #[test]
    fn a_missing_file_has_no_state() {
        let dir = TempDir::new("a_missing_file_has_no_state");

        assert_eq!(StateStore::new(dir.path()).load(), None);
    }

    #[test]
    fn saved_state_reads_back() {
        let dir = TempDir::new("saved_state_reads_back");
        let store = StateStore::new(dir.path());

        store.save(&State { owner_uid: A }).unwrap();

        assert_eq!(store.load(), Some(State { owner_uid: A }));
        assert_eq!(store.owner(), Some(A));
        assert!(!store.tmp_path().exists());
    }

    #[test]
    fn save_overwrites() {
        let dir = TempDir::new("save_overwrites");
        let store = StateStore::new(dir.path());

        store.save(&State { owner_uid: A }).unwrap();
        store.save(&State { owner_uid: B }).unwrap();

        assert_eq!(store.owner(), Some(B));
    }

    #[test]
    fn save_creates_private_file_in_world_readable_dirs() {
        let dir = TempDir::new("save_creates_private_file");
        let state_dir = dir.path().join("Proton").join("VPN");
        let store = StateStore::new(&state_dir);

        store.save(&State { owner_uid: A }).unwrap();

        let mode = |path: &Path| {
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        assert_eq!(mode(&dir.path().join("Proton")), 0o755);
        assert_eq!(mode(&state_dir), 0o755);
        assert_eq!(mode(&store.path()), 0o600);
    }

    #[test]
    fn a_corrupt_file_has_no_state() {
        let dir = TempDir::new("a_corrupt_file_has_no_state");
        let store = StateStore::new(dir.path());

        fs::write(store.path(), b"{\"owner_uid\": ").unwrap();

        assert_eq!(store.load(), None);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // So a newer version can add fields without breaking a downgrade.
        let dir = TempDir::new("unknown_fields_are_ignored");
        let store = StateStore::new(dir.path());

        fs::write(store.path(), b"{\"owner_uid\": 1000, \"permanent\": true}")
            .unwrap();

        assert_eq!(store.owner(), Some(A));
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = TempDir::new("remove_is_idempotent");
        let store = StateStore::new(dir.path());

        store.save(&State { owner_uid: A }).unwrap();
        store.remove().unwrap();
        store.remove().unwrap();

        assert_eq!(store.load(), None);
    }

    #[test]
    fn restore_saves_the_previous_state() {
        let dir = TempDir::new("restore_saves_the_previous_state");
        let store = StateStore::new(dir.path());

        store.save(&State { owner_uid: B }).unwrap();
        store.restore(Some(&State { owner_uid: A })).unwrap();

        assert_eq!(store.owner(), Some(A));
    }

    #[test]
    fn restore_removes_when_there_was_no_state() {
        let dir = TempDir::new("restore_removes_when_there_was_no_state");
        let store = StateStore::new(dir.path());

        store.save(&State { owner_uid: B }).unwrap();
        store.restore(None).unwrap();

        assert_eq!(store.load(), None);
    }
}
