// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! A tarball install's directories, given back to root at every start.
//!
//! Up to 0.4.126 the universal tarball recorded its directory entries (`usr/`,
//! `usr/bin/`, `usr/lib/` …) with the CI builder's own uid, 1001. `install.sh`
//! extracted it with `sudo tar -xzf … -C /`, and GNU tar running as root
//! restores the archive's owners, onto directories that already exist too. So
//! every install that took the tarball path (any host without dpkg: Fedora,
//! RHEL, SUSE, Arch …) left `/usr`, `/usr/bin`, `/usr/lib` and the systemd
//! unit directories owned by whichever local account holds that uid: write
//! access to every binary and every unit, so root. Measured on the FR-93 lab
//! (Fedora 44, the released 0.4.126).
//!
//! The archive and `install.sh` are fixed, but neither reaches a host that is
//! already damaged: its daemon updates through the OLD updater, which copies
//! files and never looks at a directory. So the daemon, as root, repairs at
//! every start. It costs a dozen `fstat`s on a healthy host.
//!
//! ⚠️ This is root changing directories that another account may own, the
//! case a symlink swap turns into a write anywhere. The walk is built so that
//! cannot happen:
//! - every path is opened one component at a time, with `openat(…,
//!   O_NOFOLLOW)` from the previous component's descriptor, starting from `/`.
//!   No path is ever resolved by name, so no symlink anywhere along it is
//!   followed, and a symlink where a directory belongs ends that walk;
//! - owner and mode are changed through the opened descriptor (`fchown`,
//!   `fchmod`), never by path;
//! - parents are repaired before children, so by the time a child is opened
//!   its parent is root's and nothing can be renamed under the walk.
//!
//! Owner goes to root:root. The mode only loses group and other write; bits are
//! never added. A distribution's own mode (Fedora ships `/usr/bin` and
//! `/usr/lib` 0555) is `install.sh`'s to restore from the package database.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// The directories a tarball carried, PARENT BEFORE CHILD, relative to `/`.
// RETIRED-NAME-ANCHOR(12): usr/lib/meshharbor is the binary's RPATH and
// usr/share/doc/meshharbor the payload's doc dir: what the tarball installs.
pub(crate) const TARBALL_DIRS: &[&str] = &[
    "usr",
    "usr/bin",
    "usr/lib",
    "usr/lib/meshharbor",
    "usr/lib/systemd",
    "usr/lib/systemd/system",
    "usr/lib/systemd/user",
    "usr/share",
    "usr/share/doc",
    "usr/share/doc/meshharbor",
];

/// The files it carried that an update does not rewrite: the units and the
/// README are written only when absent, so a damaged host keeps the old owner
/// on them. The bundled libraries are found, not listed.
// RETIRED-NAME-ANCHOR(6): the same payload dirs, for the files in them.
pub(crate) const TARBALL_FILES: &[&str] = &[
    "usr/bin/meshharbord",
    "usr/bin/meshharbor",
    "usr/lib/systemd/system/meshharbord.service",
    "usr/lib/systemd/user/meshharbor.service",
    "usr/share/doc/meshharbor/README.Debian",
];
// RETIRED-NAME-ANCHOR: the RPATH-bound library dir, scanned for its files.
const TARBALL_LIB_DIR: &str = "usr/lib/meshharbor";

/// What the walk did with one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Owned by root already: nothing done.
    Fine,
    /// Was `uid:gid` (and the old mode); now root's, without group or other write.
    Repaired { uid: u32, gid: u32, mode: u32 },
    /// Not there.
    Absent,
    /// A symlink, or not the expected kind of file: left alone, and nothing
    /// below it touched.
    Refused(String),
    /// The change itself failed (not root, or a read-only filesystem).
    Failed(String),
}

/// One walk over `root` (`/` in production, a scratch tree in a test).
pub fn repair_under(root: &Path) -> Vec<(PathBuf, Outcome)> {
    let mut out = Vec::new();
    let root_fd = match open_dir_path(root) {
        Ok(fd) => fd,
        Err(e) => {
            out.push((root.to_path_buf(), Outcome::Failed(e.to_string())));
            return out;
        }
    };
    for rel in TARBALL_DIRS {
        out.push((root.join(rel), repair_one(&root_fd, rel, Kind::Dir)));
    }
    for rel in TARBALL_FILES {
        out.push((root.join(rel), repair_one(&root_fd, rel, Kind::File)));
    }
    // The bundled libraries, only once their directory is known to be a real
    // one that is root's: then its entries cannot be swapped under the scan.
    let lib_dir_ok = out.iter().any(|(p, o)| {
        p == &root.join(TARBALL_LIB_DIR) && matches!(o, Outcome::Fine | Outcome::Repaired { .. })
    });
    let entries = lib_dir_ok
        .then(|| std::fs::read_dir(root.join(TARBALL_LIB_DIR)).ok())
        .flatten();
    if let Some(entries) = entries {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".so"))
            .collect();
        names.sort();
        for name in names {
            let rel = format!("{TARBALL_LIB_DIR}/{name}");
            out.push((root.join(&rel), repair_one(&root_fd, &rel, Kind::File)));
        }
    }
    out
}

/// The production walk, logged. Linux, root only; a no-op elsewhere.
pub fn repair_at_start() {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    for (path, outcome) in repair_under(Path::new("/")) {
        match outcome {
            Outcome::Fine | Outcome::Absent => {}
            Outcome::Repaired { uid, gid, mode } => tracing::warn!(
                path = %path.display(),
                uid,
                gid,
                mode = %format!("{mode:o}"),
                "tarball install: repaired a path an earlier tarball install had left another \
                 account's; now root's, without group or other write"
            ),
            Outcome::Refused(why) => tracing::warn!(
                path = %path.display(),
                why = %why,
                "tarball install: left a path alone, and everything below it"
            ),
            Outcome::Failed(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "tarball install: could not repair a path"
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
}

/// Walk `rel` from `root_fd` one component at a time, never following a
/// symlink, then repair the last component through its own descriptor.
fn repair_one(root_fd: &OwnedFd, rel: &str, kind: Kind) -> Outcome {
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    let Some((last, parents)) = parts.split_last() else {
        return Outcome::Absent;
    };
    // The walk owns each parent's descriptor in turn; the root's stays borrowed.
    let mut held: Option<OwnedFd> = None;
    for part in parents {
        let parent = held.as_ref().unwrap_or(root_fd);
        match openat_nofollow(parent, part, true) {
            Ok(fd) => held = Some(fd),
            Err(e) => return refused_or_absent(parent, part, e, "a parent"),
        }
    }
    let parent = held.as_ref().unwrap_or(root_fd);
    let fd = match openat_nofollow(parent, last, kind == Kind::Dir) {
        Ok(fd) => fd,
        Err(e) => return refused_or_absent(parent, last, e, "the path itself"),
    };
    // SAFETY: an all-zero `stat` is a valid value for fstat to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a live descriptor owned above; `st` is a valid out-pointer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Outcome::Failed(std::io::Error::last_os_error().to_string());
    }
    let is_kind = match kind {
        Kind::Dir => st.st_mode & libc::S_IFMT == libc::S_IFDIR,
        Kind::File => st.st_mode & libc::S_IFMT == libc::S_IFREG,
    };
    if !is_kind {
        return Outcome::Refused("not the expected kind of file".into());
    }
    if st.st_uid == 0 && st.st_gid == 0 {
        return Outcome::Fine;
    }
    // SAFETY: as above; fchown changes the object `fd` names, never a path.
    if unsafe { libc::fchown(fd.as_raw_fd(), 0, 0) } != 0 {
        return Outcome::Failed(std::io::Error::last_os_error().to_string());
    }
    let mode = st.st_mode & 0o7777;
    let stripped = mode & !0o022;
    // SAFETY: as above.
    if stripped != mode && unsafe { libc::fchmod(fd.as_raw_fd(), stripped) } != 0 {
        return Outcome::Failed(std::io::Error::last_os_error().to_string());
    }
    Outcome::Repaired {
        uid: st.st_uid,
        gid: st.st_gid,
        mode,
    }
}

/// Why `name` under `parent` would not open. A symlink can fail either way:
/// O_NOFOLLOW alone makes it ELOOP, but with O_DIRECTORY the kernel checks
/// the type first and answers ENOTDIR (measured: the symlink test saw
/// ENOTDIR). So the entry itself is asked, with `fstatat(…,
/// AT_SYMLINK_NOFOLLOW)`, which reads and never follows.
fn refused_or_absent(parent: &OwnedFd, name: &str, e: std::io::Error, what: &str) -> Outcome {
    match e.raw_os_error() {
        Some(libc::ENOENT) => Outcome::Absent,
        Some(libc::ELOOP | libc::ENOTDIR) if is_symlink(parent, name) => {
            Outcome::Refused(format!("{what} is a symlink"))
        }
        Some(libc::ELOOP) => Outcome::Refused(format!("{what} is a symlink")),
        Some(libc::ENOTDIR) => Outcome::Refused(format!("{what} is not a directory")),
        _ => Outcome::Failed(e.to_string()),
    }
}

/// Is `name` under `parent` a symlink? `fstatat` with AT_SYMLINK_NOFOLLOW
/// describes the entry itself; nothing is followed or opened.
fn is_symlink(parent: &OwnedFd, name: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: an all-zero `stat` is a valid value for fstatat to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `parent` is a live descriptor, `c` NUL-terminated, `st` a valid
    // out-pointer.
    let r = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// `openat(parent, name, O_NOFOLLOW)`: a directory, or a regular file opened
/// without blocking (a planted FIFO must not hang the daemon's start).
fn openat_nofollow(parent: &OwnedFd, name: &str, dir: bool) -> std::io::Result<OwnedFd> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    flags |= if dir {
        libc::O_DIRECTORY
    } else {
        libc::O_NONBLOCK | libc::O_NOCTTY
    };
    // SAFETY: `parent` is a live descriptor; `c` is a NUL-terminated string.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The walk's root, `/` itself, opened by path: it is the one component no
/// other account can own.
fn open_dir_path(path: &Path) -> std::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `c` is a NUL-terminated string.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by open and is owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A tree shaped like a tarball install, under a scratch root.
    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("tempdir");
        for d in TARBALL_DIRS {
            std::fs::create_dir_all(t.path().join(d)).expect("mkdir");
        }
        for f in TARBALL_FILES {
            std::fs::write(t.path().join(f), b"x").expect("write");
        }
        std::fs::write(t.path().join(TARBALL_LIB_DIR).join("libvpx.so.9"), b"x").expect("write");
        t
    }

    fn outcome<'a>(report: &'a [(PathBuf, Outcome)], root: &Path, rel: &str) -> &'a Outcome {
        &report
            .iter()
            .find(|(p, _)| p == &root.join(rel))
            .unwrap_or_else(|| panic!("{rel} not in the report"))
            .1
    }

    fn running_as_root() -> bool {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    /// Unprivileged: every path of the tree is visited, in order, and none of
    /// them can be changed (they are the test user's, and fchown to root is
    /// refused), so each is `Failed` — never skipped, never `Fine`.
    #[test]
    fn every_path_is_visited_parent_first() {
        if running_as_root() {
            return;
        }
        let t = tree();
        let report = repair_under(t.path());
        let dirs: Vec<&PathBuf> = report
            .iter()
            .take(TARBALL_DIRS.len())
            .map(|(p, _)| p)
            .collect();
        let want: Vec<PathBuf> = TARBALL_DIRS.iter().map(|d| t.path().join(d)).collect();
        assert_eq!(dirs, want.iter().collect::<Vec<_>>(), "parent before child");
        for rel in TARBALL_DIRS.iter().chain(TARBALL_FILES) {
            assert!(
                matches!(outcome(&report, t.path(), rel), Outcome::Failed(_)),
                "{rel}"
            );
        }
        let lib = format!("{TARBALL_LIB_DIR}/libvpx.so.9");
        assert!(
            report.iter().all(|(p, _)| p != &t.path().join(&lib)),
            "no lib scan under a dir the walk could not take"
        );
    }

    /// A symlink where a directory belongs is refused, and nothing below it
    /// is followed: the target it points at keeps its owner and mode.
    #[test]
    fn a_symlink_stops_the_walk_there() {
        let t = tree();
        let elsewhere = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(elsewhere.path().join("system")).expect("mkdir");
        std::fs::set_permissions(elsewhere.path(), std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        let systemd = t.path().join("usr/lib/systemd");
        std::fs::remove_dir_all(&systemd).expect("rm");
        std::os::unix::fs::symlink(elsewhere.path(), &systemd).expect("symlink");
        let before = std::fs::metadata(elsewhere.path()).expect("stat");
        let report = repair_under(t.path());
        assert!(
            matches!(outcome(&report, t.path(), "usr/lib/systemd"), Outcome::Refused(w) if w.contains("symlink")),
            "{:?}",
            outcome(&report, t.path(), "usr/lib/systemd")
        );
        for rel in ["usr/lib/systemd/system", "usr/lib/systemd/user"] {
            assert!(
                matches!(outcome(&report, t.path(), rel), Outcome::Refused(w) if w.contains("a parent")),
                "{rel}: {:?}",
                outcome(&report, t.path(), rel)
            );
        }
        let after = std::fs::metadata(elsewhere.path()).expect("stat");
        assert_eq!(
            (before.uid(), before.mode()),
            (after.uid(), after.mode()),
            "the symlink's target was touched"
        );
    }

    #[test]
    fn a_missing_path_is_absent_and_a_file_where_a_dir_belongs_is_refused() {
        let t = tree();
        std::fs::remove_dir_all(t.path().join("usr/share/doc")).expect("rm");
        std::fs::write(t.path().join("usr/share/doc"), b"not a dir").expect("write");
        std::fs::remove_file(t.path().join("usr/bin/meshharbor")).expect("rm");
        let report = repair_under(t.path());
        assert!(matches!(
            outcome(&report, t.path(), "usr/share/doc"),
            Outcome::Refused(_)
        ));
        assert!(matches!(
            outcome(&report, t.path(), "usr/bin/meshharbor"),
            Outcome::Absent
        ));
    }

    /// As root (CI's sudo lane; `ROOMLERD_TEST_REQUIRE_ROOT=1` turns a skip
    /// into a failure): a tree owned by uid 1001 with a group-writable
    /// directory comes back root's, write taken from group and others, no bit
    /// added; a root-owned path is left alone.
    #[test]
    fn as_root_the_tree_comes_back_root_s() {
        if !running_as_root() {
            assert!(
                std::env::var_os("ROOMLERD_TEST_REQUIRE_ROOT").is_none(),
                "ROOMLERD_TEST_REQUIRE_ROOT is set, and this test is not root"
            );
            return;
        }
        let t = tree();
        let all: Vec<PathBuf> = TARBALL_DIRS
            .iter()
            .chain(TARBALL_FILES)
            .map(|r| t.path().join(r))
            .chain([t.path().join(TARBALL_LIB_DIR).join("libvpx.so.9")])
            .collect();
        for p in &all {
            let c = std::ffi::CString::new(p.to_str().expect("utf-8")).expect("cstr");
            // SAFETY: a valid path; the test owns the tree.
            assert_eq!(
                unsafe { libc::chown(c.as_ptr(), 1001, 1001) },
                0,
                "{}",
                p.display()
            );
        }
        std::fs::set_permissions(
            t.path().join("usr/bin"),
            std::fs::Permissions::from_mode(0o775),
        )
        .expect("chmod");
        std::fs::set_permissions(
            t.path().join("usr/lib"),
            std::fs::Permissions::from_mode(0o555),
        )
        .expect("chmod");
        let report = repair_under(t.path());
        for p in &all {
            let m = std::fs::symlink_metadata(p).expect("stat");
            assert_eq!((m.uid(), m.gid()), (0, 0), "{}", p.display());
            assert_eq!(
                m.mode() & 0o022,
                0,
                "{} still group/other writable",
                p.display()
            );
        }
        assert_eq!(
            std::fs::metadata(t.path().join("usr/bin"))
                .expect("stat")
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(t.path().join("usr/lib"))
                .expect("stat")
                .mode()
                & 0o777,
            0o555,
            "a bit was added"
        );
        assert!(matches!(
            outcome(&report, t.path(), "usr/bin"),
            Outcome::Repaired {
                uid: 1001,
                gid: 1001,
                mode: 0o775
            }
        ));
        // A second walk finds nothing to do.
        let again = repair_under(t.path());
        assert!(
            again.iter().all(|(_, o)| matches!(o, Outcome::Fine)),
            "{again:?}"
        );
    }
}
