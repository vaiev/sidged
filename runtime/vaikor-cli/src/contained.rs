// Copyright 2026 VAIEV
// SPDX-License-Identifier: Apache-2.0
//! Workspace file operations confined to one directory handle (ROADMAP 11g).
//!
//! A root (the node's `<workspace>/files`) is opened once without following a symlink and
//! must be a directory owned by the Core uid. Every later open resolves relative to that
//! handle with Linux `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS)`: the kernel refuses a path above the root, an absolute path and
//! a symlink anywhere on the way at the moment of the open, so a directory swapped in
//! between a check and a use cannot redirect the operation. Paths are also checked
//! lexically first for a clear refusal. A file with more than one hard link is refused, so
//! a link to a file outside the root does not reach it either. A kernel without `openat2`
//! (before Linux 5.6) refuses every operation; there is no pathname fallback.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// `struct open_how` of `openat2(2)` (Linux UAPI, stable since 5.6); declared here because
/// the `libc` crate does not provide it for every target the Core builds for (Android).
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// The kind of a directory entry, read without following it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
    Other,
}

/// A directory handle; every path is resolved beneath it.
#[derive(Debug)]
pub(crate) struct Dir {
    fd: OwnedFd,
}

/// `rel` as a C path when it is relative and made of plain components only.
fn relative(rel: &str) -> Result<CString, String> {
    if rel.trim().is_empty() || rel.contains('\0') {
        return Err("invalid empty or NUL path".into());
    }
    let path = Path::new(rel);
    if path.is_absolute() {
        return Err("workspace path must be relative to the files root".into());
    }
    if !path.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err("path traversal (.. or prefix) is forbidden".into());
    }
    CString::new(rel).map_err(|_| "invalid empty or NUL path".to_string())
}

fn refusal(rel: &str, err: io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::ELOOP) => format!("{rel}: a symlink is on the path; refused"),
        Some(libc::EXDEV) => format!("{rel}: the path leaves the files root; refused"),
        Some(libc::ENOENT) => format!("{rel} does not exist"),
        Some(libc::ENOSYS) => {
            "the kernel has no openat2 (Linux 5.6 or later); workspace files are refused".into()
        }
        _ => format!("{rel}: {}", err.kind()),
    }
}

/// `openat2` beneath `dir` with no symlink on the way. `mode` applies to `O_CREAT` only.
fn open_beneath(dir: BorrowedFd<'_>, path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOCTTY) as u64,
        mode: if flags & libc::O_CREAT != 0 { 0o600 } else { 0 },
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // EAGAIN: a rename raced the resolution (RESOLVE_BENEATH); retried a bounded number
    // of times, then refused.
    for _ in 0..16 {
        // SAFETY: `path` is NUL-terminated, `how` is a live `open_how` of the given size;
        // the kernel reads both and returns a new descriptor or -1.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: the kernel returned a new descriptor that nothing else owns.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        }
        let err = io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
            return Err(err);
        }
    }
    Err(io::Error::from_raw_os_error(libc::EAGAIN))
}

/// A regular file with one link, or a refusal.
fn single_file(rel: &str, fd: OwnedFd) -> Result<File, String> {
    let file = File::from(fd);
    let meta = file.metadata().map_err(|e| refusal(rel, e))?;
    if !meta.is_file() {
        return Err(format!("{rel} is not a regular file"));
    }
    if meta.nlink() != 1 {
        return Err(format!("{rel} has more than one hard link; refused"));
    }
    Ok(file)
}

impl Dir {
    /// Open `path` as a root: not a symlink, a directory owned by the Core uid.
    pub(crate) fn open_root(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| {
                let link = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_symlink());
                if err.raw_os_error() == Some(libc::ELOOP) || link {
                    format!("{shown} is a symlink; refused")
                } else {
                    format!("{shown}: {}", err.kind())
                }
            })?;
        let meta = file
            .metadata()
            .map_err(|err| format!("{shown}: {}", err.kind()))?;
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != euid {
            return Err(format!(
                "{shown} is not a directory owned by the Core uid; refused"
            ));
        }
        Ok(Self { fd: file.into() })
    }

    /// The owner's files root of a node workspace, `<workspace>/files`, created with mode
    /// 0700 when it is missing.
    pub(crate) fn files_of(workspace: &Path) -> Result<Self, String> {
        let files = workspace.join("files");
        match std::fs::DirBuilder::new().mode(0o700).create(&files) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {}", files.display(), e.kind())),
        }
        Self::open_root(&files)
    }

    /// An existing directory beneath this one.
    pub(crate) fn subdir(&self, rel: &str) -> Result<Dir, String> {
        let path = relative(rel)?;
        let fd = open_beneath(self.fd.as_fd(), &path, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|e| refusal(rel, e))?;
        Ok(Dir { fd })
    }

    /// This directory again, with its own open file description (a duplicate would share
    /// the read position of its entries).
    pub(crate) fn subdir_self(&self) -> Result<Dir, String> {
        let fd = open_beneath(self.fd.as_fd(), c".", libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(|e| refusal(".", e))?;
        Ok(Dir { fd })
    }

    /// A regular file beneath this one, opened for reading.
    pub(crate) fn open_read(&self, rel: &str) -> Result<File, String> {
        let path = relative(rel)?;
        let fd = open_beneath(self.fd.as_fd(), &path, libc::O_RDONLY | libc::O_NONBLOCK)
            .map_err(|e| refusal(rel, e))?;
        single_file(rel, fd)
    }

    /// A regular file beneath this one, opened for writing: created (0600) with its
    /// missing parent directories (0700), then emptied, or positioned at its end when
    /// `append`. A file that is refused is never truncated. The file is opened by its whole
    /// path from this directory, never from a handle of a parent that may have moved
    /// meanwhile; a parent this call creates is checked to be beneath this directory and
    /// removed again when it is not.
    pub(crate) fn open_write(&self, rel: &str, append: bool) -> Result<File, String> {
        let full = relative(rel)?;
        let parts: Vec<&OsStr> = Path::new(rel).iter().collect();
        let (_, parents) = parts.split_last().ok_or("invalid empty or NUL path")?;
        let mut prefix = PathBuf::new();
        for part in parents {
            let parent = if prefix.as_os_str().is_empty() {
                None
            } else {
                let path =
                    CString::new(prefix.as_os_str().as_bytes()).map_err(|_| "invalid NUL path")?;
                Some(
                    open_beneath(self.fd.as_fd(), &path, libc::O_RDONLY | libc::O_DIRECTORY)
                        .map_err(|e| refusal(rel, e))?,
                )
            };
            prefix.push(part);
            let at = parent.as_ref().map_or(self.fd.as_fd(), |d| d.as_fd());
            let name = CString::new(part.as_bytes()).map_err(|_| "invalid NUL path")?;
            // SAFETY: `name` is NUL-terminated and `at` is an open directory descriptor.
            if unsafe { libc::mkdirat(at.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
                self.created_beneath(at, &name, &prefix)
                    .map_err(|e| format!("{rel}: {e}"))?;
            } else {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(refusal(rel, err));
                }
            }
        }
        let mode = if append { libc::O_APPEND } else { 0 };
        let fd = open_beneath(
            self.fd.as_fd(),
            &full,
            libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK | mode,
        )
        .map_err(|e| refusal(rel, e))?;
        let file = single_file(rel, fd)?;
        if !append {
            file.set_len(0).map_err(|e| refusal(rel, e))?;
        }
        Ok(file)
    }

    /// The directory `name` just created in `at` is the one `prefix` names beneath this
    /// directory; otherwise `at` moved out between its open and the creation, and the new
    /// directory is removed again (best effort).
    ///
    /// Threat model: Linux has no `mkdirat` with `RESOLVE_BENEATH`, so a concurrent process
    /// of the Core's own uid that moves a parent out of `files/` at that instant can leave an
    /// empty directory outside it. Such a process can create that directory itself, so this
    /// is no privilege boundary; the write itself is refused, and every file open stays
    /// beneath the root through `openat2`. Plans and models cannot run such a process.
    fn created_beneath(
        &self,
        at: BorrowedFd<'_>,
        name: &CStr,
        prefix: &Path,
    ) -> Result<(), String> {
        // SAFETY: an all-zero `stat` is a valid output buffer for fstatat.
        let mut made: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `at` is open and `name` is NUL-terminated.
        let stat_ok = unsafe {
            libc::fstatat(
                at.as_raw_fd(),
                name.as_ptr(),
                &mut made,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        let beneath = stat_ok
            && CString::new(prefix.as_os_str().as_bytes())
                .ok()
                .and_then(|path| {
                    open_beneath(self.fd.as_fd(), &path, libc::O_RDONLY | libc::O_DIRECTORY).ok()
                })
                .is_some_and(|fd| {
                    // SAFETY: an all-zero `stat` is a valid output buffer for fstat.
                    let mut found: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: `fd` is an open descriptor owned here.
                    (unsafe { libc::fstat(fd.as_raw_fd(), &mut found) } == 0)
                        && found.st_dev == made.st_dev
                        && found.st_ino == made.st_ino
                });
        if beneath {
            return Ok(());
        }
        // SAFETY: `at` is open and `name` is NUL-terminated; removes an empty directory only.
        unsafe { libc::unlinkat(at.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        Err("a parent directory moved during the write; refused".into())
    }

    /// The entries of this directory with their kinds, read one at a time without following
    /// links, and how many entries were examined. Every entry `readdir` returns counts against
    /// `limit`, also one that vanished before its lookup, so a directory changing underneath
    /// cannot make the walk exceed its budget.
    pub(crate) fn entries(&self, limit: usize) -> Result<(Vec<(String, Kind)>, usize), String> {
        let own = self.subdir_self()?.fd;
        let raw = own.as_raw_fd();
        // SAFETY: `raw` is an open directory descriptor; on success the stream owns it.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            return Err(refusal(".", io::Error::last_os_error()));
        }
        std::mem::forget(own);
        let mut out = Vec::new();
        let mut examined = 0;
        while examined < limit {
            // SAFETY: `stream` is a live directory stream used by this thread only.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: readdir returned a valid entry whose name is NUL-terminated.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            examined += 1;
            // SAFETY: an all-zero `stat` is a valid output buffer for fstatat.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `raw` stays open while the stream lives; `name` is NUL-terminated.
            if unsafe { libc::fstatat(raw, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0
            {
                continue;
            }
            let kind = match st.st_mode & libc::S_IFMT {
                libc::S_IFDIR => Kind::Dir,
                libc::S_IFREG => Kind::File,
                _ => Kind::Other,
            };
            out.push((name.to_string_lossy().into_owned(), kind));
        }
        // SAFETY: `stream` is live; closing it closes its descriptor.
        unsafe { libc::closedir(stream) };
        Ok((out, examined))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_read_no_more_than_the_budget() {
        // Other tests of this crate change the process umask while binding a socket.
        let _umask = crate::approval::UMASK_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("vaikor-contained-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in 0..50 {
            std::fs::write(dir.join(format!("n{n}")), "").unwrap();
        }
        let root = Dir::open_root(&dir).unwrap();
        assert_eq!(root.entries(10).unwrap(), (root.entries(10).unwrap().0, 10));
        assert_eq!(root.entries(10).unwrap().0.len(), 10);
        assert_eq!(root.entries(0).unwrap(), (Vec::new(), 0));
        let (all, examined) = root.entries(100).unwrap();
        assert_eq!((all.len(), examined), (50, 50));
        let _ = std::fs::remove_dir_all(dir);
    }
}
