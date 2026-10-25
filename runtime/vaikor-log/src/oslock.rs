//! Exclusive advisory file locks. `std::fs::File::try_lock` is not implemented
//! for every target (on Android with Rust 1.89 it always fails), so Unix targets
//! call flock(2) directly; other targets use the std implementation.

use std::fs::File;
use std::io;

/// Take an exclusive lock without blocking; fails if another open file
/// description holds it.
#[cfg(unix)]
pub fn try_lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock only reads the fd, which `file` keeps open for the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Release a lock taken with [`try_lock_exclusive`].
#[cfg(unix)]
pub fn unlock(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: as above.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
pub fn try_lock_exclusive(file: &File) -> io::Result<()> {
    file.try_lock().map_err(|err| match err {
        std::fs::TryLockError::Error(err) => err,
        std::fs::TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
    })
}

#[cfg(not(unix))]
pub fn unlock(file: &File) -> io::Result<()> {
    file.unlock()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn second_description_is_refused_until_unlock() {
        let path = std::env::temp_dir().join(format!("vaikor-oslock-{}.lock", std::process::id()));
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .unwrap()
        };
        let (a, b) = (open(), open());
        try_lock_exclusive(&a).unwrap();
        assert!(try_lock_exclusive(&b).is_err());
        unlock(&a).unwrap();
        try_lock_exclusive(&b).unwrap();
        drop((a, b));
        std::fs::remove_file(path).unwrap();
    }
}
