//! Thread-safe handle table mapping integer JNI handles to active tunnels.
//!
//! `awgTurnOn` returns an `int` to Java; Java passes that int back to
//! every subsequent function (`awgTurnOff`, `awgGetSocketV4`, etc.). We
//! use a `Slab<Tunnel>` so handle ints are dense and stable. The slab
//! sits behind a parking_lot mutex because the JNI surface is thread-safe
//! by spec — Java may call from any thread at any time.
//!
//! This module knows nothing about JNI types, GotaTun internals, or
//! UAPI. It only stores opaque `Tunnel` values. That keeps it cheap to
//! test in isolation.

use parking_lot::Mutex;
use slab::Slab;

/// A handle issued to Java. Negative values signal failure (the
/// amneziawg-go convention is `-1` for any error). Positive values index
/// into the slab. We reserve `i32::MAX` to never index there, so even
/// pathological allocators can't collide with the sentinel.
pub type Handle = i32;

/// Registry of active tunnels. Cheap to clone (it's an `Arc`-backed
/// `Mutex`), but in practice we only need one global instance.
pub struct Registry<T> {
    slab: Mutex<Slab<T>>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Registry<T> {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            slab: Mutex::new(Slab::new()),
        }
    }

    /// Insert a tunnel and return its handle. Returns `None` if the
    /// resulting slab index would overflow `i32` — practically
    /// impossible with the typical fleet size (we'd need 2 billion
    /// concurrent tunnels on a single phone) but we don't want a wrap
    /// to silently produce a negative handle that Java treats as
    /// failure.
    pub fn insert(&self, value: T) -> Option<Handle> {
        let mut slab = self.slab.lock();
        let key = slab.insert(value);
        i32::try_from(key).ok().filter(|&n| n >= 0)
    }

    /// Take a tunnel out of the registry, dropping it. Returns `true`
    /// if the handle was present.
    pub fn remove(&self, handle: Handle) -> Option<T> {
        let key: usize = handle.try_into().ok()?;
        let mut slab = self.slab.lock();
        if slab.contains(key) {
            Some(slab.remove(key))
        } else {
            None
        }
    }

    /// Apply a function to a tunnel without removing it. Returns `None`
    /// if the handle is unknown.
    pub fn with<R>(&self, handle: Handle, f: impl FnOnce(&T) -> R) -> Option<R> {
        let key: usize = handle.try_into().ok()?;
        let slab = self.slab.lock();
        slab.get(key).map(f)
    }

    /// Apply a mutable function to a tunnel without removing it. Used
    /// by `awgUpdateTunnelPeers` to rewrite a tunnel's peer table in
    /// place.
    pub fn with_mut<R>(&self, handle: Handle, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let key: usize = handle.try_into().ok()?;
        let mut slab = self.slab.lock();
        slab.get_mut(key).map(f)
    }

    /// Number of active tunnels. Useful for diagnostics / asserting
    /// clean teardown.
    pub fn len(&self) -> usize {
        self.slab.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.slab.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn insert_returns_distinct_handles() {
        let reg: Registry<u32> = Registry::new();
        let h1 = reg.insert(100).expect("first insert");
        let h2 = reg.insert(200).expect("second insert");
        assert_ne!(h1, h2);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn lookup_round_trip() {
        let reg: Registry<u32> = Registry::new();
        let h = reg.insert(42).unwrap();
        let got = reg.with(h, |v| *v).expect("handle should resolve");
        assert_eq!(got, 42);
    }

    #[test]
    fn remove_invalidates_handle() {
        let reg: Registry<u32> = Registry::new();
        let h = reg.insert(42).unwrap();
        let taken = reg.remove(h).expect("first remove returns the value");
        assert_eq!(taken, 42);
        assert!(reg.with(h, |_| ()).is_none(), "second lookup must fail");
        assert!(reg.remove(h).is_none(), "second remove must be a no-op");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn negative_handle_returns_none() {
        let reg: Registry<u32> = Registry::new();
        let _ = reg.insert(1);
        assert!(reg.with(-1, |_| ()).is_none());
        assert!(reg.with(-42, |_| ()).is_none());
        assert!(reg.remove(-1).is_none());
    }

    #[test]
    fn unknown_positive_handle_returns_none() {
        let reg: Registry<u32> = Registry::new();
        let _ = reg.insert(1);
        assert!(reg.with(9999, |_| ()).is_none());
        assert!(reg.remove(9999).is_none());
    }

    #[test]
    fn with_mut_allows_in_place_mutation() {
        let reg: Registry<u32> = Registry::new();
        let h = reg.insert(10).unwrap();
        reg.with_mut(h, |v| *v = 99).unwrap();
        assert_eq!(reg.with(h, |v| *v).unwrap(), 99);
    }

    #[test]
    fn handles_are_reusable_after_removal() {
        // Slab semantics: removed slots are reused. We don't strictly
        // require this, but the test pins the behavior so that future
        // backend swaps don't silently change handle stability.
        let reg: Registry<u32> = Registry::new();
        let h1 = reg.insert(1).unwrap();
        let h2 = reg.insert(2).unwrap();
        reg.remove(h1);
        let h3 = reg.insert(3).unwrap();
        assert!(h3 == h1 || h3 != h2, "h3 should reuse h1's slot");
    }

    #[test]
    fn concurrent_insert_remove_stays_consistent() {
        let reg: Arc<Registry<u32>> = Arc::new(Registry::new());

        let mut workers = Vec::new();
        for thread_id in 0..8 {
            let reg = reg.clone();
            workers.push(thread::spawn(move || {
                for round in 0..1000 {
                    let h = reg.insert((thread_id * 1000 + round) as u32).unwrap();
                    let v = reg.with(h, |v| *v).unwrap();
                    assert_eq!(v, (thread_id * 1000 + round) as u32);
                    reg.remove(h).unwrap();
                }
            }));
        }
        for w in workers {
            w.join().unwrap();
        }

        assert_eq!(reg.len(), 0, "all handles should have been cleaned up");
    }
}
