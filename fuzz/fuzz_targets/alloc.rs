//! A global allocator that refuses to let one iteration run away.
//!
//! # Why a panic is not the only fatal outcome
//!
//! `libfuzzer` catches panics, and a fuzz target that only asserts "does not
//! panic" therefore misses a whole class of bug that ends a server just as
//! dead: an input that makes the process allocate until the kernel kills it.
//! Nothing panics on the way; the process simply stops.
//!
//! This aborts past a ceiling per iteration, which turns that class into
//! something the fuzzer reports and minimises like any other crash. About
//! thirty lines, and it is what lets `config_toml` catch an eagerly-sized pool
//! and `unbatch` catch a decompression bomb without either target knowing what
//! it is looking for.
//!
//! Not a leak check: memory is returned to the counter on free, so a target
//! that allocates and frees in a loop is fine. The ceiling is on how much is
//! held at once.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// How much one iteration may hold at once.
///
/// Generous next to what any legitimate input needs -- the frame decoder caps a
/// payload at 8 MiB -- and far below what a machine running the fuzzer has.
const CEILING: usize = 512 * 1024 * 1024;

/// Bytes currently held.
static HELD: AtomicUsize = AtomicUsize::new(0);

/// Counts what is held, and aborts past [`CEILING`].
pub struct Counting;

// SAFETY: every method forwards to `System`, which is a correct allocator, and
// the accounting around it only reads and writes an atomic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let held = HELD.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        if held > CEILING {
            // `abort`, not `panic`: a panic here would allocate.
            eprintln!(
                "allocation ceiling exceeded: {held} bytes held, asked for {}",
                layout.size()
            );
            std::process::abort();
        }
        // SAFETY: the caller's contract for `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller's contract for `GlobalAlloc::dealloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            let grew = new_size - layout.size();
            let held = HELD.fetch_add(grew, Ordering::Relaxed) + grew;
            if held > CEILING {
                eprintln!("allocation ceiling exceeded on realloc: {held} bytes held");
                std::process::abort();
            }
        } else {
            let _ = HELD.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        // SAFETY: the caller's contract for `GlobalAlloc::realloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
