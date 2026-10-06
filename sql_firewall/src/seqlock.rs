//! Lock-free consistent reads of small records in shared memory.
//!
//! A record is a fixed array of `AtomicU64` words; callers encode their
//! fields into words explicitly (no struct bytes, no padding). Writers are
//! serialized by the caller's lock and bracket their stores with the record
//! group's sequence: odd while a write is in progress. Readers copy the words
//! without a lock and keep the copy only if the sequence was even and did not
//! change. Every shared access is atomic, so an overlapping write is a
//! detected retry, never a data race (the seqlock form of H.-J. Boehm, "Can
//! Seqlocks Get Along With Programming Language Memory Models?", 2012:
//! relaxed payload accesses ordered by a release fence after the odd store and
//! an acquire fence before the second sequence load).

use std::sync::atomic::{fence, AtomicU64, Ordering};

/// The write sequence of one group of records.
#[repr(transparent)]
pub struct Sequence(AtomicU64);

impl Sequence {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// One attempt at a consistent copy of `words`; `None` if a write was in
    /// progress or completed meanwhile.
    pub fn try_read<const N: usize>(&self, words: &[AtomicU64; N]) -> Option<[u64; N]> {
        let before = self.0.load(Ordering::Acquire);
        if before & 1 != 0 {
            return None;
        }
        let mut copy = [0u64; N];
        for (value, word) in copy.iter_mut().zip(words.iter()) {
            *value = word.load(Ordering::Relaxed);
        }
        fence(Ordering::Acquire);
        (self.0.load(Ordering::Relaxed) == before).then_some(copy)
    }

    /// A copy of `words` read by the holder of the writers' lock, so no
    /// write can overlap.
    pub fn read_locked<const N: usize>(words: &[AtomicU64; N]) -> [u64; N] {
        let mut copy = [0u64; N];
        for (value, word) in copy.iter_mut().zip(words.iter()) {
            *value = word.load(Ordering::Relaxed);
        }
        copy
    }

    /// Stores `values` into `words` starting at `offset`. The caller holds
    /// the writers' lock of this sequence.
    pub fn write_locked(&self, words: &[AtomicU64], offset: usize, values: &[u64]) {
        let start = self.0.load(Ordering::Relaxed);
        self.0.store(start.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        for (word, value) in words[offset..offset + values.len()].iter().zip(values.iter()) {
            word.store(*value, Ordering::Relaxed);
        }
        self.0.store(start.wrapping_add(2), Ordering::Release);
    }
}

/// `count` zeroed words at `words` (shared memory that may hold anything).
///
/// # Safety
/// `words` must point to `count` writable, suitably aligned `AtomicU64`s
/// that no other process uses yet.
pub unsafe fn zero(words: *mut AtomicU64, count: usize) {
    for index in 0..count {
        std::ptr::write(words.add(index), AtomicU64::new(0));
    }
}

/// Little-endian packing helpers for record fields.
pub fn pack_u32s(low: u32, high: u32) -> u64 {
    u64::from(low) | (u64::from(high) << 32)
}

pub fn unpack_u32s(word: u64) -> (u32, u32) {
    (word as u32, (word >> 32) as u32)
}

pub fn bytes_to_words<const B: usize, const W: usize>(bytes: &[u8; B]) -> [u64; W] {
    let mut words = [0u64; W];
    for (index, chunk) in bytes.chunks(8).enumerate() {
        let mut buffer = [0u8; 8];
        buffer[..chunk.len()].copy_from_slice(chunk);
        words[index] = u64::from_le_bytes(buffer);
    }
    words
}

pub fn words_to_bytes<const B: usize>(words: &[u64]) -> [u8; B] {
    let mut bytes = [0u8; B];
    for (index, chunk) in bytes.chunks_mut(8).enumerate() {
        let source = words[index].to_le_bytes();
        chunk.copy_from_slice(&source[..chunk.len()]);
    }
    bytes
}
