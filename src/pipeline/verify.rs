// SPDX-License-Identifier: Apache-2.0
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use super::safe_open::open_regular_nofollow;
use crate::model::duplicate::DuplicateGroup;

const BUFFER_SIZE: usize = 64 * 1024;

/// Byte-for-byte comparison within each group — confirms that files with
/// the same blake3 really are identical (protection against a hash collision).
/// Files that differ from the first in the group are excluded from the group.
pub fn verify_groups(groups: Vec<DuplicateGroup>) -> Vec<DuplicateGroup> {
    let mut verified = Vec::new();
    for mut group in groups {
        if group.files.is_empty() {
            continue;
        }
        let reference = group.files[0].path.clone();
        group.files.retain(|file| {
            file.path == reference || files_equal(&reference, &file.path).unwrap_or(false)
        });
        if group.files.len() >= 2 {
            verified.push(group);
        }
    }
    for (index, group) in verified.iter_mut().enumerate() {
        group.id = index;
    }
    verified
}

/// Compares the contents of two files byte for byte.
fn files_equal(a: &Path, b: &Path) -> io::Result<bool> {
    let mut file_a = open_regular_nofollow(a)?;
    let mut file_b = open_regular_nofollow(b)?;
    let mut buf_a = [0u8; BUFFER_SIZE];
    let mut buf_b = [0u8; BUFFER_SIZE];

    loop {
        let read_a = read_chunk(&mut file_a, &mut buf_a)?;
        let read_b = read_chunk(&mut file_b, &mut buf_b)?;
        if read_a != read_b {
            return Ok(false);
        }
        if read_a == 0 {
            return Ok(true);
        }
        if buf_a[..read_a] != buf_b[..read_b] {
            return Ok(false);
        }
    }
}

/// Reads into the buffer until it is full or EOF; returns the number of bytes read.
fn read_chunk(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = file.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}
