// This file is part of the uutils coreutils package.
//
// (c) Yuan YangHao <yuanyanghau@gmail.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.

// spell-checker:ignore memmem algo

//! Implementations of digest functions, like md5 and sha1.
//!
//! The [`Digest`] trait represents the interface for providing inputs
//! to these digest functions and accessing the resulting hash. The
//! [`DigestWriter`] struct provides a wrapper around [`Digest`] that
//! implements the [`Write`] trait, for use in situations where calling
//! [`write`] would be useful.
use std::{
    io::{Read, Write},
    path::Path,
};

use hex::encode;
#[cfg(windows)]
use memchr::memmem;

// This can be replaced with usize::div_ceil once it is stabilized.
// This implementation approach is optimized for when `b` is a constant,
// particularly a power of two.
const fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn unwrap_or_dash(path: Option<&Path>) -> &Path {
    path.unwrap_or(Path::new("-"))
}

fn format_bsd_like(sum: String, size: usize, path: Option<&Path>, alignment: usize) -> String {
    match path {
        Some(path) => format!("{sum:alignment$} {size:alignment$} {}", path.display()),
        None => format!("{sum:alignment$} {size:alignment$}")
    }
}

pub trait SumAlgorithm {
    type Digest: SumDigest;
    const NAME: &'static str;

    fn output_bits(&self) -> usize;

    fn sum(
        &self,
        mut reader: impl Read,
        binary: bool,
    ) -> std::io::Result<(<Self::Digest as SumDigest>::Out, usize)> {
        // Read bytes from `reader` and write those bytes to `digest`.
        //
        // If `binary` is `false` and the operating system is Windows, then
        // `DigestWriter` replaces "\r\n" with "\n" before it writes the
        // bytes into `digest`. Otherwise, it just inserts the bytes as-is.
        //
        // In order to support replacing "\r\n", we must call `finalize()`
        // in order to support the possibility that the last character read
        // from the reader was "\r". (This character gets buffered by
        // `DigestWriter` and only written if the following character is
        // "\n". But when "\r" is the last character read, we need to force
        // it to be written.)
        let mut digest = Self::Digest::new();
        let mut digest_writer = DigestWriter::new(&mut digest, binary);
        let output_size = std::io::copy(&mut reader, &mut digest_writer)? as usize;
        digest_writer.finalize();

        let output_bytes = (self.output_bits() + 7) / 8;
        let mut output = <Self::Digest as SumDigest>::Out::new(output_bytes);
        digest.hash_finalize(&mut output);

        Ok((output, output_size))
    }

    fn format(
        &self,
        tag: bool,
        output: <Self::Digest as SumDigest>::Out,
        _size: usize,
        path: Option<&Path>,
    ) -> String {
        let p = unwrap_or_dash(path).display();
        if tag {
            format!("{} ({}) = {}", Self::NAME, p, output.fmt())
        } else {
            format!("{} {p}", output.fmt())
        }
    }
}

pub trait SumDigest {
    type Out: SumOutput;

    fn new() -> Self
    where
        Self: Sized;
    fn hash_update(&mut self, input: &[u8]);
    fn hash_finalize(&mut self, out: &mut Self::Out);
}

// The output from a digest
pub trait SumOutput {
    fn new(len: usize) -> Self;
    fn fmt(&self) -> String;
}

impl SumOutput for Vec<u8> {
    fn new(len: usize) -> Self {
        vec![0; len]
    }
    fn fmt(&self) -> String {
        encode(self)
    }
}

impl SumOutput for u16 {
    fn new(_len: usize) -> Self {
        0
    }
    fn fmt(&self) -> String {
        format!("{}", self)
    }
}

impl SumOutput for u32 {
    fn new(_len: usize) -> Self {
        0
    }
    fn fmt(&self) -> String {
        format!("{}", self)
    }
}

impl SumOutput for u64 {
    fn new(_len: usize) -> Self {
        0
    }
    fn fmt(&self) -> String {
        format!("{}", self)
    }
}

pub struct Blake2b;

impl SumAlgorithm for Blake2b {
    type Digest = blake2b_simd::State;
    const NAME: &'static str = "BLAKE2b";

    fn output_bits(&self) -> usize {
        512
    }
}

impl SumDigest for blake2b_simd::State {
    type Out = Vec<u8>;

    fn new() -> Self {
        blake2b_simd::State::new()
    }

    fn hash_update(&mut self, input: &[u8]) {
        self.update(input);
    }

    fn hash_finalize(&mut self, out: &mut Vec<u8>) {
        let hash_result = &self.finalize();
        out.copy_from_slice(hash_result.as_bytes());
    }
}

pub struct Blake3;

impl SumAlgorithm for Blake3 {
    type Digest = blake3::Hasher;
    const NAME: &'static str = "BLAKE3";

    fn output_bits(&self) -> usize {
        256
    }
}

impl SumDigest for blake3::Hasher {
    type Out = Vec<u8>;

    fn new() -> Self {
        blake3::Hasher::new()
    }

    fn hash_update(&mut self, input: &[u8]) {
        self.update(input);
    }

    fn hash_finalize(&mut self, out: &mut Vec<u8>) {
        let hash_result = &self.finalize();
        out.copy_from_slice(hash_result.as_bytes());
    }
}

pub struct Sm3;

impl SumAlgorithm for Sm3 {
    type Digest = sm3::Sm3;
    const NAME: &'static str = "SM3";

    fn output_bits(&self) -> usize {
        256
    }
}

impl SumDigest for sm3::Sm3 {
    type Out = Vec<u8>;

    fn new() -> Self {
        sm3::Digest::new()
    }

    fn hash_update(&mut self, input: &[u8]) {
        sm3::Digest::update(self, input);
    }

    fn hash_finalize(&mut self, out: &mut Vec<u8>) {
        out.copy_from_slice(&sm3::Digest::finalize(self.clone()));
    }
}

// NOTE: CRC_TABLE_LEN *must* be <= 256 as we cast 0..CRC_TABLE_LEN to u8
const CRC_TABLE_LEN: usize = 256;

pub struct CRC;

impl SumAlgorithm for CRC {
    type Digest = CRCDigest;
    const NAME: &'static str = "CRC";

    fn output_bits(&self) -> usize {
        32
    }

    fn format(&self, _tag: bool, output: u32, size: usize, path: Option<&Path>) -> String {
        format_bsd_like(output.fmt(), size, path, 0)
    }
}

pub struct CRCDigest {
    state: u32,
    size: usize,
    crc_table: [u32; CRC_TABLE_LEN],
}

impl CRCDigest {
    fn generate_crc_table() -> [u32; CRC_TABLE_LEN] {
        let mut table = [0; CRC_TABLE_LEN];

        for (i, elt) in table.iter_mut().enumerate().take(CRC_TABLE_LEN) {
            *elt = Self::crc_entry(i as u8);
        }

        table
    }
    fn crc_entry(input: u8) -> u32 {
        let mut crc = (input as u32) << 24;

        let mut i = 0;
        while i < 8 {
            let if_condition = crc & 0x8000_0000;
            let if_body = (crc << 1) ^ 0x04c1_1db7;
            let else_body = crc << 1;

            // NOTE: i feel like this is easier to understand than emulating an if statement in bitwise
            //       ops
            let condition_table = [else_body, if_body];

            crc = condition_table[(if_condition != 0) as usize];
            i += 1;
        }

        crc
    }

    fn update(&mut self, input: u8) {
        self.state = (self.state << 8)
            ^ self.crc_table[((self.state >> 24) as usize ^ input as usize) & 0xFF];
    }
}

impl SumDigest for CRCDigest {
    type Out = u32;

    fn new() -> Self {
        Self {
            state: 0,
            size: 0,
            crc_table: Self::generate_crc_table(),
        }
    }

    fn hash_update(&mut self, input: &[u8]) {
        for &elt in input.iter() {
            self.update(elt);
        }
        self.size += input.len();
    }

    fn hash_finalize(&mut self, out: &mut u32) {
        let mut sz = self.size;
        while sz != 0 {
            self.update(sz as u8);
            sz >>= 8;
        }
        self.state = !self.state;
        *out = self.state;
    }
}

pub struct BSD;

impl SumAlgorithm for BSD {
    type Digest = BSDDigest;
    const NAME: &'static str = "BSD";

    fn output_bits(&self) -> usize {
        128
    }

    fn format(&self, _tag: bool, output: u16, size: usize, path: Option<&Path>) -> String {
        // BSD format aligns to 5 digits
        format_bsd_like(output.fmt(), div_ceil(size, 1024), path, 5)
    }
}

pub struct BSDDigest {
    state: u16,
}

impl SumDigest for BSDDigest {
    type Out = u16;

    fn new() -> Self {
        Self { state: 0 }
    }

    fn hash_update(&mut self, input: &[u8]) {
        for &byte in input.iter() {
            self.state = (self.state >> 1) + ((self.state & 1) << 15);
            self.state = self.state.wrapping_add(u16::from(byte));
        }
    }

    fn hash_finalize(&mut self, out: &mut u16) {
        *out = self.state;
    }
}

pub struct SYSV;

impl SumAlgorithm for SYSV {
    type Digest = SYSVDigest;
    const NAME: &'static str = "SYSV";

    fn output_bits(&self) -> usize {
        512
    }

    fn format(&self, _tag: bool, output: u16, size: usize, path: Option<&Path>) -> String {
        format_bsd_like(output.fmt(), size, path, 0)
    }
}

pub struct SYSVDigest {
    state: u32,
}

impl SumDigest for SYSVDigest {
    type Out = u16;

    fn new() -> Self {
        Self { state: 0 }
    }

    fn hash_update(&mut self, input: &[u8]) {
        for &byte in input.iter() {
            self.state = self.state.wrapping_add(u32::from(byte));
        }
    }

    fn hash_finalize(&mut self, out: &mut u16) {
        self.state = (self.state & 0xffff) + (self.state >> 16);
        self.state = (self.state & 0xffff) + (self.state >> 16);
        *out = self.state as u16;
    }
}

// Implements the Digest trait for sha2 / sha3 algorithms with fixed output
macro_rules! impl_digest_common {
    ($algo_type: ty, $name: literal, $digest: ty, $size: expr) => {
        impl SumAlgorithm for $algo_type {
            type Digest = $digest;
            const NAME: &'static str = $name;
            fn output_bits(&self) -> usize {
                $size
            }
        }

        impl SumDigest for $digest {
            type Out = Vec<u8>;
            fn new() -> Self {
                Default::default()
            }

            fn hash_update(&mut self, input: &[u8]) {
                digest::Digest::update(self, input);
            }

            fn hash_finalize(&mut self, out: &mut Vec<u8>) {
                let slice: &mut [u8] = out;
                digest::Digest::finalize_into_reset(self, slice.into());
            }
        }
    };
}

// Implements the Digest trait for sha2 / sha3 algorithms with variable output
macro_rules! impl_digest_shake {
    ($algo_type: ty, $name: literal, $digest: ty) => {
        impl SumAlgorithm for $algo_type {
            type Digest = $digest;
            const NAME: &'static str = $name;
            fn output_bits(&self) -> usize {
                self.bits
            }
        }

        impl SumDigest for $digest {
            type Out = Vec<u8>;

            fn new() -> Self {
                Default::default()
            }

            fn hash_update(&mut self, input: &[u8]) {
                digest::Update::update(self, input);
            }

            fn hash_finalize(&mut self, out: &mut Vec<u8>) {
                digest::ExtendableOutputReset::finalize_xof_reset_into(self, out);
            }
        }
    };
}

pub struct Md5;
pub struct Sha1;
pub struct Sha224;
pub struct Sha256;
pub struct Sha384;
pub struct Sha512;
impl_digest_common!(Md5, "MD5", md5::Md5, 128);
impl_digest_common!(Sha1, "SHA1", sha1::Sha1, 160);
impl_digest_common!(Sha224, "SHA224", sha2::Sha224, 224);
impl_digest_common!(Sha256, "SHA256", sha2::Sha256, 256);
impl_digest_common!(Sha384, "SHA384", sha2::Sha384, 384);
impl_digest_common!(Sha512, "SHA512", sha2::Sha512, 512);

pub struct Sha3_224;
pub struct Sha3_256;
pub struct Sha3_384;
pub struct Sha3_512;
impl_digest_common!(Sha3_224, "SHA3-224", sha3::Sha3_224, 224);
impl_digest_common!(Sha3_256, "SHA3-256", sha3::Sha3_256, 256);
impl_digest_common!(Sha3_384, "SHA3-384", sha3::Sha3_384, 384);
impl_digest_common!(Sha3_512, "SHA3-512", sha3::Sha3_512, 512);

pub struct Shake128 {
    pub bits: usize,
}

pub struct Shake256 {
    pub bits: usize,
}

impl_digest_shake!(Shake128, "SHAKE128", sha3::Shake128);
impl_digest_shake!(Shake256, "SHAKE256", sha3::Shake256);

/// A struct that writes to a digest.
///
/// This struct wraps a [`Digest`] and provides a [`Write`]
/// implementation that passes input bytes directly to the
/// [`Digest::hash_update`].
///
/// On Windows, if `binary` is `false`, then the [`write`]
/// implementation replaces instances of "\r\n" with "\n" before passing
/// the input bytes to the [`digest`].
pub struct DigestWriter<'a, D: SumDigest> {
    digest: &'a mut D,

    /// Whether to write to the digest in binary mode or text mode on Windows.
    ///
    /// If this is `false`, then instances of "\r\n" are replaced with
    /// "\n" before passing input bytes to the [`digest`].
    #[allow(dead_code)]
    binary: bool,

    /// Whether the previous
    #[allow(dead_code)]
    was_last_character_carriage_return: bool,
    // TODO These are dead code only on non-Windows operating systems.
    // It might be better to use a `#[cfg(windows)]` guard here.
}

impl<'a, D: SumDigest> DigestWriter<'a, D> {
    pub fn new(digest: &'a mut D, binary: bool) -> DigestWriter<D> {
        let was_last_character_carriage_return = false;
        DigestWriter {
            digest,
            binary,
            was_last_character_carriage_return,
        }
    }

    pub fn finalize(&mut self) -> bool {
        if self.was_last_character_carriage_return {
            self.digest.hash_update(&[b'\r']);
            true
        } else {
            false
        }
    }
}

impl<'a, D: SumDigest> Write for DigestWriter<'a, D> {
    #[cfg(not(windows))]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.digest.hash_update(buf);
        Ok(buf.len())
    }

    #[cfg(windows)]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.binary {
            self.digest.hash_update(buf);
            return Ok(buf.len());
        }

        // The remaining code handles Windows text mode, where we must
        // replace each occurrence of "\r\n" with "\n".
        //
        // First, if the last character written was "\r" and the first
        // character in the current buffer to write is not "\n", then we
        // need to write the "\r" that we buffered from the previous
        // call to `write()`.
        let n = buf.len();
        if self.was_last_character_carriage_return && n > 0 && buf[0] != b'\n' {
            self.digest.hash_update(&[b'\r']);
        }

        // Next, find all occurrences of "\r\n", inputting the slice
        // just before the "\n" in the previous instance of "\r\n" and
        // the beginning of this "\r\n".
        let mut i_prev = 0;
        for i in memmem::find_iter(buf, b"\r\n") {
            self.digest.hash_update(&buf[i_prev..i]);
            i_prev = i + 1;
        }

        // Finally, check whether the last character is "\r". If so,
        // buffer it until we know that the next character is not "\n",
        // which can only be known on the next call to `write()`.
        //
        // This all assumes that `write()` will be called on adjacent
        // blocks of the input.
        if n > 0 && buf[n - 1] == b'\r' {
            self.was_last_character_carriage_return = true;
            self.digest.hash_update(&buf[i_prev..n - 1]);
        } else {
            self.was_last_character_carriage_return = false;
            self.digest.hash_update(&buf[i_prev..n]);
        }

        // Even though we dropped a "\r" for each "\r\n" we found, we
        // still report the number of bytes written as `n`. This is
        // because the meaning of the returned number is supposed to be
        // the number of bytes consumed by the writer, so that if the
        // calling code were calling `write()` in a loop, it would know
        // where the next contiguous slice of the buffer starts.
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// Test for replacing a "\r\n" sequence with "\n" when the "\r" is
    /// at the end of one block and the "\n" is at the beginning of the
    /// next block, when reading in blocks.
    #[cfg(windows)]
    #[test]
    fn test_crlf_across_blocks() {
        use std::io::Write;

        use crate::digest::Digest;
        use crate::digest::DigestWriter;

        // Writing "\r" in one call to `write()`, and then "\n" in another.
        let mut digest = Box::new(md5::Md5::new()) as Box<dyn Digest>;
        let mut writer_crlf = DigestWriter::new(&mut digest, false);
        writer_crlf.write_all(&[b'\r']).unwrap();
        writer_crlf.write_all(&[b'\n']).unwrap();
        writer_crlf.hash_finalize();
        let result_crlf = digest.result_str();

        // We expect "\r\n" to be replaced with "\n" in text mode on Windows.
        let mut digest = Box::new(md5::Md5::new()) as Box<dyn Digest>;
        let mut writer_lf = DigestWriter::new(&mut digest, false);
        writer_lf.write_all(&[b'\n']).unwrap();
        writer_lf.hash_finalize();
        let result_lf = digest.result_str();

        assert_eq!(result_crlf, result_lf);
    }
}
