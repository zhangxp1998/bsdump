use brotli;
use bzip2::read::BzDecoder;
use std::io::{self, ErrorKind};
use std::vec::Vec;
use std::{
    convert::TryInto,
    io::{Cursor, Read, Seek},
};

use binread::{BinRead, BinResult, ReadOptions};

#[derive(Debug, Eq, PartialEq)]
pub enum CompressorType {
    Bz2,
    Brotli,
}

const fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        | ((array[1] as u32) << 16)
        | ((array[2] as u32) << 8)
        | ((array[3] as u32) << 0)
}

const fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[3] as u32) << 24)
        | ((array[2] as u32) << 16)
        | ((array[1] as u32) << 8)
        | ((array[0] as u32) << 0)
}

const fn as_u64_le(arr: &[u8; 8]) -> u64 {
    return (as_u32_le(&[arr[0], arr[1], arr[2], arr[3]]) as u64)
        | (as_u32_le(&[arr[4], arr[5], arr[6], arr[7]]) as u64) << 32;
}

const fn as_u64_be(arr: &[u8; 8]) -> u64 {
    return (as_u32_be(&[arr[0], arr[1], arr[2], arr[3]]) as u64) << 32
        | as_u32_be(&[arr[4], arr[5], arr[6], arr[7]]) as u64;
}

const LEGACY_BSDIFF_MAGIC: u64 = as_u64_be(b"BSDIFF40");
const BSDIFF2_MAGIC: u64 = as_u64_be(b"BSDF2\x00\x00\x00");
const BSDIFF3_MAGIC: u64 = as_u64_be(b"BDF3\x00\x00\x00\x00");

fn is_valid_compressor_type(compressor_type: u8) -> bool {
    return compressor_type == 1 || compressor_type == 2;
}

fn to_compressor_type(compressor_type: u8) -> CompressorType {
    return match compressor_type {
        1 => CompressorType::Bz2,
        2 => CompressorType::Brotli,
        o => panic!("Invalid compressor type: {}", o),
    };
}

fn is_valid_bsdiff_magic(magic: u64) -> bool {
    let bytes = magic.to_be_bytes();
    return (magic & BSDIFF2_MAGIC == BSDIFF2_MAGIC
        && is_valid_compressor_type(bytes[5])
        && is_valid_compressor_type(bytes[6])
        && is_valid_compressor_type(bytes[7]))
        || ((magic & BSDIFF3_MAGIC == BSDIFF3_MAGIC)
            // && is_valid_compressor_type(bytes[4])
            && is_valid_compressor_type(bytes[5])
            && is_valid_compressor_type(bytes[6])
            && is_valid_compressor_type(bytes[7]));
}

#[derive(BinRead)]
#[br(assert(magic == LEGACY_BSDIFF_MAGIC ||is_valid_bsdiff_magic(magic)), little)]
#[derive(Debug, Clone, Copy)]
pub struct BsdiffFormat {
    #[br(big)]
    pub magic: u64,
    pub compressed_ctrl_size: u64,
    pub compressed_diff_size: u64,
    pub new_file_size: u64,
}

impl BsdiffFormat {
    fn is_legacy_bsdiff_format(&self) -> bool {
        return self.magic == LEGACY_BSDIFF_MAGIC;
    }
    fn is_bsdiff3_format(&self) -> bool {
        return self.magic & BSDIFF3_MAGIC == BSDIFF3_MAGIC;
    }
    fn get_ctrl_compressor(&self) -> CompressorType {
        return if self.is_legacy_bsdiff_format() {
            CompressorType::Bz2
        } else {
            to_compressor_type(self.magic.to_be_bytes()[5])
        };
    }
    fn get_diff_compressor(&self) -> CompressorType {
        return if self.is_legacy_bsdiff_format() {
            CompressorType::Bz2
        } else {
            to_compressor_type(self.magic.to_be_bytes()[6])
        };
    }
    fn get_extra_compressor(&self) -> CompressorType {
        return if self.is_legacy_bsdiff_format() {
            CompressorType::Bz2
        } else {
            to_compressor_type(self.magic.to_be_bytes()[7])
        };
    }
}

fn read_bsdiff_int<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, _: ()) -> BinResult<i64> {
    // BSPatch uses a non-standard encoding of integers.
    // Highest bit of that integer is used as a sign bit, 1 = negative
    // and 0 = positive.
    // Therefore, if the highest bit is set, flip it, then do 2's complement
    // to get the integer in standard form
    let raw = u64::read_options(reader, ro, ())?;
    if raw & (1 << 63) == 0 {
        return Ok(raw.try_into().unwrap());
    } else {
        let parsed: i64 = (raw & ((1 << 63) - 1)) as i64;
        return Ok(-parsed);
    }
}

#[derive(BinRead)]
#[br(little)]
#[derive(Debug)]
pub struct ControlEntry {
    // The number of bytes to copy from the source and diff stream.
    pub diff_size: u64,

    // The number of bytes to copy from the extra stream.
    pub extra_size: u64,

    // The value to add to the source pointer after patching from the diff stream.
    #[br(parse_with=read_bsdiff_int)]
    offset_increment: i64,
}
// Control entry has 3 u64 fields, so 24 bytes in total.
const CONTROL_ENTRY_SIZE: usize = 24;

pub trait BinreadReader: Read + Seek {}

pub struct BsdiffReader<'a> {
    data: &'a [u8],
    decompressed_ctrl_stream: Vec<u8>,
    pub header: BsdiffFormat,
}

pub struct ControlEntryIter<'a> {
    control_entry_reader: Cursor<&'a Vec<u8>>,
    control_entry_stream_len: usize,
}

impl<'a> Iterator for ControlEntryIter<'a> {
    type Item = ControlEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.control_entry_reader.stream_position().unwrap()
            >= self.control_entry_stream_len as u64
        {
            return None;
        }
        return Some(ControlEntry::read(&mut self.control_entry_reader).unwrap());
    }
}

impl<'a> ControlEntryIter<'a> {
    fn new(
        mut control_entry_reader: Cursor<&Vec<u8>>,
        control_entry_stream_len: usize,
    ) -> ControlEntryIter {
        control_entry_reader
            .seek(std::io::SeekFrom::Start(0))
            .expect("Failed to seek to beginning of control stream");
        return ControlEntryIter {
            control_entry_reader,
            control_entry_stream_len,
        };
    }
}

impl<'a> BsdiffReader<'a> {
    fn decompress(data: &[u8], compressor_type: CompressorType) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::new();
        match compressor_type {
            CompressorType::Brotli => {
                let mut reader = brotli::Decompressor::new(data, 4096 /* buffer size */);
                reader.read_to_end(&mut buf)?;
            }
            CompressorType::Bz2 => {
                let mut reader = BzDecoder::new(data);
                reader.read_to_end(&mut buf)?;
            }
        };
        return Ok(buf);
    }
    pub fn new(data: &'a [u8]) -> Result<BsdiffReader<'a>, binread::Error> {
        let mut reader = Cursor::new(data);
        let header = BsdiffFormat::read(&mut reader)?;
        if header.is_bsdiff3_format() {
            let mut buf = [0 as u8; 8];
            reader.read_exact(&mut buf).unwrap();
            let compressed_mask_size = as_u64_le(&buf);
            let compressed_diff_size = header.compressed_diff_size;
            let compressed_diff_data = &data[32 + 8 + header.compressed_ctrl_size as usize..]
                [..header.compressed_diff_size as usize];
            let decompressed_diff_size =
                Self::decompress(compressed_diff_data, header.get_ctrl_compressor())
                    .unwrap()
                    .len();
            let compressed_mask_data = &data[data.len() - compressed_mask_size as usize..];
            let decompressed_mask_size =
                Self::decompress(compressed_mask_data, CompressorType::Brotli)
                    .unwrap()
                    .len();
            println!(
                "Mask data: {}/{} = {}, diff data: {}/{} = {}",
                compressed_mask_size,
                decompressed_mask_size,
                compressed_mask_size as f32 / decompressed_mask_size as f32,
                compressed_diff_size,
                decompressed_diff_size,
                compressed_diff_size as f32 / decompressed_diff_size as f32,
            );
            return Err(binread::Error::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                "unsupported bsdiff3 format",
            )));
        }
        // header takes up 32 bytes, so control stream start at offset 32.
        let decompressed_ctrl_stream = Self::decompress(&data[32..], header.get_ctrl_compressor())?;
        if decompressed_ctrl_stream.len() % CONTROL_ENTRY_SIZE != 0 {
            return Err(binread::Error::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Decompressed ctrl stream has length {}, which is not a multiple of {}",
                    decompressed_ctrl_stream.len(),
                    CONTROL_ENTRY_SIZE
                ),
            )));
        }
        let compressed_diff_stream = &data[32 + header.compressed_ctrl_size as usize..]
            [..header.compressed_diff_size as usize];
        let decompressed_diff_stream =
            Self::decompress(compressed_diff_stream, header.get_diff_compressor())?;
        let diff_stream_size = decompressed_diff_stream.len();
        let diff_stream_zero_count = decompressed_diff_stream
            .into_iter()
            .map(|x| (x == 0) as u32)
            .sum::<u32>();
        println!(
            "Diff stream has {}/{} = {}% zeros",
            diff_stream_zero_count,
            diff_stream_size,
            (diff_stream_zero_count as f64) / diff_stream_size as f64 * 100.0
        );

        return Ok(BsdiffReader {
            data,
            decompressed_ctrl_stream,
            header,
        });
    }
    pub fn control_entries(&self) -> ControlEntryIter {
        let control_entry_reader = Cursor::new(&self.decompressed_ctrl_stream);
        return ControlEntryIter::new(control_entry_reader, self.decompressed_ctrl_stream.len());
    }

    pub fn get_new_file_size(&self) -> u64 {
        return self.header.new_file_size;
    }
}
