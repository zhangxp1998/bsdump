use bsdiff_format::BsdiffReader;
use std::fs;

mod bsdiff_format;

fn dump_bspatch(payload: &[u8]) {
    let reader = BsdiffReader::new(payload).expect("Failed to parse bsdiff header");
    let header = reader.header;
    println!("{:?}", header);
    for entry in reader.control_entries() {
        println!("{:?}", entry);
    }
}

fn main() -> Result<(), i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <bsdiff patch>", args[0]);
        return Err(1);
    }
    let path = &args[1];
    let path = std::path::Path::new(path);
    if !std::path::Path::exists(path) {
        println!("{} does not exists", path.display());
        return Err(2);
    }
    let file = fs::File::open(&path).unwrap();
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
    let data = mmap.as_ref();

    dump_bspatch(data);
    return Ok(());
}
