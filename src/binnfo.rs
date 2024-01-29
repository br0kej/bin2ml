use goblin::{error, Object};
use std::fs;
use std::path::{Path, PathBuf};

pub fn goblin_info(fpath: &PathBuf) -> error::Result<()> {
    let buffer = fs::read(fpath)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            println!("elf: {:#?}", &elf);
        }
        Object::PE(pe) => {
            println!("pe: {:#?}", &pe);
        }
        Object::Mach(mach) => {
            println!("mach: {:#?}", &mach);
        }
        Object::Archive(archive) => {
            println!("archive: {:#?}", &archive);
        }
        Object::Unknown(magic) => {
            println!("unknown magic: {:#x}", magic)
        }
    }
    Ok(())
}
