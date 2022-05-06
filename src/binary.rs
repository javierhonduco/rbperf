use anyhow::{anyhow, Result};
use goblin::Object;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::str;

#[derive(Debug, PartialEq)]
pub struct Symbol {
    pub address: u64,
    pub size: u64,
}

fn address_for_symbol(bin_path: &Path, symbol: &str) -> Result<Symbol> {
    let path = Path::new(bin_path);
    let buffer = fs::read(path)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            let symtab = elf.strtab;
            let syms = elf.syms.to_vec();
            for sym in &syms {
                if symtab[sym.st_name].contains(symbol) {
                    return Ok(Symbol {
                        address: sym.st_value as u64,
                        size: sym.st_size,
                    });
                }
            }
            let dynstrtab = elf.dynstrtab;
            let dynsyms = elf.dynsyms.to_vec();
            for sym in &dynsyms {
                if dynstrtab[sym.st_name].contains(symbol) {
                    return Ok(Symbol {
                        address: sym.st_value as u64,
                        size: sym.st_size,
                    });
                }
            }
            return Err(anyhow!(
                "Could not find symbol: {} in {:?}",
                symbol,
                bin_path
            ));
        }
        _ => return Err(anyhow!("{:?} is not an ELF executable", bin_path)),
    }
}

pub fn ruby_current_thread_address(bin_path: &Path) -> Result<Symbol> {
    address_for_symbol(bin_path, "ruby_current_execution_context_ptr")
}

pub fn ruby_version(bin_path: &Path) -> Result<String> {
    let symbol = address_for_symbol(bin_path, "ruby_version")?;
    let mut f = File::open(bin_path)?;
    let len: usize = symbol.size.try_into().unwrap();
    let mut buffer = vec![0u8; len - 1];
    f.seek(SeekFrom::Start(symbol.address))?;
    f.read_exact(&mut buffer)?;

    return Ok(str::from_utf8(&buffer)?.to_string().trim().to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_main_works() {
        assert!(address_for_symbol(Path::new("/proc/self/exe"), "main").is_ok());
    }

    #[test]
    fn test_ruby_current_thread_does_not_exist() {
        assert!(ruby_current_thread_address(Path::new("/proc/self/exe")).is_err());
    }
}
