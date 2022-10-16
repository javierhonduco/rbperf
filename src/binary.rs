use anyhow::{anyhow, Result};
use goblin::Object;
use log::debug;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::str;

#[derive(Debug, PartialEq, Eq)]
pub struct Symbol {
    pub address: u64,
    pub size: u64,
}

fn address_for_symbol(bin_path: &Path, symbol: &str) -> Result<Symbol> {
    debug!(
        "Checking symbol {} in binary {}",
        symbol,
        bin_path.display()
    );

    let path = Path::new(bin_path);
    let buffer = fs::read(path)?;
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            let symtab = elf.strtab;
            if let Some(sym) = elf
                .syms
                .iter()
                .find(|sym| symtab[sym.st_name].contains(symbol))
            {
                return Ok(Symbol {
                    address: sym.st_value,
                    size: sym.st_size,
                });
            }

            let dynstrtab = elf.dynstrtab;
            if let Some(sym) = elf
                .dynsyms
                .iter()
                .find(|sym| dynstrtab[sym.st_name].contains(symbol))
            {
                return Ok(Symbol {
                    address: sym.st_value,
                    size: sym.st_size,
                });
            }
            Err(anyhow!(
                "Could not find symbol: {} in {:?}",
                symbol,
                bin_path
            ))
        }
        _ => Err(anyhow!("{:?} is not an ELF executable", bin_path)),
    }
}

pub fn ruby_current_thread_address(bin_path: &Path, ruby_version: &str) -> Result<Symbol> {
    let v: Vec<i32> = ruby_version
        .split('.')
        .map(|x| x.parse::<i32>().unwrap())
        .collect();
    let (major, minor, _patch) = (v[0], v[1], v[2]);

    let vm_pointer_symbol = if major == 2 && minor >= 5 {
        "ruby_current_execution_context_ptr"
    } else {
        "ruby_current_thread"
    };

    address_for_symbol(bin_path, vm_pointer_symbol)
}

pub fn ruby_current_vm_address(bin_path: &Path, ruby_version: &str) -> Result<Symbol> {
    let v: Vec<i32> = ruby_version
        .split('.')
        .map(|x| x.parse::<i32>().unwrap())
        .collect();
    let (major, minor, _patch) = (v[0], v[1], v[2]);
    let vm_pointer_symbol = if major == 2 && minor >= 5 {
        "ruby_current_vm_ptr"
    } else {
        "ruby_current_vm"
    };
    address_for_symbol(bin_path, vm_pointer_symbol)
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
        assert!(ruby_current_thread_address(Path::new("/proc/self/exe"), "2.5.0").is_err());
    }

    #[test]
    #[should_panic]
    fn test_malformed_ruby_version_should_panic() {
        assert!(ruby_current_thread_address(Path::new("/proc/self/exe"), "2.").is_err());
    }
}
