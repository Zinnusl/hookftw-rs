use clap::{Arg, Parser};
use ffi::DecodedInstruction;
use libc::{free, malloc, memcpy};
use std::ffi::c_int;
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::ptr::copy_nonoverlapping;
use std::slice;
use std::sync::Arc;
use zydis::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct Address {
    address: *mut u8,
}

impl Address {
    /// Returns a slice of the memory at the address.
    /// # Safety
    /// The caller must ensure that the address is valid and that the length is correct.
    fn memory_slice(&self, length: usize) -> &[u8] {
        unsafe { slice::from_raw_parts(self.address, length) }
    }

    fn add(&self, offset: usize) -> Address {
        Address {
            address: unsafe { self.address.add(offset) },
        }
    }

    fn sub(&self, offset: usize) -> Address {
        Address {
            address: unsafe { self.address.sub(offset) },
        }
    }

    fn lowest_reachable_by_five_byte_jump(&self) -> Option<Address> {
        let signed_int_max_value = 0x7fffffff;
        let lowest_address_reachable_by_five_byte_jump =
            (self.address as usize).checked_sub(signed_int_max_value)? + 5;

        Some(Self {
            address: lowest_address_reachable_by_five_byte_jump as *mut u8,
        })
    }
}

struct Trampoline {}

struct Detour {
    original_bytes: *mut u8,
    source_address: *mut u8,
    trampoline: *mut u8,
    hook_length: usize,
}

impl Detour {
    pub fn new() -> Self {
        Detour {
            original_bytes: ptr::null_mut(),
            source_address: ptr::null_mut(),
            trampoline: ptr::null_mut(),
            hook_length: 0,
        }
    }

    pub unsafe fn hook(&mut self) -> Arc<Trampoline> {
        Arc::new(Trampoline {})
    }

    pub unsafe fn unhook(&self) {}
}

fn get_length_of_instructions(source_address: &Address, min_size: usize) -> anyhow::Result<usize> {
    // Plus 0xFF to ensure we have enough bytes to decode the instructions to get to the minimum size.
    let buf = source_address.memory_slice(min_size + 0xFF);

    let mut num_bytes = 0;

    let decoder = Decoder::new64();
    let mut insn_iter =
        decoder
            .decode_all::<VisibleOperands>(&buf, 0)
            .map(|insn| -> anyhow::Result<usize> {
                let (offs, bytes, insn) = insn?;
                let bytes_str: String = bytes.iter().map(|x| format!("{x:02x} ")).collect();
                println!("0x{:04X}: {:<24} {}", offs, bytes_str, insn);
                Ok(bytes.len())
            });

    while let Some(result) = insn_iter.next() {
        if let Err(e) = result {
            return Err(e);
        }
        if num_bytes >= min_size {
            return Ok(num_bytes);
        }

        num_bytes += result?;
    }

    if num_bytes < min_size {
        return Err(anyhow::anyhow!(
            "Not enough bytes to decode instructions: {}",
            num_bytes
        ));
    }

    Ok(num_bytes)
}

fn is_rip_relative_instruction(insn: &DecodedInstruction) -> bool {
    insn.raw.modrm.mod_ == 0 && insn.raw.modrm.rm == 5
}

struct Bounds {
    lowest_address: Address,
    highest_address: Address,
}

fn calculate_rip_relative_memory_access_bounds(
    source_address: &Address,
    length: usize,
) -> anyhow::Result<Bounds> {
    let buf = source_address.memory_slice(length);

    let decoder = Decoder::new64();
    let addresses = decoder
        .decode_all::<VisibleOperands>(&buf, 0)
        .map(|insn| -> anyhow::Result<Address> {
            let (_, _, insn) = insn?;
            if !is_rip_relative_instruction(&insn) {
                return Ok(source_address.clone());
            }
            let absolute_target_address =
                source_address.add(insn.length as usize + insn.raw.disp.value as usize);
            Ok(absolute_target_address)
        })
        .take_while(|x| x.is_ok())
        .map(|x| x.unwrap());

    Ok(Bounds {
        lowest_address: addresses
            .clone()
            .min()
            .ok_or(anyhow::anyhow!("Lower bound not found"))?,
        highest_address: addresses
            .max()
            .ok_or(anyhow::anyhow!("Upper bound not found"))?,
    })
}

fn get_page_size() -> i32 {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        let mut system_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut system_info) };
        return system_info.dwPageSize as i32;
    }

    #[cfg(target_os = "linux")]
    {
        return unsafe { libc::sysconf(libc::_SC_PAGESIZE) as i32 };
    }
}

#[cfg(windows)]
#[repr(u32)]
enum MemoryPageProtection {
    HookftwPageReadonly = winapi::um::winnt::PAGE_READONLY,
    HookftwPageReadwrite = winapi::um::winnt::PAGE_READWRITE,
    HookftwPageExecute = winapi::um::winnt::PAGE_EXECUTE,
    HookftwPageExecuteRead = winapi::um::winnt::PAGE_EXECUTE_READ,
    HookftwPageExecuteReadwrite = winapi::um::winnt::PAGE_EXECUTE_READWRITE,
}

#[cfg(target_os = "linux")]
#[repr(u32)]
enum MemoryPageProtection {
    HOOKFTW_PAGE_READONLY = PROT_READ,
    HOOKFTW_PAGE_READWRITE = PROT_READ | PROT_WRITE,
    HOOKFTW_PAGE_EXECUTE = PROT_EXEC,
    HOOKFTW_PAGE_EXECUTE_READ = PROT_EXEC | PROT_READ,
    HOOKFTW_PAGE_EXECUTE_READWRITE = PROT_EXEC | PROT_READ | PROT_WRITE,
}

#[cfg(windows)]
#[repr(u32)]
enum MemoryPageFlag {
    HookftwMemDefault = winapi::um::winnt::MEM_RESERVE | winapi::um::winnt::MEM_COMMIT,
}

#[cfg(target_os = "linux")]
#[repr(u32)]
enum MemoryPageFlag {
    HOOKFTW_MEM_DEFAULT = MAP_PRIVATE | MAP_ANONYMOUS,
}

fn alloc_page(
    address: &Address,
    size: usize,
    protection: MemoryPageProtection,
    flag: MemoryPageFlag,
) -> *mut u8 {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::memoryapi::VirtualAlloc;
        unsafe {
            VirtualAlloc(
                address.address as *mut winapi::ctypes::c_void,
                size,
                flag as u32,
                protection as u32,
            ) as *mut u8
        }
    }
    #[cfg(target_os = "linux")]
    {
        use libc::{mmap, PROT_NONE};
        unsafe {
            mmap(
                address.address as *mut libc::c_void,
                size as usize,
                protection as i32,
                flag as i32,
                -1,
                0,
            ) as *mut i8
        }
    }
}

#[allow(unused_variables)]
fn free_page(address: *mut u8, size: i32) -> bool {
    #[cfg(target_os = "windows")]
    {
        use winapi::um::memoryapi::VirtualFree;
        use winapi::um::winnt::MEM_RELEASE;
        unsafe { VirtualFree(address as *mut winapi::ctypes::c_void, 0, MEM_RELEASE) != 0 }
    }
    #[cfg(target_os = "linux")]
    {
        use libc::munmap;
        unsafe { munmap(address as *mut libc::c_void, size as usize) == 0 }
    }
}

enum TrampolineAllocResult {
    FiveByteJmp(Address),
    FourteenByteJmp(Address),
}

fn allocate_trampoline(source_address: Address) -> anyhow::Result<TrampolineAllocResult> {
    let page_size: usize = get_page_size() as usize;
    let signed_int_max_value: usize = 0x7fffffff;
    let mut allocation_attempts = 0;

    let lowest_address_reachable_by_five_bytes_jump = source_address
        .lowest_reachable_by_five_byte_jump()
        .ok_or(anyhow::anyhow!(
            "Could not calculate lowest address reachable by five byte jump"
        ))?;

    let mut trampoline: Option<Address> = None;
    let mut target_address = source_address.add(signed_int_max_value + 5);
    while trampoline.is_none() {
        allocation_attempts += 1;
        target_address = target_address.sub(allocation_attempts * page_size);

        if target_address >= lowest_address_reachable_by_five_bytes_jump {
            let address = alloc_page(
                &target_address,
                page_size,
                MemoryPageProtection::HookftwPageExecuteReadwrite,
                MemoryPageFlag::HookftwMemDefault,
            );

            if address.is_null() {
                continue;
            }

            trampoline = Some(Address { address });
        } else {
            let address = alloc_page(
                &target_address,
                page_size,
                MemoryPageProtection::HookftwPageReadwrite,
                MemoryPageFlag::HookftwMemDefault,
            );

            if address.is_null() {
                return Err(anyhow::anyhow!("Could not allocate trampoline"));
            }

            trampoline = Some(Address { address });

            return Ok(TrampolineAllocResult::FourteenByteJmp(
                trampoline.ok_or(anyhow::anyhow!("Could not allocate trampoline"))?,
            ));
        }
    }
    Ok(TrampolineAllocResult::FiveByteJmp(
        trampoline.ok_or(anyhow::anyhow!("Could not allocate trampoline"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() -> anyhow::Result<()> {
        // Encode a simple `add` function with a stack-frame in Sys-V ABI.
        let mut buf = (0..128).map(|_| 0).collect::<Vec<u8>>();
        // let mut add = |request: EncoderRequest| request.encode_extend(&mut buf);
        //
        // add(insn64!(PUSH RBP))?;
        // add(insn64!(MOV RBP, RSP))?;
        // add(insn64!(LEA RAX, qword ptr [RDI + RSI + (args.offset)]))?;
        // add(insn64!(POP RBP))?;
        // add(insn64!(RET))?;
        //
        // let decoder = Decoder::new64();
        //
        // // Decode and print the program for demonstration purposes.
        // for insn in decoder.decode_all::<VisibleOperands>(&buf, 0) {
        //     let (offs, bytes, insn) = insn?;
        //     let bytes: String = bytes.iter().map(|x| format!("{x:02x} ")).collect();
        //     println!("0x{:04X}: {:<24} {}", offs, bytes, insn);
        // }

        let source_address = Address {
            address: buf.as_mut_ptr() as *mut u8,
        };

        // if we can allocate our trampoline in +-2gb range we only need a 5 bytes JMP
        // if we can't, we need a 14 bytes JMP
        let five_bytes_without_cutting_instructions =
            get_length_of_instructions(&source_address, 5)?;
        let fourteen_bytes_without_cutting_instructions =
            get_length_of_instructions(&source_address, 14)?;

        assert_eq!(6, five_bytes_without_cutting_instructions);
        assert_eq!(14, fourteen_bytes_without_cutting_instructions);

        let bounds = calculate_rip_relative_memory_access_bounds(
            &source_address,
            five_bytes_without_cutting_instructions,
        )?;

        assert_eq!(source_address, bounds.lowest_address);
        assert_eq!(source_address, bounds.highest_address);

        assert_eq!(0x1000, get_page_size());

        // Ok(())
        Err(anyhow::anyhow!("Alibi Error"))
    }
}
