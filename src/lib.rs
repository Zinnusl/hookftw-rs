#![allow(dead_code)]
#![allow(unused_imports)]

use anyhow::{Context, Result};
use clap::{Arg, Parser};
use ffi::DecodedInstruction;
use libc::{free, malloc, memcpy};
use std::ffi::c_int;
use std::ffi::c_void;
use std::fmt::Display;
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

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:p}", self.address)
    }
}

impl<T> From<*mut T> for Address {
    fn from(address: *mut T) -> Self {
        Address {
            address: address as *mut u8,
        }
    }
}

impl From<usize> for Address {
    fn from(address: usize) -> Self {
        Address {
            address: address as *mut u8,
        }
    }
}

impl From<u64> for Address {
    fn from(address: u64) -> Self {
        Address {
            address: address as *mut u8,
        }
    }
}

impl Into<usize> for Address {
    fn into(self) -> usize {
        self.address as usize
    }
}

impl Address {
    /// Returns a slice of the memory at the address.
    /// # Safety
    /// The caller must ensure that the address is valid and that the length is correct.
    fn memory_slice(&self, length: usize) -> &[u8] {
        unsafe { slice::from_raw_parts(self.address, length) }
    }

    fn decode_up_to(&self, length: usize) -> Result<Vec<String>> {
        let buf = self.memory_slice(length + 0xFF);
        Ok(Decoder::new64()
            .decode_all::<VisibleOperands>(&buf, 0)
            .take_while(|result| {
                let (offset, bytes, _) = result.as_ref().unwrap();
                (*offset) as i64 - (bytes.len() as i64) < length as i64
            })
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .map(|insn| {
                let (offset, bytes, insn) = insn;
                format!("0x{:04X}: {:?} {}", offset, bytes, insn)
            })
            .collect())
    }

    fn print_up_to(&self, length: usize) -> Result<()> {
        for instruction in self
            .decode_up_to(length)
            .context("Failed to decode instructions")?
        {
            println!("{}", instruction);
        }

        Ok(())
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

    unsafe fn write(&self, bytes_slice: &[u8]) -> Result<()> {
        copy_nonoverlapping(bytes_slice.as_ptr(), self.address, bytes_slice.len());
        println!(
            "Wrote {} ({:x?}) bytes to address: {:x?}",
            bytes_slice.len(),
            bytes_slice,
            (self.address as usize).to_be_bytes()
        );

        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn get_last_error() -> String {
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winbase::FormatMessageA;
    let last_error = unsafe { GetLastError() };

    let mut buffer = [0u8; 256];
    let length = unsafe {
        FormatMessageA(
            winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM,
            std::ptr::null_mut(),
            last_error,
            0,
            buffer.as_mut_ptr() as *mut i8,
            buffer.len() as u32,
            std::ptr::null_mut(),
        )
    };

    if length == 0 {
        return format!("Failed to get error message for error code: {}", last_error);
    }

    let message = String::from_utf8_lossy(&buffer[..length as usize]);

    format!("Error code: {}, Message: {}", last_error, message)
}

///
///
/// If lpAddress specifies an address above the highest memory address accessible to the process,
/// the function fails with ERROR_INVALID_PARAMETER.
#[cfg(target_os = "windows")]
fn query_page_protection(address: Address) -> Result<MemoryPageProtection> {
    use winapi::ctypes::c_void;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

    let mut memory_basic_information: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe {
        VirtualQuery(
            address.address as *const c_void,
            &mut memory_basic_information,
            mem::size_of::<MEMORY_BASIC_INFORMATION>() as usize,
        )
    };

    if result == 0 {
        return Err(anyhow::anyhow!(
            "[Error] - QueryPageProtection - VirtualQuery failed with: {} {}",
            memory_basic_information.Protect as usize,
            get_last_error()
        ));
    }

    Ok(match memory_basic_information.Protect {
        winapi::um::winnt::PAGE_NOACCESS => MemoryPageProtection::HookftwPageReadonly,
        winapi::um::winnt::PAGE_READONLY => MemoryPageProtection::HookftwPageReadonly,
        winapi::um::winnt::PAGE_READWRITE => MemoryPageProtection::HookftwPageReadwrite,
        winapi::um::winnt::PAGE_EXECUTE => MemoryPageProtection::HookftwPageExecute,
        winapi::um::winnt::PAGE_EXECUTE_READ => MemoryPageProtection::HookftwPageExecuteRead,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE => {
            MemoryPageProtection::HookftwPageExecuteReadwrite
        }
        _ => MemoryPageProtection::HookftwPageReadonly,
    })
}

#[cfg(target_os = "windows")]
fn modify_page_protection(
    address: Address,
    size: usize,
    new_protection: MemoryPageProtection,
) -> Result<MemoryPageProtection> {
    use winapi::ctypes::c_void;
    use winapi::um::memoryapi::VirtualProtect;
    let mut old_protection: u32 = 0;
    let result = unsafe {
        VirtualProtect(
            address.address as *mut c_void,
            size,
            new_protection as u32,
            &mut old_protection,
        )
    };

    if result == 0 {
        return Err(anyhow::anyhow!(
            "[Error] - ModifyPageProtection - VirtualProtect failed with: {}",
            get_last_error()
        ));
    }

    Ok(match old_protection {
        winapi::um::winnt::PAGE_NOACCESS => MemoryPageProtection::HookftwPageReadonly,
        winapi::um::winnt::PAGE_READONLY => MemoryPageProtection::HookftwPageReadonly,
        winapi::um::winnt::PAGE_READWRITE => MemoryPageProtection::HookftwPageReadwrite,
        winapi::um::winnt::PAGE_EXECUTE => MemoryPageProtection::HookftwPageExecute,
        winapi::um::winnt::PAGE_EXECUTE_READ => MemoryPageProtection::HookftwPageExecuteRead,
        winapi::um::winnt::PAGE_EXECUTE_READWRITE => {
            MemoryPageProtection::HookftwPageExecuteReadwrite
        }
        _ => MemoryPageProtection::HookftwPageReadonly,
    })
}

struct Detour {
    original_bytes: Vec<u8>,
    source_address: Address,
    trampoline_address: Address,
    hook_length: usize,
}

impl Detour {
    #[cfg(target_os = "windows")]
    pub fn hook(source_address: Address, new_function: Address) -> Result<Self> {
        use std::borrow::Borrow;

        let trampoline = handled_trampoline_allocation(&source_address)
            .context("[Error] - Detour - Failed to allocate trampoline")?;

        // Make sure that the address of function stays reliable.
        let address_of_hook_function = new_function.address as i64;
        println!(
            "Address of hook function: {:x?}",
            (address_of_hook_function as usize).to_be_bytes()
        );
        let address_delta = address_of_hook_function - source_address.address as i64;

        let hook_length = get_length_of_instructions(
            &source_address,
            if address_delta > std::i32::MAX as i64 || address_delta < std::i32::MIN as i64 {
                14
            } else {
                5
            },
        )
        .context("get_length_of_instructions")?;

        if hook_length < 5 {
            return Err(anyhow::anyhow!(
                "[Error] - Detour - 5 bytes are required to place detour, the hook length is too short: {}",
                hook_length
            ));
        }

        // save original bytes
        let mut original_bytes: Vec<u8> = Vec::with_capacity(hook_length);
        original_bytes.resize(hook_length, 0u8);
        unsafe {
            std::ptr::copy_nonoverlapping(
                source_address.address,
                original_bytes.as_mut_ptr(),
                hook_length,
            )
        };

        let old_page_protection = modify_page_protection(
            source_address,
            hook_length,
            MemoryPageProtection::HookftwPageExecuteReadwrite,
        )?;

        // relocate to be overwritten instructions to trampoline
        let relocated_bytes = relocate(&source_address, hook_length, &trampoline);
        if relocated_bytes.is_empty() {
            return Err(anyhow::anyhow!(
                "[Error] - Detour - Relocation of bytes replaced by hook failed"
            ));
        }

        let trampoline_address = match trampoline {
            TrampolineAllocResult::FiveByteJmp(address) => address,
            TrampolineAllocResult::FourteenByteJmp(address) => address,
        };

        // copy overwritten bytes to trampoline
        unsafe {
            std::ptr::copy_nonoverlapping(
                relocated_bytes.as_ptr(),
                trampoline_address.address,
                relocated_bytes.len(),
            )
        };

        let address_after_relocated_bytes = trampoline_address.add(relocated_bytes.len());

        // write JMP back from trampoline to original code
        let stub_jump_back_length = 14;

        {
            let jump_to_continue_original_code = source_address.add(hook_length).address as i64;
            let jump_to_continue_original_code_instruction_bytes = vec![
                insn64!(JMP qword ptr [RIP + 0])
                    .encode()
                    .context("jump_to_continue_original_code")?,
                jump_to_continue_original_code.to_be_bytes().to_vec(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>();
            unsafe {
                address_after_relocated_bytes
                    .write(jump_to_continue_original_code_instruction_bytes.as_slice())?
            };
        }

        let jmp_to_hooked_function_length =
            if address_delta > std::i32::MAX as i64 || address_delta < std::i32::MIN as i64 {
                14i64
            } else {
                5i64
            };

        println!("Writing to original function");
        // check if a jmp rel32 can reach
        if jmp_to_hooked_function_length == 14i64 {
            // need absolute 14 byte jmp
            let instructions = vec![
                insn64!(JMP qword ptr [RIP + 0])
                    .encode()
                    .context("jump_from_original_to_hook_function abs jmp")?,
                (address_of_hook_function as usize).to_be_bytes().to_vec(),
            ];
            let jump_from_original_to_hook_function: Vec<u8> =
                instructions.into_iter().flatten().collect();
            unsafe { source_address.write(jump_from_original_to_hook_function.as_slice())? };
        } else {
            let relative_jump_to_address_of_hook_function =
                address_of_hook_function - source_address.address as i64 - 5;
            let jump_from_original_to_hook_function =
                insn64!(JMP(relative_jump_to_address_of_hook_function as i32))
                    .encode()
                    .context("jump_from_original_to_hook_function relative jmp")?;
            unsafe { source_address.write(jump_from_original_to_hook_function.as_slice())? };
        }

        // NOP left over bytes
        if hook_length < jmp_to_hooked_function_length as usize {
            return Err(anyhow::anyhow!(
                "[Error] - Detour - Hook length is too small: {}",
                hook_length
            ));
        }

        // restore page protection
        modify_page_protection(source_address, hook_length, old_page_protection)?;

        // make trampoline executable
        modify_page_protection(
            trampoline_address,
            relocated_bytes.len() + stub_jump_back_length,
            MemoryPageProtection::HookftwPageExecuteReadwrite,
        )?;

        Ok(Detour {
            original_bytes,
            source_address,
            trampoline_address,
            hook_length,
        })
    }

    pub unsafe fn unhook(&self) {
        todo!();
    }
}

fn get_length_of_instructions(source_address: &Address, min_size: usize) -> Result<usize> {
    // Plus 0xFF to ensure we have enough bytes to decode the instructions to get to the minimum size.
    let buf = source_address.memory_slice(min_size + 0xFF);

    let mut num_bytes = 0;

    let decoder = Decoder::new64();
    let mut insn_iter =
        decoder
            .decode_all::<VisibleOperands>(&buf, 0)
            .map(|insn| -> Result<usize> {
                let (_, bytes, _) = insn?;
                // let bytes_str: String = bytes.iter().map(|x| format!("{x:02x} ")).collect();
                // println!("0x{:04X}: {:<24} {}", offs, bytes_str, insn);
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
    insn.attributes.contains(InstructionAttributes::IS_RELATIVE)
}

fn is_rip_relative_memory_instruction(insn: &DecodedInstruction) -> bool {
    insn.attributes.contains(InstructionAttributes::HAS_MODRM)
        && insn.raw.modrm.mod_ == 0
        && insn.raw.modrm.rm == 5
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum RipRelativeBoundsResult {
    RipRelativeBounds(Bounds),
    NoRipRelativeInstructions,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Bounds {
    lowest_address: Address,
    highest_address: Address,
}

fn calculate_rip_relative_memory_access_bounds(
    source_address: &Address,
    length: usize,
) -> RipRelativeBoundsResult {
    let buf = source_address.memory_slice(0xFF);

    let decoder = Decoder::new64();
    let addresses = decoder
        .decode_all::<VisibleOperands>(&buf, 0)
        .scan(0usize, |bytes_running_total, insn| match insn {
            // FIXME: Remove scan, because the first element in the tuple that comes from the iter is the offset, which is what we
            // needed. (aka bytes_running_total)
            Ok((_, bytes, insn)) => {
                if *bytes_running_total > length {
                    return None;
                }

                *bytes_running_total += bytes.len();

                if !is_rip_relative_instruction(&insn) {
                    return Some(Ok(None));
                }

                let absolute_target_address = source_address
                    .add(bytes.len() + insn.length as usize + insn.raw.disp.value as usize);
                return Some(Ok(Some(absolute_target_address)));
            }
            Err(e) => Some(Err(e)),
        })
        .filter_map(|x| x.transpose())
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
        .collect::<Vec<Address>>();

    if addresses.is_empty() {
        return RipRelativeBoundsResult::NoRipRelativeInstructions;
    }

    RipRelativeBoundsResult::RipRelativeBounds(Bounds {
        lowest_address: addresses.iter().min().copied().unwrap(),
        highest_address: addresses.iter().max().copied().unwrap(),
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
#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug)]
enum TrampolineAllocResult {
    FiveByteJmp(Address),
    FourteenByteJmp(Address),
}

fn allocate_trampoline(source_address: &Address) -> Result<TrampolineAllocResult> {
    let page_size = get_page_size() as usize;
    let signed_int_max_value: usize = 0x7fffffff;

    let lowest_address_reachable_by_five_byte_jump = source_address
        .lowest_reachable_by_five_byte_jump()
        .ok_or(anyhow::anyhow!(
            "Could not calculate lowest address reachable by five byte jump"
        ))?;

    let target_address = source_address.add(signed_int_max_value + 5);

    println!(
        "Lowest address reachable by five byte jump: {:?}",
        lowest_address_reachable_by_five_byte_jump
    );

    let allocated_five_byte_jump_trampoline = (lowest_address_reachable_by_five_byte_jump.address
        as u64..target_address.address as u64)
        .step_by(page_size)
        .map(|x| Address {
            address: x as *mut u8,
        })
        .map(|x| {
            alloc_page(
                &x,
                page_size,
                MemoryPageProtection::HookftwPageReadwrite,
                MemoryPageFlag::HookftwMemDefault,
            )
        })
        .filter(|x| {
            !x.is_null()
                && x >= &lowest_address_reachable_by_five_byte_jump.address
                && x < &target_address.address
        })
        .take(1)
        .map(|x| Address { address: x })
        .last();

    if let Some(trampoline) = allocated_five_byte_jump_trampoline {
        println!("Allocated five byte jump trampoline: {:?}", trampoline);
        assert!(
            trampoline.address as u64 >= lowest_address_reachable_by_five_byte_jump.address as u64
        );
        assert!(trampoline.address as u64 <= target_address.address as u64);

        // init with nops
        let nops = (0..page_size).map(|_| 0x90).collect::<Vec<u8>>();
        unsafe { trampoline.write(nops.as_slice())? };

        return Ok(TrampolineAllocResult::FiveByteJmp(trampoline));
    }

    let address = alloc_page(
        &lowest_address_reachable_by_five_byte_jump,
        page_size,
        MemoryPageProtection::HookftwPageReadwrite,
        MemoryPageFlag::HookftwMemDefault,
    );

    if address.is_null() {
        return Err(anyhow::anyhow!("Could not allocate trampoline"));
    }

    let address = Address { address };
    // init with nops
    let nops = (0..page_size).map(|_| 0x90).collect::<Vec<u8>>();
    unsafe { address.write(nops.as_slice())? };

    println!("Allocated fourteen byte jump trampoline: {:?}", address);
    return Ok(TrampolineAllocResult::FourteenByteJmp(address));
}

fn allocate_trampoline_within_bounds(
    _source_address: &Address,
    _bounds: Bounds,
) -> Result<TrampolineAllocResult> {
    todo!();
}

fn handled_trampoline_allocation(source_address: &Address) -> Result<TrampolineAllocResult> {
    let five_bytes_without_cutting_instructions = get_length_of_instructions(&source_address, 5)?;
    let fourteen_bytes_without_cutting_instructions =
        get_length_of_instructions(&source_address, 14)?;

    let five_bytes_bounds = calculate_rip_relative_memory_access_bounds(
        source_address,
        five_bytes_without_cutting_instructions,
    );

    match five_bytes_bounds {
        RipRelativeBoundsResult::NoRipRelativeInstructions => {
            let trampoline = allocate_trampoline(source_address).context(format!(
                "[Error] - Trampoline - Failed to allocate trampoline for hookAddress {}",
                source_address
            ))?;

            match trampoline {
                TrampolineAllocResult::FiveByteJmp(_) => {
                    return Ok(trampoline);
                }
                TrampolineAllocResult::FourteenByteJmp(_) => {
                    let fourteen_bytes_bounds = calculate_rip_relative_memory_access_bounds(
                        source_address,
                        fourteen_bytes_without_cutting_instructions,
                    );

                    match fourteen_bytes_bounds {
                        RipRelativeBoundsResult::NoRipRelativeInstructions => {
                            return Ok(trampoline);
                        }
                        RipRelativeBoundsResult::RipRelativeBounds(_) => {
                            return Err(anyhow::anyhow!("[Error] - Trampoline - The trampoline could not be allocated withing +-2GB range. The instructions at the hook address do contain rip-relative memory access. Relocating those is not supported when the trampoline is not in +-2GB range!"));
                        }
                    }
                }
            }
        }
        RipRelativeBoundsResult::RipRelativeBounds(_bounds) => {
            todo!();
            // let trampoline = allocate_trampoline_within_bounds(source_address, five_bytes_bounds).context(format!("[Error] - Trampoline - Failed to allocate trampoline within bounds [{}, {}]", bounds.lowest_address, bounds.highest_address))?;
            //
            // match trampoline {
            // }
            // if (*restrictedRelocation) {
            // printf("[Error] - Trampoline - The trampoline could not be allocated "
            //         "withing +-2GB range. The instructions at the hook address do "
            //         "contain rip-relative memory access. Relocating those is not "
            //         "supported when the trampoline is not in +-2GB range!\n");
            // return nullptr;
            // }
        }
    }
}

fn relocate(
    source_address: &Address,
    amount_of_instructions: usize,
    // trampoline is target address & restrictedRelocation in one
    _trampoline: &TrampolineAllocResult,
) -> Vec<u8> {
    /* Instructions that need to be relocated
      32bit:
            - call
            - jcc
            - loopcc
            - XBEGIN //not handled

       64bit:
            -call
            - jcc
            - loopcc
            - XBEGIN //not handled
            - rip-relative memory access (ModR/M addressing)
    */
    Decoder::new64()
        .decode_all::<VisibleOperands>(
            source_address.memory_slice(amount_of_instructions + 0xFF),
            0,
        )
        .take_while(|result| {
            let (offset, bytes, _) = result.as_ref().unwrap();
            (*offset) as i64 - (bytes.len() as i64) < amount_of_instructions as i64
        })
        .map(|result| {
            let (_, bytes, insn) = result.unwrap();
            if is_rip_relative_instruction(&insn) {
                unimplemented!("Relocating rip-relative instructions is not supported yet");
            }
            bytes
        })
        .flatten()
        .copied()
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use libc::rand;

    use super::*;

    fn test_single_instruction(insn: EncoderRequest) -> bool {
        let insn = insn.encode().unwrap();
        let decoder = Decoder::new64();
        let insn_decoded = decoder
            .decode_first::<VisibleOperands>(&insn)
            .unwrap()
            .unwrap();

        is_rip_relative_instruction(&insn_decoded)
    }

    #[test]
    fn test_is_rip_relative_instruction() -> Result<()> {
        assert_eq!(false, test_single_instruction(insn64!(MOV RAX, 0x1234)));
        assert_eq!(false, test_single_instruction(insn64!(CMP RAX, 0x1234)));
        assert_eq!(true, test_single_instruction(insn64!(JMP 0x1234)));
        assert_eq!(false, test_single_instruction(insn64!(ADD RAX, 0x1234)));
        assert_eq!(false, test_single_instruction(insn64!(AND RAX, 0x1234)));
        assert_eq!(true, test_single_instruction(insn64!(CALL 0x1234)));

        assert_eq!(
            true,
            test_single_instruction(insn64!(MOV RAX, qword ptr [RIP + 0x1234]))
        );
        assert_eq!(
            true,
            test_single_instruction(insn64!(LEA RAX, qword ptr [RIP + 0x1234]))
        );
        assert_eq!(
            true,
            test_single_instruction(insn64!(CMP RAX, qword ptr [RIP + 0x1234]))
        );
        assert_eq!(
            true,
            test_single_instruction(insn64!(JMP qword ptr [RIP + 0x1234]))
        );
        assert_eq!(
            true,
            test_single_instruction(insn64!(ADD RAX, qword ptr [RIP + 0x1234]))
        );
        assert_eq!(
            true,
            test_single_instruction(insn64!(AND RAX, qword ptr [RIP + 0x1234]))
        );

        Ok(())
    }

    #[test]
    fn test_calculate_rip_relative_memory_access_bounds_good_case() -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        let mut add = |request: EncoderRequest| request.encode_extend(&mut buf);

        add(insn64!(MOV RBP, RSP))?;
        add(insn64!(MOV RSP, RBP))?;
        add(insn64!(RET))?;

        let source_address = Address {
            address: buf.as_mut_ptr() as *mut u8,
        };

        let bounds = calculate_rip_relative_memory_access_bounds(&source_address, 5);

        assert_eq!(
            RipRelativeBoundsResult::NoRipRelativeInstructions,
            bounds,
            "Expected no rip-relative instructions"
        );

        Ok(())
    }

    fn test_calculate_rip_relative_memory_access_bounds_bad_case() -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        let mut add = |request: EncoderRequest| request.encode_extend(&mut buf);

        add(insn64!(MOV RBP, RSP))?;
        add(insn64!(JMP 0x0010))?;
        add(insn64!(JMP 0x1100))?;

        let source_address = Address {
            address: buf.as_mut_ptr() as *mut u8,
        };

        let bounds = calculate_rip_relative_memory_access_bounds(&source_address, 5);

        if let RipRelativeBoundsResult::RipRelativeBounds(bounds) = bounds {
            assert_eq!(
                0x0010 + source_address.address as usize,
                bounds.lowest_address.address as usize
            );
            assert_eq!(
                0x1100 + source_address.address as usize,
                bounds.highest_address.address as usize
            );
        } else {
            assert!(false, "Expected rip-relative instructions");
        }

        Ok(())
    }

    #[test]
    fn test_query_page_protection() -> Result<()> {
        let mut buf = Vec::with_capacity(128);
        let mut add = |request: EncoderRequest| request.encode_extend(&mut buf);

        add(insn64!(MOV RBP, RSP))?;
        add(insn64!(MOV RSP, RBP))?;
        add(insn64!(RET))?;

        let source_address = Address {
            address: buf.as_mut_ptr() as *mut u8,
        };

        let page_protection = query_page_protection(source_address)?;

        assert_eq!(
            MemoryPageProtection::HookftwPageReadwrite,
            page_protection,
            "Expected read-write page protection"
        );

        let source_address = Address {
            address: 0x0000_000B_0000_0000 as *mut u8,
        };

        let page_protection = query_page_protection(source_address)?;

        assert_eq!(
            MemoryPageProtection::HookftwPageReadonly,
            page_protection,
            "Expected read-only page protection"
        );

        Ok(())
    }

    #[test]
    fn test_jmp_sizes() -> Result<()> {
        let insn = insn64!(JMP(0x1000i32)).encode()?;
        println!("{} ({:x?})", format_instructions(&insn), insn);
        assert_eq!(5, insn.len());

        let test = 0xaabbccddeeffaabbu64;
        let instructions = vec![
            insn64!(JMP qword ptr [RIP + 0]).encode()?,
            test.to_be_bytes().to_vec(),
        ];
        let insn: Vec<u8> = instructions.into_iter().flatten().collect();
        // Everything is working as expected
        // Output of this is incorrect, see https://github.com/zyantific/zydis/issues/188
        println!("{} ({:x?})", format_instructions(&insn), insn);
        assert_eq!(14, insn.len());

        Ok(())
    }

    fn format_instructions(insn: &Vec<u8>) -> String {
        Decoder::new64()
            .decode_all::<VisibleOperands>(&insn, 0)
            .map(|insn| insn.unwrap().2)
            .map(|insn| format!("{}", insn))
            .collect::<Vec<String>>()
            .join("\n")
    }

    fn victim_func() -> i32 {
        // This is a function that we will hook
        // It needs to be at least 14 bytes long
        let a = 1;
        let b = 2;
        let c = a + b;
        let d = c + 1;
        let e = d + 1;
        let f = e + 1;
        let g = f + 1;
        println!("Hello, world! {}", g);
        c + f
    }

    fn attacker_func() -> i32 {
        let a = 5;
        let b = 8;
        let c = a + b;
        let d = c + 1;
        let e = d + 1;
        let f = e + 1;
        let g = f + 1;
        println!("Hello, hook! {}", g);
        g + f
    }

    #[test]
    fn it_works() -> Result<()> {
        let victim_address = unsafe { std::mem::transmute::<_, u64>(victim_func as fn() -> i32) };
        let attacker_address =
            unsafe { std::mem::transmute::<_, u64>(attacker_func as fn() -> i32) };

        let _detour = Detour::hook(victim_address.into(), attacker_address.into())
            .context("Creating Detour Hook")?;

        assert_eq!(33, victim_func());

        Ok(())
    }
}
