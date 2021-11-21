use ntapi::ntpsapi::{NtQueryInformationThread, THREAD_BASIC_INFORMATION};
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::MODULEENTRY32;
use winapi::um::tlhelp32::Module32First;
use winapi::um::tlhelp32::TH32CS_SNAPMODULE;
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory};

#[macro_export]
macro_rules! is_valid_handle {
    ($handle:expr) => {
        ($handle != 0 as HANDLE && $handle != INVALID_HANDLE_VALUE)
    }
}

// Safely close the handle to the process
//
fn close_valid_handle(value: HANDLE) -> bool {
    if is_valid_handle!(value) {
        unsafe { CloseHandle(value) };
        return true;
    }
    return false;
}

pub fn write_memory(process: HANDLE, address: usize, buffer: &Vec<u8>) -> Result<(), u32> {

    let mut old_protection: DWORD = 0;

    unsafe {
        if VirtualProtectEx(
            process, 
            address as _, 
            buffer.len(), 
            PAGE_EXECUTE_READWRITE, 
            &mut old_protection
        ) == 0 {
            return Err(GetLastError())
        }
    };

    unsafe {
        if WriteProcessMemory(
            process, 
            address as _, 
            buffer.as_ptr() as *const _, 
            buffer.len(), 
            0 as _
        ) == 0 {
            return Err(GetLastError())
        }
    }

    unsafe {
        if VirtualProtectEx(
            process, 
            address as _, 
            buffer.len(), 
            old_protection, 
            &mut old_protection
        ) == 0 {
            return Err(GetLastError())
        }
    };

    Ok(())
}

pub fn read_memory(process: HANDLE, address: usize, size: usize) -> Result<Vec<u8>, u32> {
    let mut memory: Vec<u8> = Vec::new();
    memory.resize(size, 0);

    unsafe {
        if ReadProcessMemory(
            process, 
            address as _, 
            memory.as_ptr() as *mut _, 
            size, 
            0 as _
        ) == 0 {
            return Err(GetLastError())
        }
    };

    Ok(memory)
}

pub fn get_base_address(process: HANDLE, thread: Option<HANDLE>, process_id: u32) -> Result<usize, u32> {
    const PEB_OFFSET: usize = 0x60;
    const BASE_OFFSET: usize = 0x10;

    if thread.is_some() {
        let mut thread_basic_information: THREAD_BASIC_INFORMATION = unsafe { std::mem::MaybeUninit::<THREAD_BASIC_INFORMATION>::zeroed().assume_init() };
        let mut return_length: u32 = 0;

        let result = unsafe {
            NtQueryInformationThread(
                thread.unwrap(),
                0,
                &mut thread_basic_information as *mut THREAD_BASIC_INFORMATION as _,
                std::mem::size_of_val(&thread_basic_information) as _,
                &mut return_length
            )
        };

        if result != 0 {
            return Err(result as _)
        }

        let mut peb_ptr: usize = 0;
        //
        // Parse the TEB for the remote process to retrieve that process's process environment block (PEB)
        // Retrieve the base address of the first module from the PEB
        //
        unsafe {

            if ReadProcessMemory(
                process, 
                (thread_basic_information.TebBaseAddress as usize + PEB_OFFSET) as _, 
                &mut peb_ptr as *mut _ as _, 
                std::mem::size_of_val(&peb_ptr), 
                0 as *mut usize
            ) == 0 {
                return Err(GetLastError())
            }

            if ReadProcessMemory(
                process, 
                (peb_ptr + BASE_OFFSET) as _, 
                &mut peb_ptr as *mut _ as _,
                std::mem::size_of_val(&peb_ptr), 
                0 as *mut usize
            ) == 0 {
                return Err(GetLastError())
            }

            if peb_ptr as usize == 0 {
                return Err(GetLastError())
            }
        };
        return Ok(peb_ptr as usize)
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id) };


    let mut module_entry: MODULEENTRY32 = unsafe { std::mem::MaybeUninit::<MODULEENTRY32>::zeroed().assume_init() };
    module_entry.dwSize = std::mem::size_of_val(&module_entry) as u32;

    unsafe {
        if Module32First(snapshot, &mut module_entry) == false as _ {
            close_valid_handle(snapshot);
            return Err(GetLastError())
        }
    }

    close_valid_handle(snapshot);
    Ok(module_entry.modBaseAddr as usize)
}
