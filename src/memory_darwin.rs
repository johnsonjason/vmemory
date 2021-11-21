#![cfg(target_os = "macos")]
use mach::{kern_return::KERN_SUCCESS, message::mach_msg_type_number_t, port::{MACH_PORT_NULL, mach_port_name_t, mach_port_t}, 
vm::{mach_vm_protect, mach_vm_read_overwrite, mach_vm_write}, 
vm_region::{VM_REGION_BASIC_INFO, vm_region_basic_info_data_64_t, vm_region_basic_info_data_t, vm_region_info_t, vm_region_basic_info_64}, 
vm_types::{mach_vm_address_t, mach_vm_size_t}};

pub const _VM_PROT_NONE: i32 = 0x00;
pub const VM_PROT_READ: i32 = 0x01;
pub const VM_PROT_WRITE: i32 = 0x02;
pub const VM_PROT_EXECUTE: i32 = 0x04;


//
// Change the memory page protections on a process at an address
//
pub fn proc_protect(target_task: u32, address: usize, size: usize, protection: i32) -> Result<(), u32> {
    let result = unsafe {
        mach_vm_protect(
            target_task, 
            address as _,
            size as _, 
            false as _,
            protection
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _)
    }
    Ok(())
}

//
// Write the u8 slice to a process at the specified address
//
pub fn write_memory(target_task: u32, _address: usize, buffer: &Vec<u8>) -> Result<(), u32> {
    //
    // Retrieve the current protection of the page where the address being written to is resident
    // Allow read/write/execute permissions and then perform a write operation
    //
    let protection = get_protection(target_task, _address as _).unwrap();
    proc_protect(target_task, _address, buffer.len(), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE).unwrap();

    let result = unsafe {
        mach_vm_write(
            target_task, 
            _address as _, 
            buffer.as_ptr() as _, 
            buffer.len() as _
        )
    };

    //
    // Restore the page's memory protections
    //
    proc_protect(target_task, _address, buffer.len(), protection as _).unwrap();

    if result != KERN_SUCCESS {
        return Err(result as _)
    }

    Ok(())
}

//
// Read from the process, memory that is of size specified in the size parameter
//
pub fn read_memory(target_task: u32, address: usize, size: usize) -> Result<Vec<u8>, u32> {
    let mut buf = vec![0_u8; size];
    let mut read_len: u64 = 0;
    
    let result = unsafe { 
        mach_vm_read_overwrite(
            target_task,
            address as _,
            size as _,
            buf.as_mut_ptr() as _,
            &mut read_len,
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _);
    }

    Ok(buf)
}

//
// Query the memory protection on a region of memory
//
fn get_protection(target_task: u32, _address: mach_vm_address_t) -> Result<u32, u32> {
    let mut count = std::mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
    let mut object_name: mach_port_t = 0;

    let mut address = _address;
    let mut size = unsafe { std::mem::zeroed::<mach_vm_size_t>() };
    let mut info = unsafe { std::mem::MaybeUninit::<vm_region_basic_info_64>::zeroed().assume_init()  };

    let result = unsafe {
        mach::vm::mach_vm_region(
            target_task, 
            &mut address, 
            &mut size,
            VM_REGION_BASIC_INFO, 
            &mut info as *mut vm_region_basic_info_64 as vm_region_info_t, 
            &mut count, 
            &mut object_name
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _)
    }

    Ok(info.protection as _)
}

//
// Referenced from <https://github.com/rbspy/proc-maps/blob/master/src/mac_maps/mod.rs> (MIT)
// Copyright (c) 2016 Julia Evans, Kamal Marhubi Portions (continuous integration setup) Copyright (c) 2016 Jorge Aparicio
//
pub fn get_base_address(target_task: mach_port_name_t, mut address: mach_vm_address_t) -> Result<usize, u32> {
    let mut count = std::mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
    let mut object_name: mach_port_t = 0;

    let mut size = unsafe { std::mem::zeroed::<mach_vm_size_t>() };
    let mut info = unsafe { std::mem::zeroed::<vm_region_basic_info_data_t>() };

    let result = unsafe {
        mach::vm::mach_vm_region(
            target_task, 
            &mut address, 
            &mut size,
            VM_REGION_BASIC_INFO, 
            &mut info as *mut vm_region_basic_info_data_t as vm_region_info_t, 
            &mut count, 
            &mut object_name
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _)
    }

    Ok(address as usize)
}

//
// Referenced from <https://github.com/rbspy/proc-maps/blob/master/src/mac_maps/mod.rs> (MIT)
// Copyright (c) 2016 Julia Evans, Kamal Marhubi Portions (continuous integration setup) Copyright (c) 2016 Jorge Aparicio
//
pub fn get_task_for_pid(pid: u32) -> mach_port_name_t {
    let mut task: mach_port_name_t = MACH_PORT_NULL;
    // sleep for 10ms to make sure we don't get into a race between `task_for_pid` and execing a new
    // process. Races here can freeze the OS because of a Mac kernel bug on High Sierra.
    // See https://jvns.ca/blog/2018/01/28/mac-freeze/ for more.
    std::thread::sleep(std::time::Duration::from_millis(10));
    unsafe {
        let result =
            mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as _, &mut task);
        if result != KERN_SUCCESS {
            return 0;
        }
    }
    task
}
