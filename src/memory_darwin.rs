#![cfg(target_os = "macos")]
use mach::{
    kern_return::{KERN_PROTECTION_FAILURE, KERN_SUCCESS},
    message::mach_msg_type_number_t,
    port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL},
    vm::{
        mach_vm_allocate, mach_vm_deallocate, mach_vm_protect, mach_vm_read_overwrite,
        mach_vm_write,
    },
    vm_region::{
        vm_region_basic_info_64, vm_region_basic_info_data_64_t, vm_region_basic_info_data_t,
        vm_region_info_t, VM_REGION_BASIC_INFO,
    },
    vm_types::{mach_vm_address_t, mach_vm_size_t},
};

pub const _VM_PROT_NONE: i32 = 0x00;
pub const VM_PROT_READ: i32 = 0x01;
pub const VM_PROT_WRITE: i32 = 0x02;
pub const VM_PROT_EXECUTE: i32 = 0x04;

//
// Change the memory page protections on a process at an address
//
pub fn proc_protect(
    target_task: u32,
    address: usize,
    size: usize,
    protection: i32,
) -> Result<(), u32> {
    let result =
        unsafe { mach_vm_protect(target_task, address as _, size as _, false as _, protection) };

    if result != KERN_SUCCESS {
        return Err(result as _);
    }

    Ok(())
}

//
// Write the u8 vector to a process at the specified address
//
pub fn write_memory(target_task: u32, _address: usize, buffer: &Vec<u8>) -> Result<(), u32> {
    //
    // Retrieve the current protection of the page where the address being written to is resident
    // If setting the region permission fails, read it, unmap it, then re-map it
    // Allow read/write/execute permissions and then perform a write operation
    //
    let _protection = get_protection(target_task, _address as _).unwrap();
    let region_address = _protection.2;
    let region_size = _protection.1;
    let region_protection = _protection.0;

    match proc_protect(
        target_task,
        region_address,
        region_size,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    ) {
        Ok(_) => (),
        Err(e) => {
            if e == KERN_PROTECTION_FAILURE as _ {
                unsafe { sub_alloc(target_task, region_address) }
                proc_protect(
                    target_task,
                    region_address,
                    _protection.1,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
                )
                .unwrap()
            } else {
                panic!("Setting memory region protection failed with: {}", e)
            }
        }
    }

    let result = unsafe {
        mach_vm_write(
            target_task,
            _address as _,
            buffer.as_ptr() as _,
            buffer.len() as _,
        )
    };

    //
    // Restore the page's memory protections
    //
    proc_protect(
        target_task,
        region_address,
        region_size,
        region_protection as _,
    )
    .unwrap();

    if result != KERN_SUCCESS {
        return Err(result as _);
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
fn get_protection(
    target_task: u32,
    _address: mach_vm_address_t,
) -> Result<(u32, usize, usize), u32> {
    let mut count = std::mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
    let mut object_name: mach_port_t = 0;

    let mut address = _address;
    let mut size = unsafe { std::mem::zeroed::<mach_vm_size_t>() };
    let mut info =
        unsafe { std::mem::MaybeUninit::<vm_region_basic_info_64>::zeroed().assume_init() };

    let result = unsafe {
        mach::vm::mach_vm_region(
            target_task,
            &mut address,
            &mut size,
            VM_REGION_BASIC_INFO,
            &mut info as *mut vm_region_basic_info_64 as vm_region_info_t,
            &mut count,
            &mut object_name,
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _);
    }

    Ok((info.protection as _, size as _, address as _))
}

//
// Referenced from <https://github.com/rbspy/proc-maps/blob/master/src/mac_maps/mod.rs> (MIT)
// Copyright (c) 2016 Julia Evans, Kamal Marhubi Portions (continuous integration setup) Copyright (c) 2016 Jorge Aparicio
//
pub fn get_base_address(
    target_task: mach_port_name_t,
    mut address: mach_vm_address_t,
) -> Result<(usize, usize), u32> {
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
            &mut object_name,
        )
    };

    if result != KERN_SUCCESS {
        return Err(result as _);
    }

    Ok((address as usize, size as usize))
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
        let result = mach::traps::task_for_pid(mach::traps::mach_task_self(), pid as _, &mut task);
        if result != KERN_SUCCESS {
            return 0;
        }
    }
    task
}

//
// Used only when write_memory fails to set the memory protection to writeable,
// so an attempt will be made to query the attributes of the region (size, current protection)
// and then an attempt will be made to read the memory of the region and copy it to a temporary buffer, then deallocate the region.
// When the region is deallocated, a new, empty region will be allocated at the same - prior address which will be set to VM_PROT_ALL (R/W/X)
// And then the temporary buffer will be copied to fill the new empty region
// The region protections will be set back to the original protections of the region prior to deallocation
//
unsafe fn sub_alloc(target_task: mach_port_name_t, address: usize) {
    //
    // Query region attributes
    //
    let info = get_protection(target_task, address as _).unwrap();
    let size = info.1;

    //
    // Copyregion's memory into a temporary buffer and then deallocate the memory region
    //
    let buffer = read_memory(target_task, address, size).unwrap();

    if mach_vm_deallocate(target_task, address as _, size as _) != KERN_SUCCESS {
        panic!("map could not be deallocated")
    }

    //
    // Allocate a new memory region at the same virtual address
    //
    if mach_vm_allocate(target_task, &mut (address as _), info.1 as _, true as _) != KERN_SUCCESS {
        panic!("sub-map could not be allocated")
    }

    //
    // Allow RWX on the region and then write the temporary buffer to the region
    //
    proc_protect(
        target_task,
        address as _,
        size as _,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    )
    .unwrap();

    write_memory(target_task, address, &buffer).unwrap();

    //
    // Restore the original region protections
    //
    proc_protect(target_task, address as _, size as _, info.0 as _).unwrap();
}
