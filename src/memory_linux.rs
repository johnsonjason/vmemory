#![cfg(target_vendor = "unknown")]
use nix::libc::c_long;
use nix::sys::ptrace;

//
// This function attempts to make ptrace reads more granular rather than just word-sized reads
//
pub fn read_memory(pid: u32, _address: usize, size: usize) -> Result<Vec<u8>, u32> {
    let nix_pid = nix::unistd::Pid::from_raw(pid as _);
    let mut word_buffer: Vec<u8> = Vec::new();

    for n in (_address.._address + size + 16).step_by(std::mem::size_of::<c_long>()) {
        if word_buffer.len() > size {
            word_buffer.truncate(size);
            break;
        }

        let word: [u8; std::mem::size_of::<c_long>()] = match ptrace::read(nix_pid, n as _) {
            Ok(val) => (val as usize).to_ne_bytes(),
            Err(_) => break,
        };

        word_buffer.extend(word.iter().cloned());
    }

    Ok(word_buffer)
}

//
// Unlike vm_write (Mach) and WriteProcessMemory (Windows),
// a write via ptrace is officially documented to bypass the virtual memory page protections
// This function attempts to make ptrace writes more granular rather than just word-sized writes
//
pub fn write_memory(pid: u32, _address: usize, content: &Vec<u8>) -> Result<(), u32> {
    let nix_pid = nix::unistd::Pid::from_raw(pid as _);
    let mut index = 0;

    loop {
        if index + (std::mem::size_of::<c_long>() * 2) > content.len() {
            let mut store =
                read_memory(pid, _address + index, std::mem::size_of::<c_long>() * 2).unwrap();

            let remaining = content.len() - index;
            let left_slice = &content[index..content.len()];

            if left_slice.len() > store.len() {
                return Err(0);
            }

            for n in 0..remaining {
                store[n] = left_slice[n]
            }

            let mut dst = [0u8; std::mem::size_of::<c_long>()];
            dst.clone_from_slice(&store[0..std::mem::size_of::<c_long>()]);

            let store1 = c_long::from_ne_bytes(dst);

            dst.clone_from_slice(
                &store[std::mem::size_of::<c_long>()..std::mem::size_of::<c_long>() * 2],
            );

            let store2 = c_long::from_ne_bytes(dst);
            unsafe {
                ptrace::write(nix_pid, (_address + index) as _, store1 as _).unwrap();
                ptrace::write(
                    nix_pid,
                    (_address + index + std::mem::size_of::<c_long>()) as _,
                    store2 as _,
                )
                .unwrap();
            }
            break;
        }

        let mut _word = [0u8; std::mem::size_of::<c_long>()];
        _word.clone_from_slice(&content[index..index + std::mem::size_of::<c_long>()]);

        let word = c_long::from_ne_bytes(_word);
        unsafe { ptrace::write(nix_pid, (_address + index) as _, word as _).unwrap() }
        index += std::mem::size_of::<c_long>();
    }
    Ok(())
}
