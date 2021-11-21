#![allow(unused_imports)]
#![allow(dead_code)]
#[cfg(target_family = "windows")]
mod memory_windows;

#[cfg(target_vendor = "apple")]
mod memory_darwin;

#[cfg(target_vendor = "unknown")]
mod memory_linux;

#[cfg(target_vendor = "unknown")]
use nix::sys::ptrace;
#[cfg(any(target_vendor = "unknown", target_os = "macos"))]
use nix::libc::{SIGCONT, SIGKILL, SIGTRAP, WIFSTOPPED, WSTOPSIG, c_char, fork, kill, pid_t, waitpid};
#[cfg(any(target_vendor = "unknown", target_os = "macos"))]
use nix::unistd::close;

#[cfg(target_family = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_family = "windows")]
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
#[cfg(target_family = "windows")]
use winapi::um::winnt::HANDLE;

use std::mem::MaybeUninit;

#[cfg(target_os = "macos")]
use nix::libc::{POSIX_SPAWN_START_SUSPENDED, posix_spawn, posix_spawnattr_init, posix_spawnattr_setflags, posix_spawnattr_t};

use std::ffi::CString;


#[cfg(any(target_os = "macos", target_family = "windows"))]
pub struct ProcessMemory {
    base_address: usize,
    handle: usize,
    pid: u32,
    thread: usize,
}

#[cfg(target_vendor = "unknown")]
pub struct ProcessMemory {
    base_address: usize,
    pid: u32
}

//
// Safely close the handle to the process
//
#[cfg(target_family = "windows")]
fn close_valid_handle(value: HANDLE) -> bool {
    if is_valid_handle!(value) {
        unsafe { CloseHandle(value) };
        return true;
    }
    return false;
}

#[cfg(target_family = "windows")]
fn delimit(text: &Vec<String>) -> String {
    let mut result: String = String::new();
    for s in text {
        result.push_str(s.as_str());
        result.push(' ');
    }
    result.pop();
    result
}


//
// Referenced from <https://github.com/dfinity/ic/blob/c58c75a687621530b2635b22630e9562424fa3b3/rs/canister_sandbox/common/src/process.rs>
// Using the Apache 2 License <http://www.apache.org/licenses/LICENSE-2.0>
// Null-terminate an array of likely null-terminated strings
//
#[cfg(target_os = "macos")]
fn make_null_terminated_string_array(strings: &mut Vec<std::ffi::CString>) -> Vec<*mut c_char> {
    let mut result = Vec::<*mut c_char>::new();
    for s in strings {
        result.push(s.as_ptr() as *mut c_char);
    }
    result.push(std::ptr::null::<c_char>() as *mut c_char);
    result
}

//
// Referenced from <https://github.com/dfinity/ic/blob/c58c75a687621530b2635b22630e9562424fa3b3/rs/canister_sandbox/common/src/process.rs>
// Using the Apache 2 License <http://www.apache.org/licenses/LICENSE-2.0>
// Parse the vector of argv strings into C strings and return it
//
#[cfg(target_os = "macos")]
fn collect_argv(argv: &[String]) -> Vec<std::ffi::CString> {
    argv.iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect::<Vec<std::ffi::CString>>()
}

//
// Referenced from <https://github.com/dfinity/ic/blob/c58c75a687621530b2635b22630e9562424fa3b3/rs/canister_sandbox/common/src/process.rs>
// Using the Apache 2 License <http://www.apache.org/licenses/LICENSE-2.0>
// Collect the environment variables and return a vector of FFI-compatible C strings
//
#[cfg(target_os = "macos")]
fn collect_env() -> Vec<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::env::vars_os().map(|(key, value) | {
        std::ffi::CString::new(
            [
                key.as_os_str().as_bytes(),
                &[b'='],
                value.as_os_str().as_bytes(),
            ]
            .concat()
        )
        .unwrap()
    })
    .collect::<Vec<std::ffi::CString>>()
}

//
// Get the base address for the the first section in the process via procfs
//
#[cfg(target_vendor = "unknown")]
pub fn get_main_module(pid: u32) -> usize {
    use std::fs::File;
    use std::io::BufRead;
    let proc = format!("/proc/{process_id}/maps", process_id=pid);
    let file = File::open(proc).unwrap();
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        for token in line.unwrap().split("-") {
            return usize::from_str_radix(token, 16).unwrap();
        }
    }
    0
}

#[cfg(target_vendor = "unknown")]
fn create_reference_process(file_name: &str, arguments: &Vec<String>) {
    ptrace::traceme().unwrap();
    let cfile = CString::new(file_name).unwrap();
    let mut cfile_args: Vec<CString> = vec![cfile];

    for argument in arguments {
        cfile_args.push(CString::new(argument.as_str()).unwrap());
    }

    nix::unistd::execv(&cfile_args[0], &cfile_args).unwrap();
}

impl ProcessMemory {
    #[cfg(target_family = "windows")]
    pub fn attach_process(pid: u32) -> Option<ProcessMemory> {
        use winapi::um::{processthreadsapi::OpenProcess, winnt::PROCESS_ALL_ACCESS};
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;
        use winapi::um::winnt::HANDLE;
        use crate::memory_windows::get_base_address;

        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false as _, pid) };

        if !is_valid_handle!(process) {
            return None
        }

        let base = get_base_address(process, None, pid).unwrap();

        Some(
            ProcessMemory{
                base_address: base,
                handle: process as _,
                pid: pid,
                thread: 0
            }
        )
    }

    #[cfg(target_vendor = "apple")]
    pub fn attach_process(pid: u32) -> Option<ProcessMemory> {
        let task = memory_darwin::get_task_for_pid(pid as _);

        if task == 0 {
            return None
        }

        let base = memory_darwin::get_base_address(task, 1).unwrap();

        Some(
            ProcessMemory{
                base_address: base,
                handle: task as _,
                pid: pid as _,
                thread: 0,
            }
        )
    }

    #[cfg(target_vendor = "unknown")]
    pub fn attach_process(pid: u32) ->  Option<ProcessMemory> {
        let nix_pid = nix::unistd::Pid::from_raw(pid as _);

        match ptrace::attach(nix_pid) {
            Ok(_) => (),
            Err(_) => return None
        }

        let base = get_main_module(pid);

        if base == 0 {
            return None
        }

        Some(
            ProcessMemory{
                base_address: base,
                pid: pid
            }
        )
    }

    #[cfg(target_vendor = "unknown")]
    pub fn new_process(file_name: &str, arguments: &Vec<String>) -> Option<ProcessMemory> {
        let pid: pid_t = unsafe { fork() };

        match pid {
            0 => create_reference_process(file_name, &arguments),
            -1 => return None,
            _ => ()
        }

        unsafe {
            let mut status: i32 = 0;
            waitpid(pid, &mut status, 0);
            if WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP {
                panic!("waitpid failed");
            }
        }

        let base = get_main_module(pid as _);
        
        Some(
            ProcessMemory {
                base_address: base,
                pid: pid as _
            }
        )
    }

    #[cfg(target_vendor = "apple")]
    pub fn new_process(file_name: &str, arguments: &Vec<String>) -> Option<ProcessMemory> {
        let mut pid: pid_t = 0;
        unsafe {
            //
            // Allocate, initialize a POSIX spawn attribute structure with the flags POSIX_SPAWN_START_SUSPENDED which will create a process in a suspended state
            //
            let mut posix_attr = MaybeUninit::<posix_spawnattr_t>::uninit();
            posix_spawnattr_init(posix_attr.as_mut_ptr());
            let mut posix_attr = posix_attr.assume_init();
            posix_spawnattr_setflags(&mut posix_attr, POSIX_SPAWN_START_SUSPENDED as _);

            //
            // Collect the environment variables and launch arguments and pass them to posix_spawn(2)
            //
            let mut envp = collect_env();
            let envpp = make_null_terminated_string_array(&mut envp);

            let mut argvp = collect_argv(arguments.as_slice());
            let argvpp = make_null_terminated_string_array(&mut argvp);

            let cfile_name = CString::new(file_name).unwrap();
            //
            // Spawn a new process and receive the process ID into pid
            //
            if posix_spawn(
                &mut pid,
                cfile_name.as_ptr(),
                0 as _, 
                &posix_attr, 
                argvpp.as_ptr(), 
                envpp.as_ptr()
            ) != 0 {
                return None
            }
        }

        let task = memory_darwin::get_task_for_pid(pid as _);

        if task == 0 {
            panic!("Failed to get task port for process");
        }

        let base = memory_darwin::get_base_address(task, 1).unwrap();

        Some(
            ProcessMemory{
                base_address: base,
                handle: task as _,
                pid: pid as _,
                thread: 0,
            }
        )
    }

    #[cfg(target_family = "windows")]
    pub fn new_process(file_path: &str, args: &Vec<String>) -> Option<ProcessMemory> {
        use winapi::um::{processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA}, winbase::CREATE_SUSPENDED};

        use crate::memory_windows::get_base_address;

        let proc_string = CString::new(file_path).unwrap();
        let argv_text = delimit(&args);
        let argv = CString::new(argv_text.as_str()).unwrap();

        let mut start_up: STARTUPINFOA = unsafe { std::mem::MaybeUninit::<STARTUPINFOA>::zeroed().assume_init() };
        let mut proc_info: PROCESS_INFORMATION = unsafe { std::mem::MaybeUninit::<PROCESS_INFORMATION>::zeroed().assume_init() };

        let result = unsafe {
            CreateProcessA(
                proc_string.as_ptr(),
                argv.as_ptr() as _,
                0 as _,
                0 as _,
                0,
                CREATE_SUSPENDED,
                0 as *mut _,
                0 as *mut _,
                &mut start_up as *mut _,
                &mut proc_info as *mut _
            )
        };

        if result == 0 {
            return None;
        }

        let base = get_base_address(proc_info.hProcess, Some(proc_info.hThread), proc_info.dwProcessId).unwrap();

        Some(
            ProcessMemory{
                base_address: base,
                handle: proc_info.hProcess as _,
                pid: proc_info.dwProcessId,
                thread: proc_info.hThread as _
            }
        )
    }

    pub fn write_memory(&mut self, _address: usize, data: &Vec<u8>, offset: bool) {
        let mut address: usize = _address;
        if offset {
            address = self.base_address + address;
        }

        #[cfg(target_family = "windows")] {
            memory_windows::write_memory(self.handle as _, address, &data).unwrap()
        }

        #[cfg(target_os = "macos")] {
            memory_darwin::write_memory(self.handle as _, address, &data).unwrap()
        }

        #[cfg(target_vendor = "unknown")] {
            memory_linux::write_memory(self.pid, address, &data).unwrap()
        }
    }

    pub fn read_memory(&mut self, _address: usize, size: usize, offset: bool) -> Vec<u8>  {
        let mut address: usize = _address;
        if offset {
            address = self.base_address + address;
        }

        #[cfg(target_vendor = "unknown")] {
            memory_linux::read_memory(self.pid, address, size).unwrap()
        }

        #[cfg(target_family = "windows")] {
            memory_windows::read_memory(self.handle as _, address, size).unwrap()
        }
        
        #[cfg(target_os = "macos")] {
            memory_darwin::read_memory(self.handle as _, address, size).unwrap()
        }
    }

    pub fn resume(&mut self) {
        #[cfg(target_family = "unix")]
        unsafe { kill(self.pid as _, SIGCONT);}
        #[cfg(target_family = "windows")]
        unsafe { winapi::um::processthreadsapi::ResumeThread(self.thread as _) };
    }

    pub fn base(&mut self) -> usize {
        self.base_address
    }
}

impl Drop for ProcessMemory {
    #[cfg(target_family = "windows")]
    fn drop(&mut self) {
        close_valid_handle(self.handle as _);
        close_valid_handle(self.thread as _);
    }

    #[cfg(target_os = "macos")]
    fn drop(&mut self) {
        unsafe {
            mach::mach_port::mach_port_deallocate(mach::traps::mach_task_self(), self.handle as _);
        }
    }

    #[cfg(target_vendor = "unknown")]
    fn drop(&mut self) {
        let nix_pid = nix::unistd::Pid::from_raw(self.pid as _);
        ptrace::detach(nix_pid, None).unwrap();   
    }
}
