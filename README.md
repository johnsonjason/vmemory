# vmemory

Rust library for reading/writing memory in other processes for Windows, macOS, Linux, and in the future potentially, BSD variants.

## Rationale

After having to write software working with memory reading/writing in processes on multiple operating systems, I found that there are some inconveniences for my purpose. While other cross-platform process memory reading/writing libraries exist for Rust, they did not all fit my purpose or solve the underlying issues I had with the platform-specific APIs. For example, ptrace(2) on Linux only accepts word-sized reads/writes, if a processor word is 8 bytes, only 8 bytes can be read from the process at a time. You could not for example, read 123 bytes.

Another example is that macOS removes important functionality from ptrace(2) even though it is inherited from the BSD implementation, it removes a lot of functionality such as reading/writing memory via ptrace(2). So instead, code must opt to use mach's vm_write, vm_read_overwrite, and vm_region functions which are entirely undocumented by Apple and as such, may be subject to change.

Examples:
https://developer.apple.com/documentation/kernel/1585462-vm_write
https://developer.apple.com/documentation/kernel/1585371-vm_read_overwrite
https://developer.apple.com/documentation/kernel/1585377-vm_region

The actual ptrace(2) implementation by Apple which does not implement PT_WRITE/PT_READ functionality: https://opensource.apple.com/source/xnu/xnu-344.21.74/bsd/kern/mach_process.c.auto.html

Then there were of course inconsistencies, while many UNIX-based systems implement a form of procfs (BSD variants, Solaris, AIX) as well as Linux, macOS does not and instead memory mapping information is retrieved via mach vm_region-related functions, or via the vmmap software.

With other Rust libraries I used, there were specific things that just were not solved, for example, the issue of granularity with ptrace(2) is the same if they use it as an underlying call. If they use process_vm_writev, then there's no guarantee that page protections such as writing to read-only memory will allow this call to succeed, though this does not seem explicitly documented, there are no indications of the page protection changing to allow this write. Also, https://reviews.llvm.org/D10488.

So this API allows for arbitrary reading/writing memory to other processes regardless of the page protections present, allows for processes to be spawned in a suspended state, and attempts to allow for much more granular reads/writes. In addition, it is easy to retrieve the base address of the first mapping/module for the process.

## API

```Rust
ProcessMemory::new_process(file_path: &str, arguments: &Vec<String>) -> Option<ProcessMemory>
```

Spawn a new process in a suspended state to be manually resumed via self.resume(), passing the file path of the process to start
and the arguments to spawn the process with. Returns an option consisting of the struct to be unwrapped

```Rust
ProcessMemory::attach_process(pid: u32) -> Option<ProcessMemory>
```

Attach to a process with the process ID (PID). Returning a structure in an option to be unwrapped, which will allow
memory read/write operations

```Rust
ProcessMemory::write_memory(_address: usize, data: &Vec<u8>, offset: bool)
```

Write memory to the process. The memory to be written is the memory in the `data` parameter, at the location of `_address` in the remote process. The `offset` boolean will specify whether the value of `_address` is an offset relative to the first module/mapping loaded into the process (true), or if it is a direct address value to be written (false)

Example, the first module is loaded at **0x00400000**

`offset` is set to true, and `_address` = **5**

Memory would be written at **0x00400005**

```Rust
ProcessMemory::read_memory(_address: usize, size: usize, offset: bool) -> Vec<u8>
```

Read memory from the process at the location of `_address`, and read n bytes according to `size`. The rules off the `offset` parameter are the same as specified in
`ProcessMemory::write_memory()`

```Rust
ProcessMemory::resume()
```

Resume the process from a suspended state (SIGCONT on Linux/macOS. ResumeThread on the first thread from CreateProcess on Windows). This should generally only be used for ptrace(2) sessions on Linux, posix_spawn(2) from a suspended state on macOS, or CreateProcess on Windows. Essentially all `ProcessMemory::new_process()` calls will require this function to be called

```Rust
ProcessMemory::base()
```

Retrieve the base address for the first mapping/module loaded into the process

## Examples

### Example 1

Using `new_process`

```Rust
use vmemory::*;

fn main() {
    //
    // Spawn a new process in a suspended state with no arguments
    //
    let test = ProcessMemory::new_process(r"C:\TEST.EXE", &vec!["".to_string()]).unwrap();

    //
    // Write memory to the process at (base address + 0xA)
    // Writing 4 bytes at this location, each byte = 9
    //
    test.write_memory(0xA, &vec![9, 9, 9, 9], true);

    //
    // Read memory to confirm the write was registered to the process, as well as a few additional bytes that
    // were not written
    //
    let vmem = test.read_memory(0xA, 10, true);

    for v in vmem {
        print!("{:02X} ", v);
    }

    //
    // Get the base address of the first module in the process, and print it out
    //
    println!("\nbase: {:08X}", test.base());

    //
    // Resume the process
    //
    test.resume();
}
```
### Example 2

Here we use `attach_process` instead of `new_process`.

Take note of the `offset` boolean (third argument to `write_memory` and `read_memory`) in this example. Here the direct address passed to `write_memory` and the offset passed to `read_memory` refer to the same location in the process's memory.

```Rust
use vmemory::*;

fn main() {

    //
    // Attach to a process with a process ID (PID) of 3145
    // Immediately resume from the ptrace attachment
    //
    let mut test = ProcessMemory::attach_process(3145).unwrap();
    test.resume();

    //
    // Write 5 bytes at the direct address (no offset) 0x5616B07DB000
    //
    let write_test: Vec<u8> = vec![7, 7, 9, 9, 9];
    test.write_memory(0x5616B07DB000, &write_test, false);

    //
    // Read 5 bytes from the offset (0) relative to the base address of the first mapping/module in the process
    //
    let vmem = test.read_memory(0, 5, true);

    for v in &vmem {
        print!("{:02X} ", v);
    }

    //
    // Print out the base address of the process
    //
    println!("\nbase: {:08X}", test.base());
}
```
