use std::ffi::{CString, OsString};
use std::io::{Error, ErrorKind, stdin, stdout, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;
use std::{mem, ptr};
use widestring::WideCString;
use winapi::shared::minwindef::{BOOL, DWORD, LPARAM, MAX_PATH};
use winapi::shared::ntdef::NULL;
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE};
use winapi::um::winuser::{EnumWindows, GetWindowTextLengthA, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible};
use colored::Colorize;
use serde::Serialize;

fn logo() {
    println!("{}", "

 █████   █████                █████
░░███   ░░███                ░░███
 ░███    ░███  █████ ████  ███████  ████████  █████ ████  █████
 ░███████████ ░░███ ░███  ███░░███ ░░███░░███░░███ ░███  ███░░
 ░███░░░░░███  ░███ ░███ ░███ ░███  ░███ ░░░  ░███ ░███ ░░█████
 ░███    ░███  ░███ ░███ ░███ ░███  ░███      ░███ ░███  ░░░░███
 █████   █████ ░░███████ ░░████████ █████     ░░████████ ██████
░░░░░   ░░░░░   ░░░░░███  ░░░░░░░░ ░░░░░       ░░░░░░░░ ░░░░░░
                ███ ░███
               ░░██████
                ░░░░░░

".green())
}

extern "system" fn enum_windows_proc(hwnd: HWND, _: LPARAM) -> BOOL {
    unsafe {
        if IsWindowVisible(hwnd) == 0 { return 1; }
        let window_text_length = GetWindowTextLengthA(hwnd);
        if window_text_length <= 0 { return 1; }

        //create buffer for the window title (max size of window title is 256 bit)
        let mut buffer = [0; 256];

        GetWindowTextW(hwnd, buffer.as_mut_ptr(), window_text_length + 1);
        let window_title = OsString::from_wide(&buffer[..window_text_length as usize]);

        //create buffer for process id as u32
        let mut buf: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut buf);
        //format u32 to hex
        let process_id = format!("{:#0X}", buf);

        println!("Process id: {} , Window Text: {}", process_id, window_title.to_string_lossy());
        return 1;
    }
}

fn print_current_windows_with_process_id() {
    unsafe {
        EnumWindows(Some(enum_windows_proc), 0);
    }
}

fn convert_hex_to_dword(input: &str) -> DWORD {
    let process_id = input;
    let remove_prefix = process_id.trim_start_matches("0x");
    let proc_id = match u32::from_str_radix(remove_prefix, 16) {
        Ok(proc_id) => proc_id,
        Err(error) => {
            println!("Could not parse the hex number {:?}", error);
            exit(1)
        }
    };
    proc_id
}

fn inject_into_process(proc_id: DWORD, dll: &Path) {
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, proc_id);
        if h_process == NULL {
            println!("Program could not be found the process id was {:#0X}", proc_id);
            exit(1)
        }
        let dll_path = dll;
        let full_path = dll_path.canonicalize().expect("Error");
        let full_path = full_path.as_os_str();
        let full_path = WideCString::from_str(full_path.to_string_lossy())
            .map_err(|e| Error::new(ErrorKind::InvalidInput,
                                    format!("invalid dll path: {:?}", e))).expect("Error");

        let path_len = (full_path.len() * 2) + 1;

        let mut allocate_memory = VirtualAllocEx(h_process, ptr::null_mut(), MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if allocate_memory == NULL {
            println!("Hooking the memory didn't work");
            exit(1)
        }

        if WriteProcessMemory(h_process,
                              allocate_memory,
                              full_path.as_ptr() as *mut _,
                              path_len,
                              ptr::null_mut()) == 0 {
            let error = GetLastError();
            println!("{:?}", error);
            println!("Writing Memory went wrong");
            exit(1)
        }
        let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
        let loadlibraryw = CString::new("LoadLibraryW").expect("CString::new failed");

        let h_kernel32 = GetModuleHandleA(kernel32.as_ptr());
        if h_kernel32.is_null() {
            println!("Failed to get the handle of kernel32.dll.");
            exit(1);
        }
        let h_loadlibraryw =
            GetProcAddress(h_kernel32, loadlibraryw.as_ptr());
        if h_loadlibraryw.is_null() {
            println!("Failed to get the address of LoadLibraryW.");
            exit(1)
        }
         let hthread = CreateRemoteThread(h_process, ptr::null_mut(), 0, Some(mem::transmute(h_loadlibraryw)), allocate_memory, 0, ptr::null_mut());

        CloseHandle(hthread);
        println!("Injected successfully")
    }
}

fn main() {
    logo();
    print_current_windows_with_process_id();

    print!("Please enter the process id: ");
    stdout().flush().expect("Failed to flush stdout");
    let mut process_id = String::new();
    stdin().read_line(&mut process_id).expect("Failed to read line");
    println!("The process you selected is {}", process_id);
    print!("Please enter the dll path: ");
    stdout().flush().expect("Failed to flush stdout");
    let mut dll_path = String::new();
    stdin().read_line(&mut dll_path).expect("Failed to read line");
    println!("The dll path you selected is {}", dll_path);
    let dll_path = dll_path.trim();
    let dll_path = Path::new(dll_path);
    let proc_id = convert_hex_to_dword(process_id.trim());
    inject_into_process(proc_id, dll_path)
}
