use std::ffi::{c_char, c_uchar, CStr, CString, OsString};
use std::io::{Error, ErrorKind, Read, stdin, stdout, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;
use std::{fs, mem, ptr, slice};
use std::mem::size_of;
use widestring::WideCString;
use winapi::shared::minwindef::{BOOL, DWORD, LPARAM, MAX_PATH};
use winapi::shared::ntdef::{NULL, UCHAR};
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{CHAR, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE};
use winapi::um::winuser::{EnumWindows, GetWindowTextLengthA, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible};
use colored::Colorize;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, LPPROCESSENTRY32, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS};

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

fn enum_processes() {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
        if !snapshot.is_null() {
            let mut proc_entry: PROCESSENTRY32 = PROCESSENTRY32 {
                dwSize: 0,
                cntUsage: 0,
                th32ProcessID: 0,
                th32DefaultHeapID: 0,
                th32ModuleID: 0,
                cntThreads: 0,
                th32ParentProcessID: 0,
                pcPriClassBase: 0,
                dwFlags: 0,
                szExeFile: [0; MAX_PATH],
            };

            proc_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
            if Process32First(snapshot, &mut proc_entry as *mut PROCESSENTRY32) != 0 {
                loop {
                    let exe_file = proc_entry.szExeFile.clone();
                    let mut exe_name = "Unkown".to_string();

                    if !exe_file.is_empty() {
                        if !exe_file.as_ptr().is_null() {
                            let exe_file = mem::transmute::<Vec<i8>, Vec<u8>>(exe_file.to_vec());
                            let length = String::from_utf8_unchecked(exe_file.clone()).find("\0").unwrap();
                            let string = String::from_utf8_unchecked(exe_file.clone()[..length].to_owned());
                            exe_name = string;
                        }
                    }
                    println!("{:?} {:?}", proc_entry.th32ProcessID, exe_name.clone());
                    let process_id = format!("{:#0X}", proc_entry.th32ProcessID);
                    println!("Process id: {} , Exe Name: {}", process_id, exe_name);
                    if Process32Next(snapshot, &mut proc_entry as *mut PROCESSENTRY32) == 0 {
                        break;
                    }
                }
            } else {
                println!("Process32First failed: {:#x}", GetLastError());
            }
        }
    }
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
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct PeHeader {
    mMagic: [c_char; 4],
    mMachine: u16,
    mNumberOfSections: u16,
    mTimeDateStamp: u32,
    mPointerToSymbolTable: u32,
    mNumberOfSymbols: u32,
    mSizeOfOptionalHeader: u16,
    mCharacteristics: u16,
}

fn manual_map(proc_id: DWORD, dll: &Path) {
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, proc_id);
        if h_process == NULL {
            println!("Program could not be found the process id was {:#0X}", proc_id);
            exit(1)
        }
        let dll_path = dll;
        let full_path = dll_path.canonicalize().expect("Error");
        let dll_size = full_path.metadata().unwrap().len();

        // struct PeHeader {
        //     uint32_t mMagic; // PE\0\0 or 0x00004550
        //     uint16_t mMachine;
        //     uint16_t mNumberOfSections;
        //     uint32_t mTimeDateStamp;
        //     uint32_t mPointerToSymbolTable;
        //     uint32_t mNumberOfSymbols;
        //     uint16_t mSizeOfOptionalHeader;
        //     uint16_t mCharacteristics;
        // };

        // println!("{}", dll_size);

        // let path_len = (full_path.len() * 2) + 1;

        let mut pe = PeHeader{
            mMagic: [0; 4],
            mMachine: 0,
            mNumberOfSections: 0,
            mTimeDateStamp: 0,
            mPointerToSymbolTable: 0,
            mNumberOfSymbols: 0,
            mSizeOfOptionalHeader: 0,
            mCharacteristics: 0,
        };

        let mut allocate_memory = VirtualAllocEx(h_process, ptr::null_mut(), dll_size as usize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if allocate_memory == NULL {
            println!("Hooking the memory didn't work");
            exit(1)
        }

        let mut byte_content1 = fs::read(full_path).unwrap();
        let mut byte_content =byte_content1.as_slice();
        println!("{:?}", byte_content);

        let peheader_size = mem::size_of::<PeHeader>();

        let mut config_slice = slice::from_raw_parts_mut(&mut pe as *mut _ as *mut u8, peheader_size);
        byte_content.read_exact(&mut config_slice).expect("TODO: panic message");

        println!("{:?}", CStr::from_ptr(pe.mMagic.as_ptr()));


        if WriteProcessMemory(h_process,
                              allocate_memory,
                              byte_content.as_ptr() as *mut _,
                              dll_size as usize,
                              ptr::null_mut()) == 0 {
            let error = GetLastError();
            println!("{:?}", error);
            println!("Writing Memory went wrong");
            exit(1)
        }
    }
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
    // inject_into_process(proc_id, dll_path)
    manual_map(proc_id, dll_path)
}
