// use std::os::windows::ffi::OsStringExt;
// use std::process::exit;
// use winapi::shared::minwindef::{BOOL, DWORD, LPARAM, MAX_PATH, PDWORD};
// use winapi::shared::ntdef::NULL;
// use winapi::shared::windef::HWND;
// use winapi::um::errhandlingapi::GetLastError;
// use winapi::um::winbase::{FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageA, FormatMessageW, QueryFullProcessImageNameA, QueryFullProcessImageNameW};
// use winapi::um::libloaderapi::GetModuleHandleA;
// use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
// use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
// use winapi::um::winnt::{HANDLE, LANG_NEUTRAL, LPSTR, MAKELANGID, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE, SUBLANG_DEFAULT};
// use winapi::um::winuser::{EnumWindows, GetWindowTextLengthA, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible};
// use std::io;
// use std::ptr;
// use std::mem;
// use std::io::{Error, stdin, stdout, Write};
// use std::io::ErrorKind;
// use std::path::Path;
// use std::ffi::{CString, OsString};
// use winapi::um::memoryapi as wmem;
// use winapi::um::processthreadsapi as wproc;
// use winapi::um::handleapi as whandle;
// use winapi::um::libloaderapi as wload;
// use log::debug;
// use widestring::WideCString;
//
// extern "system" fn enum_windows_proc(hwnd: HWND, _: LPARAM) -> BOOL {
//     unsafe {
//         if IsWindowVisible(hwnd) == 0 { return 1; }
//         let window_text_length = GetWindowTextLengthA(hwnd);
//         if window_text_length <= 0 { return 1; }
//
//         //create buffer for the window title (max size of window title is 256 bit)
//         let mut buf = [0; 256];
//
//         GetWindowTextW(hwnd, buf.as_mut_ptr(), window_text_length + 1);
//         let window_title = OsString::from_wide(&buf[..window_text_length as usize]);
//
//         //create buffer for process id as u32
//         let mut buf: DWORD = 0;
//         GetWindowThreadProcessId(hwnd, &mut buf);
//         //format u32 to hex
//         let process_id = format!("{:#0X}", buf);
//
//         println!("Process id: {} , Window Text: {}", process_id, window_title.to_string_lossy());
//         return 1;
//     }
// }
//
// fn print_current_windows_with_process_id() {
//     unsafe {
//         EnumWindows(Some(enum_windows_proc), 0);
//     }
// }
//
// fn convert_hex_to_dword(input: &str) -> DWORD {
//     let process_id = input;
//     let remove_prefix = process_id.trim_start_matches("0x");
//     let proc_id = match u32::from_str_radix(remove_prefix, 16) {
//         Ok(proc_id) => proc_id,
//         Err(error) => {
//             println!("Could not parse the hex number {:?}", error);
//             exit(1)
//         }
//     };
//     proc_id
// }
//
// macro_rules! werr {
//     ($cond:expr) => {
//         if $cond {
//             let e = io::Error::last_os_error();
//             log::error!("windows error: {:?}", e);
//             return Err(e);
//         }
//     };
// }
//
// pub fn inject(proc: HANDLE, dll: &Path) -> io::Result<()> {
//     let full_path = dll.canonicalize()?;
//     let full_path = full_path.as_os_str();
//     let full_path = WideCString::from_str(full_path.to_string_lossy())
//         .map_err(|e| Error::new(ErrorKind::InvalidInput,
//                                 format!("invalid dll path: {:?}", e)))?;
//
//     let path_len = (full_path.len() * 2) + 1;
//     // allocate space for the path inside target proc
//     let dll_addr = unsafe {
//         wmem::VirtualAllocEx(proc,
//                              ptr::null_mut(),
//                              path_len,
//                              MEM_RESERVE | MEM_COMMIT,
//                              PAGE_EXECUTE_READWRITE)
//     };
//
//     werr!(dll_addr.is_null());
//     debug!("allocated remote memory @ {:?}", dll_addr);
//
//     let res = unsafe {
//         // write dll inside target process
//         wmem::WriteProcessMemory(proc,
//                                  dll_addr,
//                                  full_path.as_ptr() as *mut _,
//                                  path_len,
//                                  ptr::null_mut())
//     };
//
//     werr!(res == 0);
//
//     let krnl = CString::new("kernel32.dll").unwrap();
//     let krnl = unsafe { wload::GetModuleHandleA(krnl.as_ptr()) };
//     let loadlib = CString::new("LoadLibraryW").unwrap();
//     let loadlib = unsafe { wload::GetProcAddress(krnl, loadlib.as_ptr()) };
//     debug!("found LoadLibraryW for injection @ {:?}", loadlib);
//
//     let hthread = unsafe {
//         wproc::CreateRemoteThread(proc, ptr::null_mut(), 0,
//                                   Some(mem::transmute(loadlib)),
//                                   dll_addr, 0, ptr::null_mut())
//     };
//
//     werr!(hthread.is_null());
//     debug!("spawned remote thread @ {:?}", hthread);
//     unsafe { whandle::CloseHandle(hthread); }
//
//     Ok(())
// }
//
// fn main() {
//     unsafe {
//         // let proc_id =
//         print_current_windows_with_process_id();
// //
//         print!("Please enter the process id: ");
//         stdout().flush().expect("Failed to flush stdout");
//         let mut process_id = String::new();
//         stdin().read_line(&mut process_id).expect("Failed to read line");
//         println!("The process you selected is {}", process_id);
//         let proc_id = convert_hex_to_dword(process_id.trim());
//         let h_process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, proc_id);
//         if h_process == NULL {
//             println!("Program could not be found the process id was {:#0X}", proc_id);
//             exit(1)
//         }
//         inject(h_process, Path::new("C:\\Users\\tlo\\RustroverProjects\\InjectorTry\\src\\testdll.dll")).expect("TODO: panic message");
//     }
// }