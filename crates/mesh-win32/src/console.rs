//! Best-effort VT styling for the follow console. Failure is silent.

use std::sync::Once;

use windows_sys::Win32::System::Console::{
    ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WRAP_AT_EOL_OUTPUT,
    GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleMode, SetConsoleTitleW,
};

/// Turns on virtual-terminal sequences for this process's stdout console.
pub fn enable_stdout_virtual_terminal() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        enable_once();
        set_title();
    });
}

fn enable_once() {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle == (-1isize as _) {
            return;
        }
        let mut mode = 0_u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return;
        }
        let wanted = mode
            | ENABLE_PROCESSED_OUTPUT
            | ENABLE_WRAP_AT_EOL_OUTPUT
            | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        let _ = SetConsoleMode(handle, wanted);
    }
}

fn set_title() {
    const TITLE: [u16; 12] = [
        b'm' as u16,
        b'e' as u16,
        b's' as u16,
        b'h' as u16,
        b' ' as u16,
        b'f' as u16,
        b'o' as u16,
        b'l' as u16,
        b'l' as u16,
        b'o' as u16,
        b'w' as u16,
        0,
    ];
    unsafe {
        let _ = SetConsoleTitleW(TITLE.as_ptr());
    }
}
