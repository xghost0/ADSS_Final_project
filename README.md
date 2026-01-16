# PAM Spy PoC

This tool demonstrates how to use eBPF (Extended Berkeley Packet Filter) and BCC (BPF Compiler Collection) to inspect user-space function calls in shared libraries. specifically, it hooks the `pam_get_authtok` function in `libpam.so` to capture authentication tokens (passwords).

> **Disclaimer**: This tool is for **educational and research purposes only**. It detects passwords in memory. Do not use this on systems you do not own or have explicit permission to test.

## Prerequisites

-   **Linux Kernel**: A modern kernel with eBPF support (check with `uname -r`).
-   **Root Privileges**: eBPF programs require root/sudo access to load into the kernel.
-   **BCC Tools**: You need the BCC framework installed.

### Installing BCC

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) bpfcc-lua
# Python bindings
sudo apt-get install python3-bpfcc
```

**Fedora:**
```bash
sudo dnf install bcc-tools python3-bcc
```

## Usage

1.  **Run the script as root**:
    ```bash
    sudo python3 pam_spy.py
    ```

    **Options:**
    - `--lib <path>`: Manually specify the path to `libpam.so.0` if auto-detection fails.
    - `--pid <pid>`: Filter output to a specific PID (optional, user-space filtering).

2.  **Trigger an Authentication Event**:
    Open a *new terminal window* and perform an action that requires PAM authentication. For example:
    -   `su -` (and type the password)
    -   `sudo ls` (if sudo is configured to ask for a password)
    -   Any other PAM-enabled application.

3.  **View Output**:
    The script captures the return value of `pam_get_authtok` and prints it to the console.

## Troubleshooting

### "Failed to attach uprobe: could not determine address of symbol"

This means BCC cannot find the `pam_get_authtok` function in the library file.

1.  **Check Library Path**: Ensure the script is finding the correct library.
    ```bash
    sudo python3 pam_spy.py --lib /usr/lib64/libpam.so.0
    ```
    (Use `find / -name libpam.so.0` to locate it on your system).

2.  **Check Symbols**: Verify the symbol exists in the library.
    ```bash
    nm -D /path/to/libpam.so.0 | grep pam_get_authtok
    ```
    If this produces no output, your library might be stripped. You may need to install debug symbols (e.g., `libpam-modules-dbgsym` on Debian/Ubuntu) or use a different environment for this lab.

## How It Works

1.  **Uprobe (Function Entry)**: A hook is placed at the start of `pam_get_authtok`. It saves the address of the pointer where the password will be written. This address is stored in a BPF Hash Map, keyed by the process ID.
2.  **Uretprobe (Function Return)**: A hook is placed at the return of `pam_get_authtok`. It retrieves the saved pointer address from the map.
3.  **Memory Reading**: It dereferences the pointer to find the string's location in memory, then reads the string using `bpf_probe_read_user_str`.
4.  **Output**: The captured string is sent to the kernel trace pipe.

## Files
-   `pam_spy.py`: The Python script containing the inline C eBPF code and the user-space loader.
