# eBPF Spy Tool (PAM + SSL)

This tool demonstrates how to use eBPF (Extended Berkeley Packet Filter) and BCC (BPF Compiler Collection) to inspect user-space function calls in shared libraries. It can intercept:
1.  **PAM Authentication**: Passwords for `sudo`, `su`, etc.
2.  **SSL/TLS Traffic**: Plaintext data before encryption or after decryption (`HTTPS`, `wget`, `curl`).
3.  **Targeting SSH**
    **Scenario 1: You are the Server (e.g., Victim connects to you)**
    -   **Solution**: Use `ebpf_spy.py --mode pam`.
    -   **Why**: SSH uses PAM for authentication. The script will capture the password as soon as the victim logs in.

    **Scenario 2: You are the Client (e.g., You connect to a server)**
    You want to capture the password you type into the `ssh` command.
    -   **Problem**: The standard `ssh` binary is **stripped** (has no function names), so we cannot simply hook functions like `read_passphrase`.
    -   **Strategy A (The "Clean" Way)**:
        1.  Install debug symbols: `sudo apt install openssh-client-dbgsym`.
        2.  Now you can hook `read_passphrase` in `/usr/bin/ssh` just like we hooked `pam_get_authtok`.
    -   **Strategy B (The "Hacker" Way - No Symbols)**:
        1.  Instead of hooking `ssh`, hook the standard `libc` library.
        2.  Attach a probe to `read()`.
        3.  Logic: "If the process name is `ssh` AND it is reading from file descriptor 0 (STDIN), log the data."
        4.  This works on *any* stripped binary because they all use `libc` to read keyboard input.

> **Disclaimer**: This tool is for **educational and research purposes only**. It detects passwords in memory. Do not use this on systems you do not own or have explicit permission to test.

## Prerequisites

-   **Linux Kernel**: A modern kernel with eBPF support.
-   **Root Privileges**: Required to load BPF programs.
-   **BCC Tools**:
    ```bash
    # Ubuntu/Debian
    sudo apt-get install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
    ```

## Usage

**Run the script as root**:

```bash
sudo python3 ebpf_spy.py [OPTIONS]
```

### Options

-   `--mode {pam,ssl,all}`: Select what to intercept. Default is `all`.
-   `--pid <PID>`: Filter output to a specific Process ID.
-   `--libpam <path>`: Manually specify path to `libpam.so`.
-   `--libssl <path>`: Manually specify path to `libssl.so`.

### Examples

**1. Intercept Everything (PAM + SSL)**
```bash
sudo python3 ebpf_spy.py
```

**2. Intercept Only HTTPS/SSL Traffic**
```bash
sudo python3 ebpf_spy.py --mode ssl
```
*Test by running `curl https://google.com` in another window.*

**3. Intercept Only Authentication**
```bash
sudo python3 ebpf_spy.py --mode pam
```
*Test by running `su -` in another window.*

## Troubleshooting

### "Failed to attach ... could not determine address of symbol"
This implies the library path is wrong or the library is stripped.
1.  **Find the library**: `find / -name libssl.so*` or `find / -name libpam.so*`.
2.  **Specify manually**: `sudo python3 ebpf_spy.py --libssl /usr/lib/x86_64-linux-gnu/libssl.so.3`

## How It Works

### PAM Spy
-   **Hook**: `pam_get_authtok` (Entry & Return).
-   **Logic**: Captures the pointer address on entry, reads the password string from that pointer on return.

### SSL Spy
-   **SSL_write**: Hooked on **Entry**. The buffer contains plaintext data *before* it is encrypted and sent to the network.
-   **SSL_read**: Hooked on **Return**. The buffer contains plaintext data just *after* it was decrypted from the network.

## Files
-   `ebpf_spy.py`: The main tool.
