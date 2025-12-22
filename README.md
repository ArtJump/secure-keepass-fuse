# secure-keepass-fuse

**Disclaimer**: I am not a security engineer, I just want to protect sensitive keys (like age-encryption or kubeconfig) from script kiddies.

secure-keepass-fuse - **mounts attachments as fuse-filesystem**. These attachments can **only be read by specific processes** specified in the notes for the entry. I only wrote the tests, most of main.go was written using Google Gemini 3.0 pro.

Warnings:
- Allow access only to compiled binaries (Go, Rust, C++), not interpreters, unless you are willing to accept the risk of access by any script.

## How it work

1. The utility scans database records. If the entry has an attachment, it **checks the Notes field** for access rules in the format filename: /path/to/binary.
2. A file system is created at the specified mount point that is read-only (ro) and only accessible to the current user (0400). The folder structure corresponds to the groups in KeePass.
3. Whenever you try to open a file (syscall open), the driver: 
    1. Determines the PID of the process that is trying to read the file. 
    2. Through /proc/<PID>/exe it gets the absolute path to the executable file of this process. 
    3. Checks the **received path against the list of allowed applications** for this file (from step 2).
4. Result: 
If the program is on the white list, the content of the file is given. 
If the program is not in the list, the error EACCES (Permission Denied) is returned.

## Install

```
curl -L -O https://github.com/Split174/secure-keepass-fuse/releases/download/v0.0.1/secure-keepass-fuse-amd64
chmod +x secure-keepass-fuse-amd64
```

## Usage

1. All entries with an attachment must contain text in the note in the following format:
filename.txt: /path/to/process

For example:
```
age.txt: /usr/bin/cat
age.txt: /usr/bin/sops
```

2. After preparing all entries, you can run the binary
```
secure-keepass-fuse --verbose ./path/to/kdbx ./mount/path
```