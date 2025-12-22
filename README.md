# secure-keepass-fuse

**Disclaimer**: I am not a security engineer, I just want to protect sensitive keys (like age-encryption or kubeconfig) from script kiddies.

secure-keepass-fuse - **mounts attachments as fuse-filesystem**. These attachments can **only be read by specific processes** specified in the notes for the entry. Keepassxc-cli is used to read kdbx. I only wrote the tests, most of main.go was written using Google Gemini 3.0 pro.

Warnings:
- Allow access only to compiled binaries (Go, Rust, C++), not interpreters, unless you are willing to accept the risk of access by any script.

## How it work

TODO

## Install

```
curl -L -O https://github.com/Split174/secure-keepass-fuse/releases/download/v1.0.0/myapp-linux-amd64
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