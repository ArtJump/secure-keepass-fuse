module secure-keepass-fuse

go 1.24.0

toolchain go1.24.11

require (
	github.com/creack/pty v1.1.24
	github.com/hanwen/go-fuse/v2 v2.9.0
	github.com/tobischo/gokeepasslib/v3 v3.6.1
	golang.org/x/sys v0.39.0
	golang.org/x/term v0.38.0
)

require (
	github.com/tobischo/argon2 v0.1.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
)
