package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Global config flags
var verbose bool

// --- Structures ---

// SecuredFile represents the content and rules for a specific extracted file.
type SecuredFile struct {
	Name        string
	Content     []byte
	AllowedBins map[string]struct{}
}

// DirEntry represents a directory in the in-memory tree using a recursive structure.
type DirEntry struct {
	Name  string
	Files map[string]*SecuredFile
	Dirs  map[string]*DirEntry
}

// NewDirEntry creates a new directory entry structure
func NewDirEntry(name string) *DirEntry {
	return &DirEntry{
		Name:  name,
		Files: make(map[string]*SecuredFile),
		Dirs:  make(map[string]*DirEntry),
	}
}

// --- Logic ---

// wipeBytes zeroes out the byte slice
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sanitizeName replaces file system path separators with underscores
func sanitizeName(name string) string {
	return strings.ReplaceAll(name, "/", "_")
}

// loadDB loads the KDBX file using gokeepasslib and builds the in-memory definition tree.
func loadDB(dbPath, keyFile string, pwd []byte) (*DirEntry, error) {
	log.Println("[INFO] Opening database...")

	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db file: %w", err)
	}
	defer file.Close()

	// 1. Create Credentials based on whether a keyfile is provided
	var creds *gokeepasslib.DBCredentials
	pwdStr := string(pwd) // Library requires string. Note: Creates a copy in memory.

	if keyFile != "" {
		// Using NewPasswordAndKeyCredentials if keyfile exists
		creds, err = gokeepasslib.NewPasswordAndKeyCredentials(pwdStr, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials with keyfile: %w", err)
		}
	} else {
		// Using NewPasswordCredentials if only password provided
		creds = gokeepasslib.NewPasswordCredentials(pwdStr)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = creds

	// 2. Decode the database
	if err := gokeepasslib.NewDecoder(file).Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode kdbx: %w", err)
	}

	// 3. Unlock protected entries (Password, protected notes, etc.)
	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock entries: %w", err)
	}

	log.Println("[INFO] Database decrypted. Building file tree...")

	// Root of our file system tree
	rootEntry := NewDirEntry("root")

	// Recursive processing
	var processGroup func(g gokeepasslib.Group, parentDir *DirEntry)
	processGroup = func(g gokeepasslib.Group, parentDir *DirEntry) {
		groupName := sanitizeName(g.Name)
		if groupName == "" {
			groupName = "_unnamed_group_"
		}

		// Ensure subdirectory exists in the parent
		currentDir, exists := parentDir.Dirs[groupName]
		if !exists {
			currentDir = NewDirEntry(groupName)
			parentDir.Dirs[groupName] = currentDir
		}

		// Process Entries in this group
		for _, entry := range g.Entries {
			title := entry.GetTitle()
			notes := entry.GetContent("Notes")

			// KDBX entry only stores references to binaries. Check if any exist.
			if len(entry.Binaries) == 0 || notes == "" || title == "" {
				continue
			}

			rules := parseRules(notes)
			if len(rules) == 0 {
				continue
			}

			// Iterate over Binary References in the Entry
			for _, binRef := range entry.Binaries {
				fName := strings.TrimSpace(binRef.Name)
				safeFName := sanitizeName(fName)

				allowedBins, ok := rules[fName]
				if !ok {
					continue
				}

				// Find the actual binary content using the ID from the reference
				// db.FindBinary looks up in the InnerHeader (KDBX4) or Meta (KDBX3)
				binaryData := db.FindBinary(binRef.Value.ID)
				if binaryData == nil {
					log.Printf("   [WARN] Binary '%s' referenced in entry '%s' not found in DB store.", fName, title)
					continue
				}

				content, err := binaryData.GetContentBytes()
				if err != nil {
					log.Printf("   [ERR] Failed to get content bytes for '%s': %v", fName, err)
					continue
				}

				if len(content) == 0 {
					log.Printf("   [WARN] File '%s' in entry '%s' is empty.", fName, title)
				}

				log.Printf("[EXTRACT] Extracting '%s' from entry '%s' -> '%s' (%d bytes)", fName, title, groupName, len(content))

				currentDir.Files[safeFName] = &SecuredFile{
					Name:        safeFName,
					Content:     content,
					AllowedBins: allowedBins,
				}
			}
		}

		// Recurse into subgroups
		for _, sub := range g.Groups {
			processGroup(sub, currentDir)
		}
	}

	// Iterate over root groups
	for _, g := range db.Content.Root.Groups {
		processGroup(g, rootEntry)
	}

	return rootEntry, nil
}

func parseRules(notes string) map[string]map[string]struct{} {
	res := make(map[string]map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(notes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		fName := strings.TrimSpace(parts[0])
		rawPath := strings.TrimSpace(parts[1])

		// Fix: Always convert to Absolute path
		absPath, err := filepath.Abs(rawPath)
		if err != nil {
			log.Printf("[WARN] Could not determine absolute path for '%s': %v", rawPath, err)
			continue
		}

		absPath = filepath.Clean(absPath)

		if _, ok := res[fName]; !ok {
			res[fName] = make(map[string]struct{})
		}

		// 1. Add literal absolute path
		res[fName][absPath] = struct{}{}

		// 2. Resolve symlinks
		resolved, err := filepath.EvalSymlinks(absPath)
		if err == nil && resolved != absPath {
			res[fName][resolved] = struct{}{}
		}
	}
	return res
}

// --- FUSE Operations ---

// SecureDirNode represents a folder in the FUSE filesystem.
type SecureDirNode struct {
	fs.Inode
	Entry *DirEntry
}

var _ fs.NodeOnAdder = (*SecureDirNode)(nil)

func (n *SecureDirNode) OnAdd(ctx context.Context) {
	// Add subdirectories
	for name, dirEntry := range n.Entry.Dirs {
		childNode := &SecureDirNode{Entry: dirEntry}
		childInode := n.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: fuse.S_IFDIR})
		n.AddChild(name, childInode, true)
	}

	// Add files in this directory
	for name, fileData := range n.Entry.Files {
		childNode := &SecureFileNode{Data: fileData}
		childInode := n.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: fuse.S_IFREG})
		n.AddChild(name, childInode, true)
	}
}

// SecureFileNode represents a file in the FUSE filesystem.
type SecureFileNode struct {
	fs.Inode
	Data *SecuredFile
}

var _ fs.NodeOpener = (*SecureFileNode)(nil)
var _ fs.NodeReader = (*SecureFileNode)(nil)
var _ fs.NodeGetattrer = (*SecureFileNode)(nil)

func (n *SecureFileNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Size = uint64(len(n.Data.Content))
	out.Mode = 0400 // Read-only for owner
	out.Owner.Uid = uint32(os.Getuid())
	out.Owner.Gid = uint32(os.Getgid())
	return 0
}

func (n *SecureFileNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil, 0, syscall.EACCES
	}

	pid := caller.Pid
	procPath := fmt.Sprintf("/proc/%d/exe", pid)

	// Identify who is calling
	realPath, err := os.Readlink(procPath)
	if err != nil {
		log.Printf("[DENY] Error reading executable path for PID %d: %v", pid, err)
		return nil, 0, syscall.EACCES
	}

	realPath = strings.TrimSuffix(realPath, " (deleted)")
	_, allowed := n.Data.AllowedBins[realPath]

	if !allowed {
		log.Printf("[DENY] Process '%s' (PID %d) denied access to '%s'", realPath, pid, n.Data.Name)
		return nil, 0, syscall.EACCES
	}

	if verbose {
		log.Printf("[ALLOW] Process '%s' granted access to '%s'", realPath, n.Data.Name)
	}

	return nil, 0, 0
}

func (n *SecureFileNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := int(off) + len(dest)
	if end > len(n.Data.Content) {
		end = len(n.Data.Content)
	}
	if int(off) < len(n.Data.Content) {
		copy(dest, n.Data.Content[off:end])
		return fuse.ReadResultData(dest[:end-int(off)]), 0
	}
	return fuse.ReadResultData(nil), 0
}

func main() {
	keyFilePtr := flag.String("keyfile", "", "Path to keyfile")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging for allowed access")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: secure-mount [options] <db.kdbx> <mountpoint>")
		flag.PrintDefaults()
		os.Exit(1)
	}
	dbPath := args[0]
	mountPoint := args[1]

	// Lock memory to prevent swapping secrets to disk
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("[WARN] Failed to lock memory (mlockall): %v. Secrets might swap to disk.", err)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	userCancelCh := make(chan struct{})
	go func() {
		<-sigCh
		log.Println("Interrupt received, shutting down...")
		close(userCancelCh)
	}()

	fmt.Print("KeePass Password: ")
	bPwd, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	// Check if cancelled before heavy lifting
	select {
	case <-userCancelCh:
		wipeBytes(bPwd)
		os.Exit(0)
	default:
	}

	rootEntry, err := loadDB(dbPath, *keyFilePtr, bPwd)

	// Best-effort wiping of password from memory slice
	wipeBytes(bPwd)
	runtime.GC()

	if err != nil {
		log.Fatalf("Fatal error loading DB: %v", err)
	}

	// Basic check: verify if any files were loaded recursively
	hasFiles := false
	var checkRec func(*DirEntry)
	checkRec = func(d *DirEntry) {
		if len(d.Files) > 0 {
			hasFiles = true
			return
		}
		for _, sub := range d.Dirs {
			checkRec(sub)
			if hasFiles {
				return
			}
		}
	}
	checkRec(rootEntry)

	if !hasFiles {
		log.Println("[WARN] No files loaded. Check entry 'Notes' format and attachment existence.")
	}

	if _, err := os.Stat(mountPoint); os.IsNotExist(err) {
		os.MkdirAll(mountPoint, 0700)
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:         "SecureFS",
			Name:           "kpx",
			SingleThreaded: true, // Simpler for read-only memory file systems
			Options:        []string{"ro", "noexec", "nosuid", "nodev"},
		},
	}

	// Check cancellation again before mount
	select {
	case <-userCancelCh:
		os.Exit(0)
	default:
	}

	server, err := fs.Mount(mountPoint, &SecureDirNode{Entry: rootEntry}, opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Mounted at %s. Press Ctrl+C to unmount.", mountPoint)

	// Listen for unmount signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Unmounting...")
		server.Unmount()
	}()

	server.Wait()
}
