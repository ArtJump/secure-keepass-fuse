package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
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

// --- XML Parsing ---

type KpxRoot struct {
	XMLName xml.Name  `xml:"KeePassFile"`
	Root    KpxGroups `xml:"Root"`
}

type KpxGroups struct {
	Group KpxGroup `xml:"Group"`
}

type KpxGroup struct {
	Name    string     `xml:"Name"`
	Entries []KpxEntry `xml:"Entry"`
	Groups  []KpxGroup `xml:"Group"`
}

type KpxEntry struct {
	UUID     string           `xml:"UUID"`
	Strings  []KpxString      `xml:"String"`
	Binaries []KpxEntryBinary `xml:"Binary"`
}

type KpxString struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type KpxEntryBinary struct {
	Key string `xml:"Key"` // Filename
}

// --- Logic ---

// wipeBytes zeroes out the byte slice
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sanitizeName replaces file system path separators with underscores
// to prevent path traversal issues or invalid directory structures.
func sanitizeName(name string) string {
	return strings.ReplaceAll(name, "/", "_")
}

func loadDB(ctx context.Context, dbPath, keyFile string, pwd []byte) (*DirEntry, error) {
	// 1. Fetch XML structure
	log.Println("[INFO] Reading database structure...")

	// We technically could use -q here too, but the XML parser has logic to skip garbage anyway.
	args := []string{"export", dbPath}
	if keyFile != "" {
		args = append(args, "--key-file", keyFile)
	}

	cmd := exec.CommandContext(ctx, "keepassxc-cli", args...)

	// SECURE FIX: Using MultiReader.
	// feeding password bytes + newline byte.
	// Avoids creating a string copy of the password.
	cmd.Stdin = io.MultiReader(bytes.NewReader(pwd), bytes.NewReader([]byte("\n")))

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("CLI export failed: %v (Stderr: %s)", err, stderr.String())
	}

	// Clean up potential garbage output (keepassxc-cli sometimes prints banners to stdout)
	rawBytes := out.Bytes()
	startIdx := bytes.Index(rawBytes, []byte("<KeePassFile"))
	if startIdx == -1 {
		startIdx = bytes.Index(rawBytes, []byte("<?xml"))
	}
	if startIdx == -1 {
		return nil, fmt.Errorf("failed to find valid XML in CLI output")
	}

	var db KpxRoot
	if err := xml.Unmarshal(rawBytes[startIdx:], &db); err != nil {
		return nil, fmt.Errorf("XML parsing error: %v", err)
	}
	out.Reset()

	// Root of our file system tree
	rootEntry := NewDirEntry("root")

	// 2. Traversal and targeted file extraction
	var processGroup func(g KpxGroup, parentDir *DirEntry)
	processGroup = func(g KpxGroup, parentDir *DirEntry) {

		// Determine directory name for the current group
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

		for _, entry := range g.Entries {
			var title, notes string
			for _, s := range entry.Strings {
				if s.Key == "Title" {
					title = s.Value
				}
				if s.Key == "Notes" {
					notes = s.Value
				}
			}

			if len(entry.Binaries) == 0 || notes == "" || title == "" {
				continue
			}

			rules := parseRules(notes)
			if len(rules) == 0 {
				continue
			}

			for _, binRef := range entry.Binaries {
				fName := strings.TrimSpace(binRef.Key)
				safeFName := sanitizeName(fName)

				allowedBins, ok := rules[fName]
				if !ok {
					continue
				}

				log.Printf("[EXTRACT] Extracting '%s' from entry '%s' -> '%s'...", fName, title, groupName)

				// Fetch file content
				content, err := fetchAttachment(ctx, dbPath, keyFile, pwd, title, fName)
				if err != nil {
					log.Printf("   [ERR] Failed to extract file: %v. Skipping...", err)
					continue
				}

				if len(content) == 0 {
					log.Printf("   [WARN] File '%s' is empty.", fName)
				}

				currentDir.Files[safeFName] = &SecuredFile{
					Name:        safeFName,
					Content:     content,
					AllowedBins: allowedBins,
				}
				log.Printf("   [OK] File loaded into memory (%d bytes).", len(content))
			}
		}

		// Recurse into subgroups
		for _, sub := range g.Groups {
			processGroup(sub, currentDir)
		}
	}

	// Start processing from the root group defined in XML
	processGroup(db.Root.Group, rootEntry)
	return rootEntry, nil
}

// fetchAttachment calls CLI for a specific attachment accepts pwd as []byte
func fetchAttachment(ctx context.Context, dbPath, keyFile string, pwd []byte, entryTitle, attachmentName string) ([]byte, error) {
	args := []string{"attachment-export", "-q", dbPath, entryTitle, attachmentName, "/dev/stdout"}
	if keyFile != "" {
		args = append(args, "--key-file", keyFile)
	}

	cmd := exec.CommandContext(ctx, "keepassxc-cli", args...)

	// SECURE FIX: Same usage of MultiReader to stream password
	cmd.Stdin = io.MultiReader(bytes.NewReader(pwd), bytes.NewReader([]byte("\n")))

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cmd error: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
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
		bPath := strings.TrimSpace(parts[1])

		cleanPath := filepath.Clean(strings.TrimSpace(bPath))
		fName = strings.TrimSpace(fName)

		if _, ok := res[fName]; !ok {
			res[fName] = make(map[string]struct{})
		}

		// 1. Add literal path (e.g., /run/current-system/sw/bin/cat)
		res[fName][cleanPath] = struct{}{}

		// 2. IMPORTANT FOR NIXOS: Resolve symlinks
		// Often /bin/foo is a symlink to /nix/store/.../bin/foo. We need to allow both.
		resolved, err := filepath.EvalSymlinks(cleanPath)
		if err == nil && resolved != cleanPath {
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
		// Traverse recursively by creating new Directory Inodes
		childNode := &SecureDirNode{Entry: dirEntry}
		// S_IFDIR for directories
		childInode := n.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: fuse.S_IFDIR})
		n.AddChild(name, childInode, true)
	}

	// Add files in this directory
	for name, fileData := range n.Entry.Files {
		// S_IFREG for regular files
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
	unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)

	// Context for graceful shutdown during loading
	ctx, cancel := context.WithCancel(context.Background())

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Interrupt received, shutting down...")
		cancel()
	}()

	fmt.Print("KeePass Password: ")
	bPwd, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	rootEntry, err := loadDB(ctx, dbPath, *keyFilePtr, bPwd)

	// Best-effort wiping of password from memory
	wipeBytes(bPwd)
	runtime.GC()

	if err != nil {
		// If cancelled by Context
		if ctx.Err() == context.Canceled {
			log.Println("Operation aborted by user.")
			os.Exit(0)
		}
		log.Fatalf("Fatal error: %v", err)
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

	// Mount the root entry found in the DB.
	// We use the rootEntry.Dirs because usually the XML export has a single <Root> group
	// which contains the actual user groups (e.g. "General", "Internet").
	// We want the mount to show "General", "Internet", etc.
	// Since loadDB wraps everything in a virtual "root", passing that virtual root
	// as the mount source works perfectly.
	server, err := fs.Mount(mountPoint, &SecureDirNode{Entry: rootEntry}, opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Mounted at %s. Press Ctrl+C to unmount.", mountPoint)

	// Reset signal handler for unmount
	signal.Stop(sigCh)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Unmounting...")
		server.Unmount()
	}()

	server.Wait()
}
