package utils

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Writes content to target, making it appear atomically, i.e. other processes
// won't observe a partially written target file. The owner, group, mode bits
// and extended attributes are copied over from a pre-existing target, if it's a
// regular file and this process has sufficient privileges. Otherwise the
// provided mode bits are used (before umask).
//
// This is intended to be a drop-in replacement for [os.WriteFile], while adding
// atomic replacement semantics. However, this makes it fail in cases where
// os.WriteFile succeeds:
//
//   - If the process can't create files in target's parent directory, e.g
//     because the target directory is read-only.
//
// On the contrary, this function succeeds in cases where os.WriteFile fails:
//
//   - If target exists and is non-writable, i.e. if its permissions don't have
//     the appropriate write bit set.
//
// Atomic replacement applies to regular target files only. Non-regular existing
// targets follow os.WriteFile semantics because they don't have replaceable
// file contents.
func WriteFileAtomically(target string, content []byte, mode os.FileMode) (err error) {
	// Open the parent directory, respecting symlinks.
	dir, base, err := openParentDir(target)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()

	switch base {
	case "":
		var err error = syscall.EISDIR
		if dir.Name() == "" {
			err = os.ErrNotExist
		}
		return &os.PathError{Op: "open", Path: dir.Name(), Err: err}
	case ".", "..":
		return &os.PathError{Op: "open", Path: dir.Name() + base, Err: syscall.EISDIR}
	}

	// Open a pre-existing target, if any.
	var stat unix.Stat_t
	preExisting, err := ignoringEINTR(func() (int, error) {
		return unix.Openat(int(dir.Fd()), base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		if err != unix.ENOENT {
			return &os.PathError{Op: "open", Path: filepath.Join(dir.Name(), base), Err: err}
		}
	} else {
		defer unix.Close(preExisting)

		// Record the pre-existing target's attributes.
		stat, err = ignoringEINTR(func() (stat unix.Stat_t, _ error) {
			err := unix.Fstat(preExisting, &stat)
			return stat, err
		})
		if err != nil {
			return &os.PathError{Op: "stat", Path: filepath.Join(dir.Name(), base), Err: err}
		}

		// If it's an irregular target, try to write directly to it.
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			mode := stat.Mode & (0777 | unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX)
			return writeFileDirect(preExisting, dir, base, content, mode)
		}
	}

	// Open the temporary file to write to.
	tmpMode := os.FileMode(0600)
	if preExisting == -1 {
		// Create the temporary file with the desired target permissions. This
		// means that the intended audience of the target path can read and
		// potentially write to it. Since this is clearly a temporary file and
		// the focus of this function is the target path rather than any
		// intermediary temporary paths, this trade-off is acceptable to
		// preserve the umask for newly created files.
		tmpMode = mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		// The user write bit is required to read extended attributes.
		tmpMode |= 0200
	}
	tmp, err := createTemp(dir, base, tmpMode)
	if err != nil {
		return err
	}

	// Defer closing the temporary file and removing it on errors.
	defer func() {
		closeErr := tmp.Close()
		if err == nil {
			// Sync the directory, so that the rename is committed to disk. The
			// renamed file is already visible to other processes; a failed sync
			// only means that the replacement might not survive a system crash.
			_ = dir.Sync()
			return
		}

		_, removeErr := ignoringEINTR(func() (unit struct{}, _ error) {
			err := unix.Unlinkat(int(dir.Fd()), tmp.Name(), 0)
			return unit, err
		})
		if removeErr != nil {
			if removeErr == unix.ENOENT {
				removeErr = nil
			} else {
				removeErr = &os.PathError{
					Op:   "remove",
					Path: filepath.Join(dir.Name(), tmp.Name()),
					Err:  removeErr,
				}
			}
		}
		err = errors.Join(err, closeErr, removeErr)
	}()

	// Write the content to disk.
	if _, err := tmp.Write(content); err != nil {
		return err
	}

	// Sync it.
	if err = tmp.Sync(); err != nil {
		return err
	}

	// Preserve file attributes, if possible.
	if preExisting != -1 {
		// Copy over extended attributes on a best-effort basis.
		// Re-open the file descriptor with read permissions.
		if f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", preExisting)); err == nil {
			defer f.Close()
			copyXAttrs(int(f.Fd()), int(tmp.Fd()))
		}

		_ = tmp.Chown(int(stat.Uid), int(stat.Gid))

		mode := os.FileMode(stat.Mode & 0777)
		if stat.Mode&unix.S_ISUID != 0 {
			mode |= os.ModeSetuid
		}
		if stat.Mode&unix.S_ISGID != 0 {
			mode |= os.ModeSetgid
		}
		if stat.Mode&unix.S_ISVTX != 0 {
			mode |= os.ModeSticky
		}
		if err := tmp.Chmod(mode); err != nil {
			return err
		}
	} else if mode&0200 == 0 {
		// Strip the write bit.
		// Re-stat to get the current mode after umask.
		stat, err := tmp.Stat()
		if err != nil {
			return err
		}
		// Do a chmod only if the write bit needs to be stripped.
		if mode := stat.Mode(); mode&0200 != 0 {
			if err := tmp.Chmod(mode &^ 0200); err != nil {
				return err
			}
		}
	}

	// Do the actual rename.
	if _, err := ignoringEINTR(func() (unit struct{}, _ error) {
		err := unix.Renameat(int(dir.Fd()), tmp.Name(), int(dir.Fd()), base)
		return unit, err
	}); err != nil {
		return &os.LinkError{
			Op:  "rename",
			Old: dir.Name() + tmp.Name(),
			New: dir.Name() + base,
			Err: err,
		}
	}

	return nil
}

// Resolves symbolic links in target, including a trailing chain of dangling
// symlinks, i.e. the result may be a non-existing path at which a new file
// would be created.
func openParentDir(target string) (_ *os.File, _ string, err error) {
	const (
		// Give up following symlinks after 40 hops.
		// This is the same as the MAXSYMLINKS constant in the kernel.
		maxSymlinkHops = 40

		// Maximum path name length including the terminal NUL.
		maxPath = 4096
	)

	parent, base := filepath.Split(target)
	dir, err := openDir(nil, parent)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil && dir != nil {
			err = errors.Join(err, dir.Close())
		}
	}()

	var pathBuf [maxPath]byte
	for symlinkHops := 0; ; {
		if base == "" {
			return dir, base, nil
		}
		linkLen, err := ignoringEINTR(func() (int, error) {
			return unix.Readlinkat(int(dir.Fd()), base, pathBuf[:])
		})
		if err != nil {
			if err == unix.ENOENT {
				return dir, base, nil
			}
			if err == unix.EINVAL {
				// The target path exists, but is not a symlink.
				return dir, base, nil
			}
			return nil, "", &os.PathError{Op: "readlink", Path: dir.Name() + base, Err: err}
		}
		symlinkHops++
		if symlinkHops > maxSymlinkHops {
			return nil, "", errors.New("too many links")
		}
		if linkLen == len(pathBuf) {
			return nil, "", &os.PathError{
				Op:   "readlink",
				Path: dir.Name() + base,
				Err:  errors.New("link name too long"),
			}
		}

		resolved := string(pathBuf[:linkLen])
		parent, base = filepath.Split(resolved)
		if parent != "" {
			newDir, err := openDir(dir, parent)
			if err != nil {
				return nil, "", err
			}
			if err, dir = dir.Close(), newDir; err != nil {
				return nil, "", err
			}
		}
	}
}

func openDir(dir *os.File, target string) (*os.File, error) {
	dirfd, path := unix.AT_FDCWD, target
	if dir == nil {
		target = cmp.Or(target, ".")
	} else {
		dirfd = int(dir.Fd())
		if !filepath.IsAbs(target) {
			path = dir.Name() + target
		}
	}

	fd, err := ignoringEINTR(func() (int, error) {
		return unix.Openat(dirfd, target, unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	})
	runtime.KeepAlive(dir)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(fd), path), nil
}

func createTemp(dir *os.File, name string, mode os.FileMode) (*os.File, error) {
	// The number of attempts to find an unused temporary file name.
	// This mirrors the retry limit of os.CreateTemp.
	const maxTempFileAttempts = 10000

	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NONBLOCK | unix.O_CLOEXEC
	unixMode := uint32(mode & 0777)
	if mode&os.ModeSetuid != 0 {
		unixMode |= unix.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		unixMode |= unix.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		unixMode |= unix.S_ISVTX
	}

	for attempt := 1; ; attempt++ {
		var rnd uint32
		if attempt <= 3 {
			rnd = mrand.Uint32() //nolint:gosec // Just try this the first three times.
		} else {
			var b [4]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			rnd = binary.NativeEndian.Uint32(b[:])
		}
		tmpName := fmt.Sprintf(".%s.%d.tmp", name, rnd)

		fd, err := ignoringEINTR(func() (int, error) {
			return unix.Openat(int(dir.Fd()), tmpName, flags, unixMode)
		})
		runtime.KeepAlive(dir)
		if err != nil {
			if attempt < maxTempFileAttempts && err == unix.EEXIST {
				continue
			}
			return nil, &os.PathError{
				Op:   "createtemp",
				Path: filepath.Join(dir.Name(), fmt.Sprintf(".%s.*.tmp", name)),
				Err:  err,
			}
		}

		return os.NewFile(uintptr(fd), tmpName), nil
	}
}

func writeFileDirect(fd int, dir *os.File, base string, content []byte, mode uint32) error {
	// First, try to re-open the existing file descriptor for writing.
	path := filepath.Join(dir.Name(), base)
	procFDPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	if f, err := os.OpenFile(procFDPath, syscall.O_WRONLY|syscall.O_TRUNC, 0); err == nil {
		normalize := func(err error) error {
			if err, ok := errors.AsType[*os.PathError](err); ok && err.Path == procFDPath {
				err.Path = path
			}
			return err
		}

		_, err := f.Write(content)
		return errors.Join(normalize(err), normalize(f.Close()))
	}

	// If that failed, try to open it via its path name. This is not completely
	// TOCTOU free, but since this is now a traditional direct write, it's at
	// least not too concerning if target became a traditional file in the
	// meantime. The atomic semantics got lost, but other than that, it behaves
	// just like os.WriteFile.
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC | unix.O_CLOEXEC
	fd, err := ignoringEINTR(func() (int, error) {
		return unix.Openat(int(dir.Fd()), base, flags, mode)
	})
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	// Set the file descriptor to non-blocking after opening it, so opening it
	// properly blocks on sockets and FIFOs. This is what os.OpenFile would do,
	// too.
	_ = syscall.SetNonblock(fd, true)
	f := os.NewFile(uintptr(fd), path)

	_, err = f.Write(content)
	return errors.Join(err, f.Close())
}

func copyXAttrs(src, dst int) {
	attrs, err := outBufferSyscall(func(buf []byte) (int, error) {
		return ignoringEINTR(func() (int, error) { return unix.Flistxattr(src, buf) })
	})
	if err != nil {
		return
	}

	attrs, nulTerminated := bytes.CutSuffix(attrs, []byte{0})
	if !nulTerminated {
		return
	}

	for attr := range bytes.SplitSeq(attrs, []byte{0}) {
		attr := string(attr)
		if val, err := outBufferSyscall(func(buf []byte) (int, error) {
			return ignoringEINTR(func() (int, error) { return unix.Fgetxattr(src, attr, buf) })
		}); err == nil {
			_, _ = ignoringEINTR(func() (unit struct{}, _ error) {
				err := unix.Fsetxattr(dst, attr, val, 0)
				return unit, err
			})
		}
	}
}

func outBufferSyscall(f func([]byte) (int, error)) ([]byte, error) {
	// The number of attempts for buffer-sizing syscall pairs whose required
	// buffer size may grow concurrently between the two calls.
	const maxBufferSizingAttempts = 5

	for attempt := 1; ; attempt++ {
		size, err := f(nil)
		if err != nil || size == 0 {
			return nil, err
		}

		var buf []byte
		if size > 0 {
			buf = make([]byte, size+1)
			size, err = f(buf)
			if err != nil {
				if attempt < maxBufferSizingAttempts && errors.Is(err, unix.ERANGE) {
					continue
				}
				return nil, err
			}

			return buf[:size], nil
		}
	}
}

func ignoringEINTR[T any](f func() (T, error)) (T, error) {
	for {
		if t, err := f(); err != syscall.EINTR {
			return t, err
		}
	}
}
