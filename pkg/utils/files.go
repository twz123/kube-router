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
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// Writes content to target, making it appear "atomically", i.e. other processes
// won't observe a partially written target file. The owner, group, mode bits
// and extended attributes are copied over from a pre-existing target, if it's a
// regular file and this process has sufficient privileges. Otherwise the
// provided mode bits are used (before umask).
//
// This is intended to be a drop-in replacement for [os.WriteFile], while adding
// the semantics described above. However, there are some notable differences:
//
//   - This function can follow symlink chains that are longer than the kernel's
//     limit for a single path-based syscall.
//   - This function fails if the process can't create files in target's parent
//     directory, e.g. because the target directory is read-only.
//   - On kernels that don't support the faccessat2 syscall, function may write
//     to files that the kernel would otherwise reject.
//   - If a symlink would have to be followed in a sticky, world-writable
//     directory, but the symlink is owned by neither the directory owner nor
//     the user running the process. This mirrors the kernel's
//     fs.protected_symlinks policy, and is applied even on systems where that
//     policy is disabled.
//
// Atomic replacement applies to regular target files only. Non-regular existing
// targets follow os.WriteFile semantics because they don't have replaceable
// file contents.
func WriteFileAtomically(path string, content []byte, mode os.FileMode) error {
	_, err := writeFileAtomically(path, content, mode)
	return err
}

func writeFileAtomically(path string, content []byte, mode os.FileMode) (bool, error) {
	entry, err := openDirEntry(path)
	if err != nil {
		return false, os.WriteFile(path, content, mode)
	}
	defer func() { err = errors.Join(err, entry.close()) }()

	if err := entry.evalSymlinks(); err != nil {
		if e, ok := errors.AsType[badSymlinkError](err); ok {
			return false, &os.PathError{Op: "open", Path: path, Err: syscall.Errno(e)}
		}
		return false, os.WriteFile(path, content, mode)
	}

	if entry.canWriteAtomically() {
		err := entry.writeAtomically(content, mode)
		if pathErr, ok := errors.AsType[*os.PathError](err); ok {
			if pathErr.Op == "createtemp" {
				switch {
				case errors.Is(err, unix.EACCES):
					return false, entry.writeDirect(content, mode)
				case errors.Is(err, unix.EROFS):
					return false, entry.writeDirect(content, mode)
				}
			}
		}

		return true, err
	}

	return false, entry.writeDirect(content, mode)
}

type dirEntry struct {
	f    *os.File
	name string
	info os.FileInfo
	dir  *os.File // TODO: Check if os.Root can be used here.
}

func (e *dirEntry) path() string {
	if e.f != nil {
		return e.f.Name()
	}

	return e.relativePath(e.name)
}

func (e *dirEntry) relativePath(name string) string {
	if e.dir == nil {
		return name
	}

	if dir := e.dir.Name(); dir == "" {
		return name
	} else if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + name
	} else {
		return dir + string(os.PathSeparator) + name
	}
}

func (e *dirEntry) dirFD() int {
	if e.dir == nil {
		return unix.AT_FDCWD
	}
	return int(e.dir.Fd())
}

func (e *dirEntry) close() error {
	if e.dir == nil {
		if e.f == nil {
			return nil
		}
		return e.f.Close()
	}

	derr := e.dir.Close()

	if e.f != nil {
		if ferr := e.f.Close(); ferr != nil {
			return errors.Join(derr, ferr)
		}
	}

	return derr
}

func openDirEntry(path string) (_ *dirEntry, err error) {
	dir, name := filepath.Split(path)

	var entry dirEntry
	if dirFD, err := entry.unixOpenAt(cmp.Or(dir, "."), unix.O_PATH, 0); err != nil {
		return nil, &os.PathError{Op: "open", Path: cmp.Or(dir, "."), Err: err}
	} else {
		entry.dir, entry.name = os.NewFile(uintptr(dirFD), dir), name
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, entry.close())
		}
	}()
	if dirInfo, err := entry.dir.Stat(); err != nil {
		return nil, err
	} else if !dirInfo.IsDir() {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOTDIR}
	}

	err = syscall.EISDIR
	switch name {
	case "":
		if dir == "" {
			err = os.ErrNotExist
		}
		fallthrough
	case ".", "..":
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	default:
	}

	if err := entry.setTarget(name); err != nil {
		return nil, err
	}

	return &entry, nil
}

func (e *dirEntry) openAt(name string, flags int, mode os.FileMode) (*os.File, error) {
	path := e.relativePath(name)
	fd, err := e.unixOpenAt(name, flags, mode)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(fd), path), nil
}

func (e *dirEntry) unixOpenAt(name string, flags int, mode os.FileMode) (_ int, err error) {
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

	fd, err := ignoringEINTR(func() (int, error) {
		return unix.Openat(e.dirFD(), name, flags|unix.O_CLOEXEC, unixMode)
	})
	runtime.KeepAlive(e.dir)
	return fd, err
}

func (e *dirEntry) onDifferentMountPoint() bool {
	for _, mask := range []uint32{unix.STATX_MNT_ID_UNIQUE, unix.STATX_MNT_ID} {
		dirStat, err := ignoringEINTR(func() (stat unix.Statx_t, _ error) {
			err := unix.Statx(int(e.dir.Fd()), "", unix.AT_EMPTY_PATH, int(mask), &stat)
			return stat, err
		})
		runtime.KeepAlive(e.dir)
		if err != nil {
			if err == unix.ENOSYS {
				break
			}
			return false
		}
		if dirStat.Mask&mask != mask {
			continue
		}

		targetStat, err := ignoringEINTR(func() (stat unix.Statx_t, _ error) {
			err := unix.Statx(int(e.f.Fd()), "", unix.AT_EMPTY_PATH, int(mask), &stat)
			return stat, err
		})
		if err != nil {
			if err == unix.ENOSYS {
				break
			}
			return false
		}
		if targetStat.Mask&mask != mask {
			continue
		}

		return dirStat.Mnt_id != targetStat.Mnt_id
	}

	if dirStat, err := e.dir.Stat(); err == nil {
		if dirStat, ok := dirStat.Sys().(*syscall.Stat_t); ok {
			if targetStat, ok := e.info.Sys().(*syscall.Stat_t); ok {
				return dirStat.Dev != targetStat.Dev
			}
		}
	}

	return false
}

func (e *dirEntry) setTarget(name string) error {
	f, err := e.openAt(name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			f, e.name, e.f, e.info = e.f, name, nil, nil
			if f == nil {
				return nil
			}
			return f.Close()
		}
		return err
	}

	info, err := f.Stat()
	if err != nil {
		return errors.Join(err, f.Close())
	}

	e.name, e.f, e.info, f = name, f, info, e.f
	if f == nil {
		return nil
	}
	return f.Close()
}

type badSymlinkError syscall.Errno

func (e badSymlinkError) Error() string { return syscall.Errno(e).Error() }

func (e *dirEntry) evalSymlinks() error {
	const (
		// Give up following symlinks after 40 hops.
		// This is the same as the MAXSYMLINKS constant in the kernel.
		maxSymlinkHops = 40

		// Maximum path name length including the terminal NUL.
		maxPath = 4096
	)

	var pathBuf [maxPath]byte
	for symlinkHops := 0; ; {
		if ok, err := e.isSymlink(); err != nil {
			return err
		} else if !ok {
			return nil
		}

		linkLen, err := ignoringEINTR(func() (int, error) {
			return unix.Readlinkat(int(e.f.Fd()), "", pathBuf[:])
		})
		if err != nil {
			return &os.PathError{Op: "open", Path: e.f.Name(), Err: err}
		}

		symlinkHops++
		if symlinkHops > maxSymlinkHops {
			return &os.PathError{Op: "open", Path: e.f.Name(), Err: badSymlinkError(syscall.ELOOP)}
		}
		if linkLen == len(pathBuf) {
			return &os.PathError{Op: "readlink", Path: e.f.Name(), Err: errors.New("link name too long")}
		}

		resolved := string(pathBuf[:linkLen])

		if filepath.IsAbs(resolved) {
			other, err := openDirEntry(resolved)
			if err != nil {
				return err
			}
			err = e.close()
			*e = *other
			return err
		}

		dir, name := filepath.Split(resolved)
		if dir != "" {
			newDir, err := e.openAt(dir, unix.O_DIRECTORY, 0)
			if err != nil {
				return err
			}
			if err, e.dir = e.dir.Close(), newDir; err != nil {
				return err
			}
		}
		if err := e.setTarget(name); err != nil {
			return err
		}
	}
}

func (e *dirEntry) isSymlink() (bool, error) {
	if e.f == nil || e.info.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}

	dirStat, err := e.dir.Stat()
	if err != nil {
		return false, err
	}

	// https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks
	const stickyWorldWritable = os.ModeSticky | 0002
	if dirStat.Mode()&stickyWorldWritable == stickyWorldWritable {
		if dirStat, ok := dirStat.Sys().(*syscall.Stat_t); ok {
			if targetStat, ok := e.info.Sys().(*syscall.Stat_t); ok &&
				targetStat.Uid != dirStat.Uid && targetStat.Uid != uint32(syscall.Geteuid()) {
				return false, badSymlinkError(syscall.EACCES)
			}
		}
	}

	return true, nil
}

func (e *dirEntry) canWriteAtomically() bool {
	if e.f == nil {
		return true
	}
	if !e.info.Mode().IsRegular() {
		return false
	}

	if e.onDifferentMountPoint() {
		return false
	}

	// Don't try atomic writes if the target is on another device.
	if stat, ok := e.info.Sys().(*syscall.Stat_t); ok {
		if dirInfo, err := e.dir.Stat(); err == nil {
			if dirStat, ok := dirInfo.Sys().(*syscall.Stat_t); ok {
				return stat.Dev == dirStat.Dev
			}
		}
	}

	return true
}

func (e *dirEntry) writeDirect(content []byte, mode os.FileMode) error {
	if e.f == nil {
		f, err := e.openAt(e.name, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC, mode)
		if err != nil {
			return err
		}
		_, err = f.Write(content)
		return errors.Join(err, f.Close())
	}

	// First, try to re-open the existing file descriptor for writing.
	procFDPath := fmt.Sprintf("/proc/self/fd/%d", e.f.Fd())
	f, err := os.OpenFile(procFDPath, syscall.O_WRONLY|syscall.O_TRUNC, 0)
	runtime.KeepAlive(e)
	if err == nil {
		normalize := func(err error) error {
			if err, ok := errors.AsType[*os.PathError](err); ok && err.Path == procFDPath {
				err.Path = e.path()
			}
			return err
		}

		_, err := f.Write(content)
		return errors.Join(normalize(err), normalize(f.Close()))
	}

	// If that failed, try to open it via its path name. This is not completely
	// TOCTOU free, but since this is a traditional direct write, it's at least
	// not too concerning if target became a traditional file in the meantime.
	// The atomic semantics got lost, but other than that, it behaves just like
	// os.WriteFile.
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC | unix.O_NOFOLLOW
	fd, err := e.unixOpenAt(e.name, flags, e.info.Mode())
	if err != nil {
		return &os.PathError{Op: "open", Path: e.path(), Err: err}
	}

	// Set the file descriptor to non-blocking after opening it, so opening it
	// properly blocks on sockets and FIFOs. This is what os.OpenFile would do,
	// too.
	_ = syscall.SetNonblock(fd, true)
	f = os.NewFile(uintptr(fd), e.path())

	_, err = f.Write(content)
	return errors.Join(err, f.Close())
}

func (e *dirEntry) writeAtomically(content []byte, mode os.FileMode) (err error) {
	if err := e.openForWriteOK(); err != nil {
		return err
	}

	// Open the temporary file to write to.
	tmp, err := e.createTemporaryFile(mode)
	if err != nil {
		return err
	}
	_, tmpName := filepath.Split(tmp.Name())

	// Defer closing the temporary file and removing it on errors.
	defer func() {
		closeErr := tmp.Close()
		if err == nil {
			// Sync the directory, so that the rename is committed to disk. The
			// renamed file is already visible to other processes; a failed sync
			// only means that the replacement might not survive a system crash.
			_ = e.dir.Sync()
			return
		}

		_, removeErr := ignoringEINTR(func() (unit struct{}, _ error) {
			err := unix.Unlinkat(int(e.dir.Fd()), tmpName, 0)
			return unit, err
		})
		if removeErr != nil {
			if removeErr == unix.ENOENT {
				removeErr = nil
			} else {
				removeErr = &os.PathError{
					Op:   "remove",
					Path: e.relativePath(tmp.Name()),
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
	if err := e.preserveAttributes(tmp, mode); err != nil {
		return err
	}

	// Do the actual rename.
	dirFD := e.dirFD()
	if _, err := ignoringEINTR(func() (unit struct{}, _ error) {
		err := unix.Renameat(dirFD, tmpName, dirFD, e.name)
		return unit, err
	}); err != nil {
		return &os.LinkError{Op: "rename", Old: tmp.Name(), New: e.path(), Err: err}
	}

	return nil
}

func (e *dirEntry) openForWriteOK() error {
	if e.f == nil {
		return nil
	}

	if true { // FIXME
		if _, err := ignoringEINTR(func() (unit struct{}, _ error) {
			err := unix.Faccessat2(int(e.f.Fd()), "", unix.W_OK, unix.AT_EACCESS|unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
			return unit, err
		}); err == nil {
			return nil
		} else if err == unix.EACCES {
			return &os.PathError{Op: "open", Path: e.f.Name(), Err: err}
		} else if err != unix.ENOSYS {
			return &os.PathError{Op: "faccessat2", Path: e.f.Name(), Err: err}
		}
	}

	err := statBasedOpenForWriteOK(func() (mode uint32, uid uint32, gid uint32, _ error) {
		if st, ok := e.info.Sys().(*syscall.Stat_t); ok {
			return st.Mode, st.Uid, st.Gid, nil
		}
		return 0, 0, 0, &os.PathError{Op: "faccessat2", Path: e.f.Name(), Err: unix.ENOSYS}
	})
	if err == unix.EACCES {
		return &os.PathError{Op: "open", Path: e.f.Name(), Err: err}
	}
	return err
}

// Userspace approximation for older kernels based on stat'ing the path.
func statBasedOpenForWriteOK(stat func() (mode, uid, gid uint32, _ error)) error {
	uid := os.Geteuid()
	if uid == 0 {
		// root can write to all files.
		return nil
	}
	if ok, err := capabilityInEffect(unix.CAP_DAC_OVERRIDE); err != nil || ok {
		// Discretionary access control overridden.
		return err
	}

	mode, fuid, fgid, err := stat()
	if err != nil {
		return err
	}

	if uint32(uid) == fuid {
		if mode&unix.S_IWUSR != 0 {
			return nil
		}
	} else if gid := os.Getegid(); uint32(gid) == fgid {
		if mode&unix.S_IWGRP != 0 {
			return nil
		}
	} else if gids, err := unix.Getgroups(); err != nil {
		return os.NewSyscallError("getgroups", err)
	} else if slices.Contains(gids, uid) {
		panic("FIXME missing test coverage")
		return nil
	} else if mode&unix.S_IWOTH != 0 {
		return nil
	}

	return unix.EACCES
}

func (e *dirEntry) createTemporaryFile(mode os.FileMode) (*os.File, error) {
	// The number of attempts to find an unused temporary file name.
	// This mirrors the retry limit of os.CreateTemp.
	const maxTempFileAttempts = 10000

	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NONBLOCK
	tmpMode := os.FileMode(0600)
	if e.f == nil {
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

	for attempt := range maxTempFileAttempts {
		var rnd uint32
		if attempt < 3 {
			rnd = mrand.Uint32() //nolint:gosec // Just try this the first three times.
		} else {
			var b [4]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			rnd = binary.NativeEndian.Uint32(b[:])
		}

		tmp, err := e.openAt(fmt.Sprintf(".%s.%d.tmp", e.name, rnd), flags, tmpMode)
		if err == nil || !errors.Is(err, os.ErrExist) {
			if pathErr, ok := errors.AsType[*os.PathError](err); ok {
				pathErr.Op = "createtemp"
				pathErr.Path = fmt.Sprintf(".%s.*.tmp", e.name)
			}
			return tmp, err
		}
	}

	return nil, &os.PathError{
		Op:   "createtemp",
		Path: e.relativePath(fmt.Sprintf(".%s.*.tmp", e.name)),
		Err:  os.ErrExist,
	}
}

func (e *dirEntry) preserveAttributes(target *os.File, mode os.FileMode) error {
	if e.f == nil {
		if mode&0200 != 0 {
			return nil
		}

		// Strip the write bit.
		// Re-stat to get the current mode after umask.
		stat, err := target.Stat()
		if err != nil {
			return err
		}
		// Do a chmod only if the write bit needs to be stripped.
		if mode := stat.Mode(); mode&0200 != 0 {
			if err := target.Chmod(mode &^ 0200); err != nil {
				return err
			}
		}

		return nil
	}

	// Copy over extended attributes on a best-effort basis.
	// Re-open the file descriptor with read permissions.
	f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", e.f.Fd()))
	runtime.KeepAlive(e.f)
	if err == nil {
		func() {
			defer f.Close()
			copyXAttrs(int(f.Fd()), int(target.Fd()))
			runtime.KeepAlive(target)
		}()
	}

	mode = e.info.Mode()

	// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/attr.c?h=v7.1#n63
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		if ok, err := capabilityInEffect(unix.CAP_FSETID); err == nil && !ok {
			mode &^= os.ModeSetuid

			if mode&0010 != 0 {
				mode &^= os.ModeSetgid
			} else if stat, ok := e.info.Sys().(*syscall.Stat_t); ok && mode&os.ModeSetgid != 0 {
				if int(stat.Gid) != unix.Getegid() {
					panic("FIXME this is currently lacking test coverage.")
					if groups, err := unix.Getgroups(); err == nil {
						if !slices.Contains(groups, int(stat.Gid)) {
							mode &^= os.ModeSetgid
						}
					}
				}
			}
		}
	}

	err = target.Chmod(mode)

	if stat, ok := e.info.Sys().(*syscall.Stat_t); ok {
		if target.Chown(int(stat.Uid), int(stat.Gid)) == nil {
			_ = target.Chmod(mode)
		}
	}

	return err
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

type capabilities [ /* _LINUX_CAPABILITY_U32S_3 */ 2]unix.CapUserData

func capabilityInEffect(cap byte) (bool, error) {
	if caps, err := getCapabilities(); err != nil {
		return false, err
	} else {
		return caps.inEffect(cap), nil
	}
}

func getCapabilities() (*capabilities, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps capabilities
	if err := unix.Capget(&hdr, &caps[0]); err != nil {
		return nil, os.NewSyscallError("capget", err)
	}

	return &caps, nil
}

func (c *capabilities) inEffect(cap byte) bool {
	pos, mask := cap/32, uint32(1)<<(cap%32)
	return int(pos) < len(c) && c[pos].Effective&mask != 0
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
