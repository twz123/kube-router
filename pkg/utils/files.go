package utils

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

// Writes content to the target path, making it appear atomically. The owner,
// group, mode bits and extended attributes are copied over from a pre-existing
// target, if it's a regular file and this process has sufficient privileges.
// Otherwise the provided mode bits are used, ignoring the process's umask.
func WriteFileAtomically(target string, content []byte, mode os.FileMode) (err error) {
	// Make the path absolute. This is a safeguard against intermediary working
	// directory changes, just in case.
	if target, err = filepath.Abs(target); err != nil {
		return err
	}

	dir, base := filepath.Split(target)
	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".%s.*.tmp", base))
	if err != nil {
		return err
	}
	defer func() {
		closeErr := tmp.Close()
		var removeErr error
		if err != nil {
			removeErr = os.Remove(tmp.Name())
			if errors.Is(err, os.ErrNotExist) {
				removeErr = nil
			}
		}
		err = errors.Join(err, closeErr, removeErr)
	}()

	if _, err := tmp.Write(content); err != nil {
		return err
	}

	if err = tmp.Sync(); err != nil {
		return err
	}

	// Preserve file attributes, if possible.
	var chmodDone bool
	if target, err := os.Open(target); err == nil {
		defer target.Close()

		var stat unix.Stat_t
		if err := unix.Fstat(int(target.Fd()), &stat); err == nil && (stat.Mode&unix.S_IFMT) == unix.S_IFREG {
			const cap FSXAttr = "security.capability"

			// Copy over extended attributes on a best-effort basis.
			var hasCap bool
			if attrs, err := ListFileXAttrs(target); err == nil {
				for attr := range attrs {
					if attr == cap {
						// Defer copying capabilities after chmod.
						hasCap = true
						continue
					}
					if val, err := attr.GetFile(target); err == nil {
						_ = attr.SetFile(tmp, val)
					}
				}
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
			chmodDone = true

			if hasCap {
				if val, err := cap.GetFile(target); err == nil {
					_ = cap.SetFile(tmp, val)
				}
			}
		}
	}

	if !chmodDone {
		if err := tmp.Chmod(mode); err != nil {
			return err
		}
	}

	return os.Rename(tmp.Name(), target)
}

func ListFileXAttrs(f *os.File) (iter.Seq[FSXAttr], error) {
	attrs, err := outBufferSyscall(func(buf []byte) (int, error) {
		size, err := unix.Flistxattr(int(f.Fd()), buf)
		runtime.KeepAlive(f)
		return size, err
	})
	if err != nil {
		return nil, os.NewSyscallError("flistxattr", err)
	}

	return iterFSXAttrs(attrs)
}

func iterFSXAttrs(attrs []byte) (iter.Seq[FSXAttr], error) {
	// Strip terminal NUL byte.
	if len := len(attrs); len > 0 {
		if attrs[len-1] != 0 {
			return nil, errors.New("extended attribute names not NUL terminated")
		}
		attrs = attrs[:len-1]
	}

	return func(yield func(FSXAttr) bool) {
		for {
			idx := bytes.IndexByte(attrs, 0)
			if idx < 0 {
				yield(FSXAttr(attrs))
				return
			} else if !yield(FSXAttr(attrs[:idx])) {
				return
			}
			attrs = attrs[idx+1:]
		}
	}, nil
}

type FSXAttr string

func (a FSXAttr) String() string { return string(a) }

func (a FSXAttr) GetFile(f *os.File) ([]byte, error) {
	val, err := outBufferSyscall(func(buf []byte) (int, error) {
		size, err := unix.Fgetxattr(int(f.Fd()), string(a), buf)
		runtime.KeepAlive(f)
		return size, err
	})
	return val, os.NewSyscallError("fgetxattr", err)
}

func (a FSXAttr) SetFile(f *os.File, val []byte) error {
	err := unix.Fsetxattr(int(f.Fd()), string(a), val, 0)
	runtime.KeepAlive(f)
	return os.NewSyscallError("fsetxattr", err)
}

func outBufferSyscall(f func([]byte) (int, error)) ([]byte, error) {
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
				if attempt < 5 && errors.Is(err, unix.ERANGE) {
					continue
				}
				return nil, err
			}

			return buf[:size], nil
		}
	}
}
