package utils

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWriteFileAtomically(t *testing.T) {
	t.Run("attributes", func(t *testing.T) {
		for _, perm := range []os.FileMode{0400, 0477, 0755, 0644, 0777} {
			for _, specialBits := range []os.FileMode{0, os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
				mode := perm | specialBits
				t.Run(mode.String(), func(t *testing.T) {
					t.Run("from scratch", func(t *testing.T) {
						dir := t.TempDir()
						ref := filepath.Join(dir, "ref")
						target := filepath.Join(dir, "target")

						// Record umask
						require.NoError(t, os.WriteFile(ref, nil, 0777))
						refStat, err := os.Stat(ref)
						require.NoError(t, err)
						umask := 0777 &^ refStat.Mode()

						require.NoError(t, WriteFileAtomically(target, nil, mode))

						if info, err := os.Stat(target); assert.NoError(t, err) {
							if expected, actual := mode&^umask, info.Mode(); expected != actual {
								assert.Failf(t, "Mode not equal", "expected: %s\nactual  : %s", expected, actual)
							}
						}

						attrs, err := outBufferSyscall(func(buf []byte) (int, error) {
							return ignoringEINTR(func() (int, error) {
								return unix.Listxattr(target, buf)
							})
						})
						if assert.NoError(t, err) {
							assert.Len(t, attrs, 0)
						}
					})

					t.Run("from pre-existing target", func(t *testing.T) {
						dir := t.TempDir()
						target := filepath.Join(dir, "target")
						attrValues := map[string][]byte{
							"user.kube-router-test":       []byte(t.Name()),
							"user.kube-router-test.empty": nil,
						}

						require.NoError(t, os.WriteFile(target, nil, 0600))
						for attr, val := range attrValues {
							_, err := ignoringEINTR(func() (unit struct{}, _ error) {
								err := unix.Setxattr(target, attr, val, 0)
								return unit, err
							})
							require.NoError(t, err)
						}
						require.NoError(t, os.Chmod(target, mode))
						// Record the actual file info. Some file systems won't retain special bits.
						info, err := os.Stat(target)
						require.NoError(t, err)

						require.NoError(t, WriteFileAtomically(target, []byte(mode.String()), 0))

						if content, err := readFileNoFollow(target); assert.NoError(t, err) {
							assert.Equal(t, []byte(mode.String()), content)
						}

						if actualInfo, err := os.Stat(target); assert.NoError(t, err) {
							if expected, actual := info.Mode(), actualInfo.Mode(); expected != actual {
								assert.Failf(t, "Mode not equal", "expected: %s\nactual  : %s", expected, actual)
							}
						}

						for attr, expected := range attrValues {
							actual, err := outBufferSyscall(func(buf []byte) (int, error) {
								return ignoringEINTR(func() (int, error) {
									return unix.Getxattr(target, attr, buf)
								})
							})
							if assert.NoErrorf(t, err, "While getting %s", attr) {
								assert.Equalf(t, expected, actual, "While comparing %s", attr)
							}
						}
					})
				})
			}
		}
	})

	t.Run("bad paths", func(t *testing.T) {
		for _, tt := range []struct {
			name, path string
			err        error
		}{
			{"empty", "", os.ErrNotExist},
			{"dot", ".", syscall.EISDIR},
			{"dot dot", "..", syscall.EISDIR},
			{"dot slash", "./", syscall.EISDIR},
			{"dot dot slash", "../", syscall.EISDIR},
			{"dot slash dot", "./.", syscall.EISDIR},
			{"dot dot slash dot", "../.", syscall.EISDIR},
			{"dot dot slash dot dot", "../..", syscall.EISDIR},
		} {
			t.Run(tt.name, func(t *testing.T) {
				err := WriteFileAtomically(tt.path, nil, 0644)
				var pathErr *os.PathError
				if assert.ErrorAs(t, err, &pathErr) {
					assert.Equal(t, "open", pathErr.Op)
					assert.Equal(t, tt.path, pathErr.Path)
					assert.ErrorIs(t, pathErr.Err, tt.err)
				}
			})
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "missing", "file")

		err := WriteFileAtomically(target, nil, 0644)

		var pathErr *os.PathError
		if assert.ErrorAs(t, err, &pathErr) {
			assert.Equal(t, "open", pathErr.Op)
			assert.Equal(t, filepath.Clean(filepath.Dir(target)), filepath.Clean(pathErr.Path))
			assert.ErrorIs(t, pathErr.Err, os.ErrNotExist)
		}
	})

	t.Run("target path obstructed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")

		// Obstruct the file path, so that the rename fails.
		require.NoError(t, os.Mkdir(target, 0700))

		err := WriteFileAtomically(target, nil, 0644)

		var pathErr *os.PathError
		if assert.ErrorAsf(t, err, &pathErr, "Expected a PathError: %v", err) {
			assert.Equal(t, "open", pathErr.Op)
			assert.Equal(t, target, pathErr.Path)
			assert.ErrorIsf(t, pathErr.Err, syscall.EISDIR, "Expected syscall.EISDIR: %v", pathErr.Err)
		}

		// Expect just the single directory that was created in order to obstruct the file path.
		if entries, err := os.ReadDir(dir); assert.NoError(t, err) && assert.Len(t, entries, 1) {
			e := entries[0]
			name := e.Name()
			assert.Equal(t, filepath.Base(target), name)
			assert.Truef(t, e.IsDir(), "Not a directory: %s", name)
		}
	})

	t.Run("follows symlinks", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		target := filepath.Join(dir, "target")

		require.NoError(t, os.WriteFile(real, []byte("old"), 0600))
		require.NoError(t, os.Symlink("real", filepath.Join(dir, "intermediate")))
		require.NoError(t, os.Symlink("intermediate", target))

		require.NoError(t, WriteFileAtomically(target, []byte("new"), 0644))

		if info, err := os.Lstat(target); assert.NoError(t, err) {
			if mode := info.Mode(); mode&os.ModeSymlink == 0 {
				assert.Failf(t, "Target is not a symlink", "%s", mode)
			}
		}
		if info, err := os.Lstat(real); assert.NoError(t, err) {
			assert.True(t, info.Mode().IsRegular())
			assert.Equal(t, os.FileMode(0600), info.Mode())
		}
		if content, err := readFileNoFollow(real); assert.NoError(t, err) {
			assert.Equal(t, []byte("new"), content)
		}
	})

	t.Run("follows dangling symlink", func(t *testing.T) {
		dir := t.TempDir()
		wd := filepath.Join(dir, "wd")
		require.NoError(t, os.Mkdir(wd, 0700))
		require.NoError(t, os.Symlink(filepath.Join("..", "real"), filepath.Join(wd, "target")))
		t.Chdir(wd)

		require.NoError(t, WriteFileAtomically("target", []byte(t.Name()), 0644))

		if info, err := os.Lstat(filepath.Join(wd, "target")); assert.NoError(t, err) {
			if actual := info.Mode(); actual&os.ModeSymlink == 0 {
				assert.Failf(t, "Expected target to remain a symlink", "Actual mode: %v", actual)
			}
		}

		if target, err := os.Readlink(filepath.Join(wd, "target")); assert.NoError(t, err) {
			assert.Equal(t, filepath.Join("..", "real"), target)
		}
		if content, err := readFileNoFollow(filepath.Join(dir, "real")); assert.NoError(t, err) {
			assert.Equal(t, t.Name(), string(content))
		}
	})

	t.Run("follows dangling symlink behind symlinked directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "a"), 0700))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "x", "y"), 0700))
		require.NoError(t, os.Symlink(filepath.Join("..", "x", "y"), filepath.Join(dir, "a", "s")))
		require.NoError(t, os.Symlink(filepath.Join("..", "file"), filepath.Join(dir, "x", "y", "link")))

		require.NoError(t, WriteFileAtomically(filepath.Join(dir, "a", "s", "link"), []byte(t.Name()), 0644))

		assert.NoFileExists(t, filepath.Join(dir, "a", "file"))
		if content, err := readFileNoFollow(filepath.Join(dir, "x", "file")); assert.NoError(t, err) {
			assert.Equal(t, t.Name(), string(content))
		}
	})

	t.Run("follows dangling symlink into subdirectory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub", "dir"), 0700))
		require.NoError(t, os.Symlink(filepath.Join("sub", "dir", "file"), filepath.Join(dir, "target")))

		require.NoError(t, WriteFileAtomically(filepath.Join(dir, "target"), []byte(t.Name()), 0644))

		if info, err := os.Lstat(filepath.Join(dir, "target")); assert.NoError(t, err) {
			if actual := info.Mode(); actual&os.ModeSymlink == 0 {
				assert.Failf(t, "Expected target to remain a symlink", "Actual mode: %v", actual)
			}
		}
		if content, err := readFileNoFollow(filepath.Join(dir, "sub", "dir", "file")); assert.NoError(t, err) {
			assert.Equal(t, t.Name(), string(content))
		}
	})

	t.Run("follows dangling absolute symlink", func(t *testing.T) {
		here, elsewhere := t.TempDir(), t.TempDir()
		require.NoError(t, os.Symlink(filepath.Join(elsewhere, "file"), filepath.Join(here, "target")))

		require.NoError(t, WriteFileAtomically(filepath.Join(here, "target"), []byte(t.Name()), 0644))

		if info, err := os.Lstat(filepath.Join(here, "target")); assert.NoError(t, err) {
			if actual := info.Mode(); actual&os.ModeSymlink == 0 {
				assert.Failf(t, "Expected target to remain a symlink", "Actual mode: %v", actual)
			}
		}
		if content, err := readFileNoFollow(filepath.Join(elsewhere, "file")); assert.NoError(t, err) {
			assert.Equal(t, t.Name(), string(content))
		}
	})

	t.Run("too many symlinks", func(t *testing.T) {
		dir := t.TempDir()
		for i := 1; i <= 41; i++ {
			require.NoError(t, os.Symlink("link-"+strconv.Itoa(i-1), filepath.Join(dir, "link-"+strconv.Itoa(i))))
		}

		err := WriteFileAtomically(filepath.Join(dir, "link-41"), nil, 0644)
		require.EqualError(t, err, "too many links")

		err = WriteFileAtomically(filepath.Join(dir, "link-40"), []byte("followed"), 0644)
		require.NoError(t, err)

		content, err := readFileNoFollow(filepath.Join(dir, "link-0"))
		require.NoError(t, err)
		assert.Equal(t, "followed", string(content))
	})

	t.Run("writes directly to FIFO", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "fifo")
		require.NoError(t, syscall.Mkfifo(fifo, 0600))

		fifoInfo, err := os.Lstat(fifo)
		require.NoError(t, err)

		done := make(chan struct{})
		var count atomic.Int32
		count.Add(2)
		go func() {
			defer func() {
				if count.Add(-1) == 0 {
					close(done)
				}
			}()

			if read, err := readFileNoFollow(fifo); assert.NoError(t, err) {
				assert.Equal(t, t.Name(), string(read))
			}
		}()

		go func() {
			defer func() {
				if count.Add(-1) == 0 {
					close(done)
				}
			}()

			assert.NoError(t, WriteFileAtomically(fifo, []byte(t.Name()), 0644))
		}()

		select {
		case <-done:
			if t.Failed() {
				return
			}
		case <-time.After(5 * time.Second):
			require.Fail(t, "Timed out waiting for FIFO read/write")
		}

		if info, err := os.Lstat(fifo); assert.NoError(t, err) {
			assert.Equal(t, fifoInfo.Mode(), info.Mode(), "FIFO file mode changed unexpectedly")
		}
	})
}

func readFileNoFollow(path string) (_ []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return io.ReadAll(f)
}
