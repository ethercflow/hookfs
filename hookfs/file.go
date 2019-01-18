package hookfs

import (
	"fmt"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	log "github.com/sirupsen/logrus"
)

type hookFile struct {
	file nodefs.File
	name string
	hook Hook
}

func newHookFile(file nodefs.File, name string, hook Hook) (*hookFile, error) {
	log.WithFields(log.Fields{
		"file": file,
		"name": name,
	}).Debug("Hooking a file")

	hookfile := &hookFile{
		file: file,
		name: name,
		hook: hook,
	}
	return hookfile, nil
}

// implements nodefs.File
func (h *hookFile) SetInode(inode *nodefs.Inode) {
	h.file.SetInode(inode)
}

// implements nodefs.File
func (h *hookFile) String() string {
	return fmt.Sprintf("HookFile{file=%s, name=%s}", h.file.String(), h.name)
}

// implements nodefs.File
func (h *hookFile) InnerFile() nodefs.File {
	return h.file.InnerFile()
}

// implements nodefs.File
func (h *hookFile) Read(dest []byte, off int64) (fuse.ReadResult, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnRead)
	var prehookBuf, posthookBuf []byte
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"dest": dest,
		"off":  off,
		"h":    h,
	}).Trace("f.Read")

	if hookEnabled {
		prehookBuf, prehooked, prehookCtx, prehookErr = hook.PreRead(h.name, int64(len(dest)), off)
		if prehooked {
			log.WithFields(log.Fields{
				"h": h,
				// "prehookBuf": prehookBuf,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Read: Prehooked")
			return fuse.ReadResultData(prehookBuf), fuse.ToStatus(prehookErr)
		}
	}

	lowerRR, lowerCode := h.file.Read(dest, off)
	if hookEnabled {
		lowerRRBuf, lowerRRBufStatus := lowerRR.Bytes(make([]byte, lowerRR.Size()))
		if lowerRRBufStatus != fuse.OK {
			log.WithField("error", lowerRRBufStatus).Panic("lowerRR.Bytes() should not cause an error")
		}
		posthookBuf, posthooked, posthookErr = hook.PostRead(int32(lowerCode), lowerRRBuf, prehookCtx)
		if posthooked {
			if len(posthookBuf) != len(lowerRRBuf) {
				log.WithFields(log.Fields{
					"h": h,
					// "posthookBuf": posthookBuf,
					"posthookErr":    posthookErr,
					"posthookBufLen": len(posthookBuf),
					"lowerRRBufLen":  len(lowerRRBuf),
					"destLen":        len(dest),
				}).Warn("Read: Posthooked, but posthookBuf length != lowerrRRBuf length. You may get a strange behavior.")
			}

			log.WithFields(log.Fields{
				"h": h,
				// "posthookBuf": posthookBuf,
				"posthookErr": posthookErr,
			}).Debug("Read: Posthooked")
			return fuse.ReadResultData(posthookBuf), fuse.ToStatus(posthookErr)
		}
	}

	return lowerRR, lowerCode
}

// implements nodefs.File
func (h *hookFile) Write(data []byte, off int64) (uint32, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnWrite)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"data": data,
		"off":  off,
		"h":    h,
	}).Trace("f.Write")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreWrite(h.name, data, off)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Write: Prehooked")
			return 0, fuse.ToStatus(prehookErr)
		}
	}

	lowerWritten, lowerCode := h.file.Write(data, off)
	if hookEnabled {
		posthooked, posthookErr = hook.PostWrite(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Write: Posthooked")
			return 0, fuse.ToStatus(posthookErr)
		}
	}

	return lowerWritten, lowerCode
}

// implements nodefs.File
func (h *hookFile) Flush() fuse.Status {
	hook, hookEnabled := h.hook.(HookOnFlush)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{"h": h}).Trace("f.Flush")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreFlush(h.name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Flush: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Flush()
	if hookEnabled {
		posthooked, posthookErr = hook.PostFlush(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Flush: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Release() {
	hook, hookEnabled := h.hook.(HookOnRelease)
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{"h": h}).Trace("f.Release")

	if hookEnabled {
		prehooked, prehookCtx = hook.PreRelease(h.name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookCtx": prehookCtx,
			}).Debug("Release: Prehooked")
		}
	}

	h.file.Release()
	if hookEnabled {
		posthooked = hook.PostRelease(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h": h,
			}).Debug("Release: Posthooked")
		}
	}
}

// implements nodefs.File
func (h *hookFile) Fsync(flags int) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnFsync)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"flags": flags,
		"h":     h,
	}).Trace("f.Fsync")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreFsync(h.name, uint32(flags))
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Fsync: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Fsync(flags)
	if hookEnabled {
		posthooked, posthookErr = hook.PostFsync(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Fsync: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Truncate(size uint64) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnTruncate)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"size": size,
		"h":    h,
	}).Trace("f.Truncate")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreTruncate(h.name, size)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Truncate: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Truncate(size)
	if hookEnabled {
		posthooked, posthookErr = hook.PostTruncate(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Truncate: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) GetAttr(out *fuse.Attr) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnGetAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"out": out,
		"h":   h,
	}).Trace("f.GetAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreGetAttr(h.name, out)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("GetAttr: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.GetAttr(out)
	if hookEnabled {
		posthooked, posthookErr = hook.PostGetAttr(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("GetAttr: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Chown(uid uint32, gid uint32) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnChown)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"uid": uid,
		"gid": gid,
		"h":   h,
	}).Trace("f.Chown")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreChown(h.name, uid, gid)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Chown: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Chown(uid, gid)
	if hookEnabled {
		posthooked, posthookErr = hook.PostChown(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Chown: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Chmod(perms uint32) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnChmod)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"perms": perms,
		"h":     h,
	}).Trace("f.Chmod")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreChmod(h.name, perms)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Chmod: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Chmod(perms)
	if hookEnabled {
		posthooked, posthookErr = hook.PostChmod(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Chmod: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Utimens(atime *time.Time, mtime *time.Time) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnUtimens)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"atime": atime,
		"mtime": mtime,
		"h":     h,
	}).Trace("f.Utimens")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreUtimens(h.name, atime, mtime)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Utimens: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Utimens(atime, mtime)
	if hookEnabled {
		posthooked, posthookErr = hook.PostUtimens(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Utimens: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) Allocate(off uint64, size uint64, mode uint32) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnAllocate)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"off":  off,
		"size": size,
		"mode": mode,
		"h":    h,
	}).Trace("f.Allocate")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreAllocate(h.name, off, size, mode)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Allocate: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.Allocate(off, size, mode)
	if hookEnabled {
		posthooked, posthookErr = hook.PostAllocate(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Allocate: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) GetLk(owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnGetLk)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"owner": owner,
		"lk":    lk,
		"flags": flags,
		"out":   out,
		"h":     h,
	}).Trace("f.GetLk")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreGetLk(h.name, owner, lk, flags, out)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("GetLk: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.GetLk(owner, lk, flags, out)
	if hookEnabled {
		posthooked, posthookErr = hook.PostGetLk(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("GetLk: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) SetLk(owner uint64, lk *fuse.FileLock, flags uint32) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnSetLk)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"owner": owner,
		"lk":    lk,
		"flags": flags,
		"h":     h,
	}).Trace("f.SetLk")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreSetLk(h.name, owner, lk, flags)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("SetLk: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.SetLk(owner, lk, flags)
	if hookEnabled {
		posthooked, posthookErr = hook.PostSetLk(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("SetLk: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// implements nodefs.File
func (h *hookFile) SetLkw(owner uint64, lk *fuse.FileLock, flags uint32) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnSetLkw)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"owner": owner,
		"lk":    lk,
		"flags": flags,
		"h":     h,
	}).Trace("f.SetLkw")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreSetLkw(h.name, owner, lk, flags)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("SetLkw: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.file.SetLkw(owner, lk, flags)
	if hookEnabled {
		posthooked, posthookErr = hook.PostSetLkw(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("SetLkw: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}
