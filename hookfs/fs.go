package hookfs

import (
	"fmt"
	"time"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"
	"github.com/hanwen/go-fuse/fuse/pathfs"
	log "github.com/sirupsen/logrus"
)

// HookFs is the object hooking the fs.
type HookFs struct {
	Original   string
	Mountpoint string
	FsName     string
	fs         pathfs.FileSystem
	hook       Hook
}

// NewHookFs creates a new HookFs object
func NewHookFs(original string, mountpoint string, hook Hook) (*HookFs, error) {
	log.WithFields(log.Fields{
		"original":   original,
		"mountpoint": mountpoint,
	}).Debug("Hooking a fs")

	loopbackfs := pathfs.NewLoopbackFileSystem(original)
	hookfs := &HookFs{
		Original:   original,
		Mountpoint: mountpoint,
		FsName:     "hookfs",
		fs:         loopbackfs,
		hook:       hook,
	}
	return hookfs, nil
}

// String implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) String() string {
	return fmt.Sprintf("HookFs{Original=%s, Mountpoint=%s, FsName=%s, Underlying fs=%s, hook=%s}",
		h.Original, h.Mountpoint, h.FsName, h.fs.String(), h.hook)
}

// SetDebug implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) SetDebug(debug bool) {
	h.fs.SetDebug(debug)
}

// GetAttr implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) GetAttr(name string, context *fuse.Context) (*fuse.Attr, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnGetAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.GetAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreGetAttr(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("GetAttr: Prehooked")
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	attr, lowerCode := h.fs.GetAttr(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostGetAttr(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("GetAttr: Posthooked")
			return attr, fuse.ToStatus(posthookErr)
		}
	}

	return attr, lowerCode
}

// Chmod implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Chmod(name string, mode uint32, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnChmod)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"mode": mode,
		"h":    h,
	}).Trace("fs.Chmod")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreChmod(name, mode)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Chmod: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Chmod(name, mode, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostChmod(int32(lowerCode), prehookCtx)
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

// Chown implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Chown(name string, uid uint32, gid uint32, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnChown)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"uid":  uid,
		"gid":  gid,
		"h":    h,
	}).Trace("fs.Chown")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreChown(name, uid, gid)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Chown: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Chown(name, uid, gid, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostChown(int32(lowerCode), prehookCtx)
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

// Utimens implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Utimens(name string, Atime *time.Time, Mtime *time.Time, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnUtimens)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name":  name,
		"atime": Atime,
		"mtime": Mtime,
		"h":     h,
	}).Trace("fs.Utimens")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreUtimens(name, Atime, Mtime)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Utimens: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Utimens(name, Atime, Mtime, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostUtimens(int32(lowerCode), prehookCtx)
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

// Truncate implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Truncate(name string, size uint64, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnTruncate)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"size": size,
		"h":    h,
	}).Trace("fs.Truncate")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreTruncate(name, size)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Truncate: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Truncate(name, size, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostTruncate(int32(lowerCode), prehookCtx)
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

// Access implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Access(name string, mode uint32, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnAccess)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"mode": mode,
		"h":    h,
	}).Trace("fs.Access")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreAccess(name, mode)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Access: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Access(name, mode, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostAccess(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Access: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Link implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Link(oldName string, newName string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnLink)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"oldName": oldName,
		"newName": newName,
		"h":       h,
	}).Trace("fs.Link")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreLink(oldName, newName)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Link: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Link(oldName, newName, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostLink(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Link: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Mkdir implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Mkdir(name string, mode uint32, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnMkdir)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"mode": mode,
		"h":    h,
	}).Trace("fs.Mkdir")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreMkdir(name, mode)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Mkdir: Prehooked")
			if prehookErr == nil {
				log.WithFields(log.Fields{
					"h":          h,
					"prehookErr": prehookErr,
					"prehookCtx": prehookCtx,
				}).Fatal("Mkdir is prehooked, but did not returned an error. h is very strange.")
			}
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Mkdir(name, mode, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostMkdir(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Mkdir: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Mknod implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Mknod(name string, mode uint32, dev uint32, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnMknod)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"mode": mode,
		"dev":  dev,
		"h":    h,
	}).Trace("fs.Mknod")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreMknod(name, mode, dev)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Mknod: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Mknod(name, mode, dev, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostMknod(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Mknod: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Rename implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Rename(oldName string, newName string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnRename)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"oldName": oldName,
		"newName": newName,
		"h":       h,
	}).Trace("fs.Rename")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreRename(oldName, newName)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Rename: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Rename(oldName, newName, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostRename(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Rename: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Rmdir implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Rmdir(name string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnRmdir)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.Rmdir")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreRmdir(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Rmdir: Prehooked")
			if prehookErr == nil {
				log.WithFields(log.Fields{
					"h":          h,
					"prehookErr": prehookErr,
					"prehookCtx": prehookCtx,
				}).Fatal("Rmdir is prehooked, but did not returned an error. h is very strange.")
			}
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Rmdir(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostRmdir(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Rmdir: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Unlink implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Unlink(name string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnUnlink)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.Unlink")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreUnlink(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Unlink: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Unlink(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostUnlink(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Unlink: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// GetXAttr implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) GetXAttr(name string, attribute string, context *fuse.Context) ([]byte, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnGetXAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name":      name,
		"attribute": attribute,
		"h":         h,
	}).Trace("fs.CetXAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreGetXAttr(name, attribute)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("GetXAttr: Prehooked")
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	attr, lowerCode := h.fs.GetXAttr(name, attribute, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostGetXAttr(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("GetXAttr: Posthooked")
			return attr, fuse.ToStatus(posthookErr)
		}
	}

	return attr, lowerCode
}

// ListXAttr implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) ListXAttr(name string, context *fuse.Context) ([]string, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnListXAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.ListXAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreListXAttr(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("ListXAttr: Prehooked")
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	attr, lowerCode := h.fs.ListXAttr(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostListXAttr(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("ListXAttr: Posthooked")
			return attr, fuse.ToStatus(posthookErr)
		}
	}

	return attr, lowerCode
}

// RemoveXAttr implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) RemoveXAttr(name string, attr string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnRemoveXAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"attr": attr,
		"h":    h,
	}).Trace("fs.RemoveXAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreRemoveXAttr(name, attr)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("RemoveXAttr: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.RemoveXAttr(name, attr, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostRemoveXAttr(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("RemoveXAttr: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// SetXAttr implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) SetXAttr(name string, attr string, data []byte, flags int, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnSetXAttr)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name":  name,
		"attr":  attr,
		"data":  data,
		"flags": flags,
		"h":     h,
	}).Trace("fs.SetXAttr")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreSetXAttr(name, attr, data, flags)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("SetXAttr: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.SetXAttr(name, attr, data, flags, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostSetXAttr(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("SetXAttr: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// OnMount implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) OnMount(nodeFs *pathfs.PathNodeFs) {
	log.WithFields(log.Fields{
		"h": h,
	}).Trace("fs.OnMount")

	h.fs.OnMount(nodeFs)
	hook, hookEnabled := h.hook.(HookWithInit)
	if hookEnabled {
		err := hook.Init()
		if err != nil {
			log.Error(err)
			log.Warn("Disabling hook")
			h.hook = nil
		}
	}
}

// OnUnmount implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) OnUnmount() {
	log.WithFields(log.Fields{
		"h": h,
	}).Trace("fs.OnUnmount")

	h.fs.OnUnmount()
}

// Open implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Open(name string, flags uint32, context *fuse.Context) (nodefs.File, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnOpen)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name":  name,
		"flags": flags,
		"h":     h,
	}).Trace("fs.Open")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreOpen(name, flags)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Open: Prehooked")
			if prehookErr == nil {
				log.WithFields(log.Fields{
					"h":          h,
					"prehookErr": prehookErr,
					"prehookCtx": prehookCtx,
				}).Fatal("Open is prehooked, but did not returned an error. h is very strange.")
			}
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	lowerFile, lowerCode := h.fs.Open(name, flags, context)
	hFile, hErr := newHookFile(lowerFile, name, h.hook)
	if hErr != nil {
		log.WithField("error", hErr).Panic("NewHookFile() should not cause an error")
	}

	if hookEnabled {
		posthooked, posthookErr = hook.PostOpen(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Open: Posthooked")
			return hFile, fuse.ToStatus(posthookErr)
		}
	}

	return hFile, lowerCode
}

// Create implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Create(name string, flags uint32, mode uint32, context *fuse.Context) (nodefs.File, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnCreate)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name":  name,
		"flags": flags,
		"mode":  mode,
		"h":     h,
	}).Trace("fs.Create")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreCreate(name, flags, mode)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Create: Prehooked")
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	lowerFile, lowerCode := h.fs.Create(name, flags, mode, context)
	hFile, hErr := newHookFile(lowerFile, name, h.hook)
	if hErr != nil {
		log.WithField("error", hErr).Panic("NewHookFile() should not cause an error")
	}

	if hookEnabled {
		posthooked, posthookErr = hook.PostCreate(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Create: Posthooked")
			return hFile, fuse.ToStatus(posthookErr)
		}
	}

	return hFile, lowerCode
}

// OpenDir implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) OpenDir(name string, context *fuse.Context) ([]fuse.DirEntry, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnOpenDir)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.OpenDir")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreOpenDir(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("OpenDir: Prehooked")
			if prehookErr == nil {
				log.WithFields(log.Fields{
					"h":          h,
					"prehookErr": prehookErr,
					"prehookCtx": prehookCtx,
				}).Fatal("OpenDir is prehooked, but did not returned an error. h is very strange.")
			}
			return nil, fuse.ToStatus(prehookErr)
		}
	}

	lowerEnts, lowerCode := h.fs.OpenDir(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostOpenDir(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("OpenDir: Posthooked")
			return lowerEnts, fuse.ToStatus(posthookErr)
		}
	}

	return lowerEnts, lowerCode
}

// Symlink implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Symlink(value string, linkName string, context *fuse.Context) fuse.Status {
	hook, hookEnabled := h.hook.(HookOnSymlink)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"value":    value,
		"linkName": linkName,
		"h":        h,
	}).Trace("fs.Symlink")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreSymlink(value, linkName)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Symlink: Prehooked")
			return fuse.ToStatus(prehookErr)
		}
	}

	lowerCode := h.fs.Symlink(value, linkName, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostSymlink(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Symlink: Posthooked")
			return fuse.ToStatus(posthookErr)
		}
	}

	return lowerCode
}

// Readlink implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) Readlink(name string, context *fuse.Context) (string, fuse.Status) {
	hook, hookEnabled := h.hook.(HookOnReadlink)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.Readlink")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreReadlink(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("Readlink: Prehooked")
			return "", fuse.ToStatus(prehookErr)
		}
	}

	link, lowerCode := h.fs.Readlink(name, context)
	if hookEnabled {
		posthooked, posthookErr = hook.PostReadlink(int32(lowerCode), prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("Readlink: Posthooked")
			return link, fuse.ToStatus(posthookErr)
		}
	}

	return link, lowerCode
}

// StatFs implements hanwen/go-fuse/fuse/pathfs.FileSystem. You are not expected to call h manually.
func (h *HookFs) StatFs(name string) *fuse.StatfsOut {
	hook, hookEnabled := h.hook.(HookOnStatFs)
	var prehookErr, posthookErr error
	var prehooked, posthooked bool
	var prehookCtx HookContext

	log.WithFields(log.Fields{
		"name": name,
		"h":    h,
	}).Trace("fs.StatFs")

	if hookEnabled {
		prehooked, prehookCtx, prehookErr = hook.PreStatFs(name)
		if prehooked {
			log.WithFields(log.Fields{
				"h":          h,
				"prehookErr": prehookErr,
				"prehookCtx": prehookCtx,
			}).Debug("StatFs: Prehooked")
			return nil
		}
	}

	out := h.fs.StatFs(name)
	if hookEnabled {
		posthooked, posthookErr = hook.PostStatFs(prehookCtx)
		if posthooked {
			log.WithFields(log.Fields{
				"h":           h,
				"posthookErr": posthookErr,
			}).Debug("StatFs: Posthooked")
			return out
		}
	}

	return out
}

// Serve starts the server (blocking).
func (h *HookFs) Serve() error {
	server, err := newHookServer(h)
	if err != nil {
		return err
	}
	server.Serve()
	return nil
}
