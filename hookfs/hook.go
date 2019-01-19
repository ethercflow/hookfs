package hookfs

import (
	"time"

	"github.com/hanwen/go-fuse/fuse"
)

// Hook is the base interface for user-written hooks.
//
// You have to implement HookXXX (e.g. HookOnOpen, HookOnRead, HookOnWrite, ..) interfaces.
type Hook interface{}

// HookContext is the context objects for interaction between prehooks and posthooks.
type HookContext interface{}

// HookWithInit is called on mount. This also implements Hook.
type HookWithInit interface {
	Init() (err error)
}

// HookOnOpen is called on open. This also implements Hook.
type HookOnOpen interface {
	// if hooked is true, the real open() would not be called
	PreOpen(path string, flags uint32) (hooked bool, ctx HookContext, err error)
	PostOpen(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnRead is called on read. This also implements Hook.
type HookOnRead interface {
	// if hooked is true, the real read() would not be called
	PreRead(path string, length int64, offset int64) (buf []byte, hooked bool, ctx HookContext, err error)
	PostRead(realRetCode int32, realBuf []byte, prehookCtx HookContext) (buf []byte, hooked bool, err error)
}

// HookOnWrite is called on write. This also implements Hook.
type HookOnWrite interface {
	// if hooked is true, the real write() would not be called
	PreWrite(path string, buf []byte, offset int64) (hooked bool, ctx HookContext, err error)
	PostWrite(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnMkdir is called on mkdir. This also implements Hook.
type HookOnMkdir interface {
	// if hooked is true, the real mkdir() would not be called
	PreMkdir(path string, mode uint32) (hooked bool, ctx HookContext, err error)
	PostMkdir(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnRmdir is called on rmdir. This also implements Hook.
type HookOnRmdir interface {
	// if hooked is true, the real rmdir() would not be called
	PreRmdir(path string) (hooked bool, ctx HookContext, err error)
	PostRmdir(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnOpenDir is called on opendir. This also implements Hook.
type HookOnOpenDir interface {
	// if hooked is true, the real opendir() would not be called
	PreOpenDir(path string) (hooked bool, ctx HookContext, err error)
	PostOpenDir(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnFsync is called on fsync. This also implements Hook.
type HookOnFsync interface {
	// if hooked is true, the real fsync() would not be called
	PreFsync(path string, flags uint32) (hooked bool, ctx HookContext, err error)
	PostFsync(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnFlush is called on flush. This also implements Hook.
type HookOnFlush interface {
	// if hooked is true, the real flush() would not be called
	PreFlush(path string) (hooked bool, ctx HookContext, err error)
	PostFlush(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOnRelease is called on release. This also implements Hook.
type HookOnRelease interface {
	// if hooked is true, the real release() would not be called
	PreRelease(path string) (hooked bool, ctx HookContext)
	PostRelease(prehookCtx HookContext) (hooked bool)
}

// HookOn is called on release. This also implements Hook.
type HookOnTruncate interface {
	// if hooked is true, the real release() would not be called
	PreTruncate(path string, size uint64) (hooked bool, ctx HookContext, err error)
	PostTruncate(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on getattr. This also implements Hook.
type HookOnGetAttr interface {
	// if hooked is true, the real getattr() would not be called
	PreGetAttr(path string) (hooked bool, ctx HookContext, err error)
	PostGetAttr(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chown. This also implements Hook.
type HookOnChown interface {
	// if hooked is true, the real chown() would not be called
	PreChown(path string, uid uint32, gid uint32) (hooked bool, ctx HookContext, err error)
	PostChown(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chmod. This also implements Hook.
type HookOnChmod interface {
	// if hooked is true, the real chmod() would not be called
	PreChmod(path string, perms uint32) (hooked bool, ctx HookContext, err error)
	PostChmod(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chmod. This also implements Hook.
type HookOnUtimens interface {
	// if hooked is true, the real utimens() would not be called
	PreUtimens(path string, atime *time.Time, mtime *time.Time) (hooked bool, ctx HookContext, err error)
	PostUtimens(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on allocate. This also implements Hook.
type HookOnAllocate interface {
	// if hooked is true, the real allocate() would not be called
	PreAllocate(path string, off uint64, size uint64, mode uint32) (hooked bool, ctx HookContext, err error)
	PostAllocate(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on getlk. This also implements Hook.
type HookOnGetLk interface {
	// if hooked is true, the real getlk() would not be called
	PreGetLk(path string, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) (hooked bool, ctx HookContext, err error)
	PostGetLk(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on setlk. This also implements Hook.
type HookOnSetLk interface {
	// if hooked is true, the real setlk() would not be called
	PreSetLk(path string, owner uint64, lk *fuse.FileLock, flags uint32) (hooked bool, ctx HookContext, err error)
	PostSetLk(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on setlkm. This also implements Hook.
type HookOnSetLkw interface {
	// if hooked is true, the real setlkw() would not be called
	PreSetLkw(path string, owner uint64, lk *fuse.FileLock, flags uint32) (hooked bool, ctx HookContext, err error)
	PostSetLkw(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on statfs. This also implements Hook.
type HookOnStatFs interface {
	// if hooked is true, the real statfs) would not be called
	PreStatFs(path string) (hooked bool, ctx HookContext, err error)
	PostStatFs(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on readlink. This also implements Hook.
type HookOnReadlink interface {
	// if hooked is true, the real readlink() would not be called
	PreReadlink(name string) (hooked bool, ctx HookContext, err error)
	PostReadlink(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on symink. This also implements Hook.
type HookOnSymlink interface {
	// if hooked is true, the real symlink() would not be called
	PreSymlink(value string, linkName string) (hooked bool, ctx HookContext, err error)
	PostSymlink(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on create. This also implements Hook.
type HookOnCreate interface {
	// if hooked is true, the real create() would not be called
	PreCreate(name string, flags uint32, mode uint32) (hooked bool, ctx HookContext, err error)
	PostCreate(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on access. This also implements Hook.
type HookOnAccess interface {
	// if hooked is true, the real access() would not be called
	PreAccess(name string, mode uint32) (hooked bool, ctx HookContext, err error)
	PostAccess(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on link. This also implements Hook.
type HookOnLink interface {
	// if hooked is true, the real link() would not be called
	PreLink(oldName string, newName string) (hooked bool, ctx HookContext, err error)
	PostLink(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on mknod. This also implements Hook.
type HookOnMknod interface {
	// if hooked is true, the real mknod() would not be called
	PreMknod(name string, mode uint32, dev uint32) (hooked bool, ctx HookContext, err error)
	PostMknod(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on rename. This also implements Hook.
type HookOnRename interface {
	// if hooked is true, the real rename() would not be called
	PreRename(oldName string, newName string) (hooked bool, ctx HookContext, err error)
	PostRename(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on unlink. This also implements Hook.
type HookOnUnlink interface {
	// if hooked is true, the real rename() would not be called
	PreUnlink(name string) (hooked bool, ctx HookContext, err error)
	PostUnlink(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on getxattr. This also implements Hook.
type HookOnGetXAttr interface {
	// if hooked is true, the real getxattr() would not be called
	PreGetXAttr(name string, attribute string) (hooked bool, ctx HookContext, err error)
	PostGetXAttr(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on listxattr. This also implements Hook.
type HookOnListXAttr interface {
	// if hooked is true, the real listxattr() would not be called
	PreListXAttr(name string) (hooked bool, ctx HookContext, err error)
	PostListXAttr(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on removeattr. This also implements Hook.
type HookOnRemoveXAttr interface {
	// if hooked is true, the real removexattr() would not be called
	PreRemoveXAttr(name string, attr string) (hooked bool, ctx HookContext, err error)
	PostRemoveXAttr(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on setxattr. This also implements Hook.
type HookOnSetXAttr interface {
	// if hooked is true, the real setxattr() would not be called
	PreSetXAttr(name string, attr string, data []byte, flags int) (hooked bool, ctx HookContext, err error)
	PostSetXAttr(realRetCode int32, prehookCtx HookContext) (hooked bool, err error)
}