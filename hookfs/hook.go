package hookfs

import (
	"github.com/hanwen/go-fuse/fuse"
	"time"
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
	PostTruncate(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on getattr. This also implements Hook.
type HookOnGetAttr interface {
	// if hooked is true, the real getattr() would not be called
	PreGetAttr(path string, out *fuse.Attr) (hooked bool, ctx HookContext, err error)
	PostGetAttr(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chown. This also implements Hook.
type HookOnChown interface {
	// if hooked is true, the real chown() would not be called
	PreChown(path string, uid uint32, gid uint32) (hooked bool, ctx HookContext, err error)
	PostChown(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chmod. This also implements Hook.
type HookOnChmod interface {
	// if hooked is true, the real chmod() would not be called
	PreChmod(path string, perms uint32) (hooked bool, ctx HookContext, err error)
	PostChmod(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on chmod. This also implements Hook.
type HookOnUtimens interface {
	// if hooked is true, the real utimens() would not be called
	PreUtimens(path string, atime *time.Time, mtime *time.Time) (hooked bool, ctx HookContext, err error)
	PostUtimens(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on allocate. This also implements Hook.
type HookOnAllocate interface {
	// if hooked is true, the real allocate() would not be called
	PreAllocate(path string, off uint64, size uint64, mode uint32) (hooked bool, ctx HookContext, err error)
	PostAllocate(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on getlk. This also implements Hook.
type HookOnGetLk interface {
	// if hooked is true, the real getlk() would not be called
	PreGetLk(path string, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) (hooked bool, ctx HookContext, err error)
	PostGetLk(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on setlk. This also implements Hook.
type HookOnSetLk interface {
	// if hooked is true, the real setlk() would not be called
	PreSetLk(path string, owner uint64, lk *fuse.FileLock, flags uint32) (hooked bool, ctx HookContext, err error)
	PostSetLk(prehookCtx HookContext) (hooked bool, err error)
}

// HookOn is called on setlkm. This also implements Hook.
type HookOnSetLkw interface {
	// if hooked is true, the real setlkm() would not be called
	PreSetLkw(path string, owner uint64, lk *fuse.FileLock, flags uint32) (hooked bool, ctx HookContext, err error)
	PostSetLkw(prehookCtx HookContext) (hooked bool, err error)
}
