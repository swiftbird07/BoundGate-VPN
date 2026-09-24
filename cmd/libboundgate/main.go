// Command libboundgate is the C interface of the embedded node for the apps
// (boundgate.h, docs/EMBED.md). Build it as a library:
//
//	go build -buildmode=c-archive -o libboundgate.a ./cmd/libboundgate   (Apple, make apple-core)
//	go build -buildmode=c-shared  -o libboundgate.so ./cmd/libboundgate  (Android)
package main

/*
#include <stdlib.h>
#include <string.h>
#define BG_TYPES_ONLY
#include "boundgate.h"

static int32_t bg_call_apply(bg_platform *p, const char *s, char **err) { return p->apply(p->ctx, s, err); }
static void bg_call_release(bg_platform *p) { p->release(p->ctx); }
static int32_t bg_call_public_key(bg_platform *p, uint8_t *out, int32_t cap, char **err) { return p->public_key(p->ctx, out, cap, err); }
static int32_t bg_call_sign(bg_platform *p, const uint8_t *d, int32_t n, uint8_t *out, int32_t cap, char **err) { return p->sign(p->ctx, d, n, out, cap, err); }
static void bg_call_log(bg_platform *p, int32_t level, const char *line) { if (p->log) p->log(p->ctx, level, line); }
static void bg_call_status_changed(bg_platform *p, const char *status) { if (p->status_changed) p->status_changed(p->ctx, status); }
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"unsafe"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/embed"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/version"
)

var (
	mu      sync.Mutex
	engines = map[int64]*engine{}
	next    int64
)

type engine struct {
	e *embed.Engine
	p *cPlatform
}

// cPlatform calls the app's callbacks. The struct lives in C memory: Go
// must not keep pointers into the app's copy.
type cPlatform struct {
	p    *C.bg_platform
	kind string
	hw   bool
}

func takeErr(cerr *C.char, what string) error {
	if cerr == nil {
		return errors.New(what + " failed")
	}
	defer C.free(unsafe.Pointer(cerr))
	return errors.New(C.GoString(cerr))
}

func (c *cPlatform) Apply(s netcfg.NetworkSettings) (int, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return -1, err
	}
	cs := C.CString(string(b))
	defer C.free(unsafe.Pointer(cs))
	var cerr *C.char
	fd := C.bg_call_apply(c.p, cs, &cerr)
	if fd < 0 {
		return -1, takeErr(cerr, "apply")
	}
	return int(fd), nil
}

func (c *cPlatform) Release() { C.bg_call_release(c.p) }

func (c *cPlatform) PublicKey() ([]byte, error) {
	buf := (*C.uint8_t)(C.malloc(512))
	defer C.free(unsafe.Pointer(buf))
	var cerr *C.char
	n := C.bg_call_public_key(c.p, buf, 512, &cerr)
	if n < 0 || n > 512 {
		return nil, takeErr(cerr, "public key")
	}
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), nil
}

func (c *cPlatform) Sign(digest []byte) ([]byte, error) {
	d := C.CBytes(digest)
	defer C.free(d)
	buf := (*C.uint8_t)(C.malloc(256))
	defer C.free(unsafe.Pointer(buf))
	var cerr *C.char
	n := C.bg_call_sign(c.p, (*C.uint8_t)(d), C.int32_t(len(digest)), buf, 256, &cerr)
	if n < 0 || n > 256 {
		return nil, takeErr(cerr, "sign")
	}
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), nil
}

func (c *cPlatform) KeyKind() string     { return c.kind }
func (c *cPlatform) HardwareBound() bool { return c.hw }

func (c *cPlatform) Log(level int, line string) {
	cs := C.CString(line)
	defer C.free(unsafe.Pointer(cs))
	C.bg_call_log(c.p, C.int32_t(level), cs)
}

// StatusChanged implements embed.StatusNotifier; an app without the
// callback hears nothing.
func (c *cPlatform) StatusChanged(statusJSON string) {
	if c.p.status_changed == nil {
		return
	}
	cs := C.CString(statusJSON)
	defer C.free(unsafe.Pointer(cs))
	C.bg_call_status_changed(c.p, cs)
}

func setErr(err **C.char, e error) {
	if err != nil {
		*err = C.CString(e.Error())
	}
}

//export bg_start
func bg_start(configJSON *C.char, platform *C.bg_platform, err **C.char) C.int64_t {
	if configJSON == nil || platform == nil || platform.apply == nil || platform.release == nil || platform.public_key == nil || platform.sign == nil {
		setErr(err, errors.New("bg_start: config and all platform callbacks except log are required"))
		return 0
	}
	var cfg embed.Config
	if e := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); e != nil {
		setErr(err, errors.New("bg_start: config: "+e.Error()))
		return 0
	}
	cp := (*C.bg_platform)(C.malloc(C.size_t(unsafe.Sizeof(C.bg_platform{}))))
	*cp = *platform
	cp.key_kind = nil // Go keeps its own copy of the string
	p := &cPlatform{p: cp, hw: platform.hardware_bound != 0}
	if platform.key_kind != nil {
		p.kind = C.GoString(platform.key_kind)
	}
	e, startErr := embed.Start(cfg, p)
	if startErr != nil {
		C.free(unsafe.Pointer(cp))
		setErr(err, startErr)
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	next++
	engines[next] = &engine{e: e, p: p}
	return C.int64_t(next)
}

func lookup(h C.int64_t) *engine {
	mu.Lock()
	defer mu.Unlock()
	return engines[int64(h)]
}

//export bg_request
func bg_request(h C.int64_t, method, path *C.char, body *C.uint8_t, bodyLen C.int32_t, status *C.int32_t) *C.char {
	en := lookup(h)
	if en == nil {
		if status != nil {
			*status = 503
		}
		return C.CString(`{"error":"no such engine"}`)
	}
	var b []byte
	if body != nil && bodyLen > 0 {
		b = C.GoBytes(unsafe.Pointer(body), C.int(bodyLen))
	}
	code, out := en.e.Request(C.GoString(method), C.GoString(path), b)
	if status != nil {
		*status = C.int32_t(code)
	}
	return C.CString(string(out))
}

//export bg_network_changed
func bg_network_changed(h C.int64_t) {
	if en := lookup(h); en != nil {
		en.e.NetworkChanged()
	}
}

//export bg_stop
func bg_stop(h C.int64_t) {
	mu.Lock()
	en := engines[int64(h)]
	delete(engines, int64(h))
	mu.Unlock()
	if en == nil {
		return
	}
	en.e.Stop()
	C.free(unsafe.Pointer(en.p.p))
}

//export bg_utun_fd
func bg_utun_fd() C.int32_t { return C.int32_t(utunFD()) }

//export bg_version
func bg_version() *C.char { return C.CString(version.Version) }

//export bg_free
func bg_free(p unsafe.Pointer) { C.free(p) }
