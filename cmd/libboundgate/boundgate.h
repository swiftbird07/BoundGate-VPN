// libboundgate: the BoundGate node as a library for the apps (docs/EMBED.md).
//
// Built with `go build -buildmode=c-archive` (Apple: make apple-core) or
// c-shared (Android). Every function may be called from any thread. The
// callbacks are called on threads of the core; they may block (apply waits
// for the platform to install the settings) but must not call back into
// bg_stop of the same engine.
//
// Memory: strings the core returns are freed by the caller with bg_free.
// Error strings a callback returns through `char **err` are allocated with
// malloc (strdup) by the app and freed by the core. Strings passed into a
// callback are valid for the duration of the call only.
#ifndef BOUNDGATE_H
#define BOUNDGATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bg_platform {
	void *ctx;
	// Installs the network settings (JSON: address, mtu, routes, excluded)
	// and returns the tunnel's file descriptor, or -1 with *err set.
	int32_t (*apply)(void *ctx, const char *settings_json, char **err);
	// The overlay went down; the core closed the descriptor.
	void (*release)(void *ctx);
	// Writes the DER SubjectPublicKeyInfo of the device key (ECDSA P-256)
	// to out and returns its length, or -1 with *err set.
	int32_t (*public_key)(void *ctx, uint8_t *out, int32_t cap, char **err);
	// Signs a SHA-256 digest with the device key: ASN.1 DER signature into
	// out, returns its length, or -1 with *err set.
	int32_t (*sign)(void *ctx, const uint8_t *digest, int32_t digest_len, uint8_t *out, int32_t cap, char **err);
	// One log line (without timestamp); level as in Go's log/slog:
	// -4 debug, 0 info, 4 warn, 8 error.
	void (*log)(void *ctx, int32_t level, const char *line);
	// secure-enclave, android-keystore, android-strongbox, softkey (copied)
	const char *key_kind;
	int32_t hardware_bound;
} bg_platform;

// The Go side declares the functions itself (cgo's export header), in its own
// spelling; it includes this header for the types only.
#ifndef BG_TYPES_ONLY

// Starts an engine. config_json: embed.Config (state_dir, platform, name,
// auto_up, memory_limit_mib, ...). The platform struct is copied; ctx must
// stay valid until bg_stop returns. Returns a handle > 0, or 0 with *err set
// (free with bg_free). An error starting with "embed: busy" means another
// engine (app or extension) holds the state directory.
int64_t bg_start(const char *config_json, const bg_platform *platform, char **err);

// Serves one request of the daemon's API (GET /v1/status, POST /v1/up, ...).
// Returns the JSON answer (free with bg_free) and sets *status to the HTTP
// status code. May block for as long as the request takes (login waits up
// to 50 s).
char *bg_request(int64_t engine, const char *method, const char *path, const uint8_t *body, int32_t body_len, int32_t *status);

// The device moved to another network (Wi-Fi <-> cellular).
void bg_network_changed(int64_t engine);

// Takes the overlay down and releases the state directory.
void bg_stop(int64_t engine);

// macOS/iOS network extension: the descriptor of the extension's utun
// (after the network settings were applied), or -1.
int32_t bg_utun_fd(void);

// Release tag of the core, e.g. "v0.1.5" or "dev" (free with bg_free).
char *bg_version(void);

void bg_free(void *p);

#endif // BG_TYPES_ONLY

#ifdef __cplusplus
}
#endif

#endif
