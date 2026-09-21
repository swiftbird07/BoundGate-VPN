// C check of libboundgate's interface (make test-lib): what the apps do,
// from C, without a tunnel. The key is a fixed P-256 public key; signing
// is refused, so the node cannot start after configure and the engine
// stays in setup mode: that is what this checks, together with ownership
// of strings, the state lock and the log callback.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boundgate.h"

static const uint8_t spki[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x09, 0xd2, 0xbf, 0x68, 0x67, 0xe9, 0x6e, 0x73, 0xa0, 0xda, 0x18, 0x15, 0xc5, 0xeb, 0x57, 0xe3, 0xe6, 0xc8, 0x14, 0xa1, 0x33, 0x89, 0xd1, 0xcc, 0xb8, 0x28, 0xc0, 0xa4, 0x68, 0xa5, 0x3e, 0xd8, 0x7f, 0xc3, 0x69, 0x47, 0xe7, 0x13, 0xe1, 0xfb, 0x5b, 0xc7, 0x12, 0x51, 0x76, 0x7c, 0x12, 0x94, 0xa8, 0x20, 0xb6, 0xa2, 0x0a, 0xd2, 0x11, 0x53, 0xc1, 0x4a, 0x14, 0xc5, 0x53, 0x17, 0x58, 0xb2 };
static const char *fingerprint = "09ad a69f c5ee b691 fb94 5d28 71a9 67f1 1207 b1cb a9aa 923f 2ffb 179b 2406 1182";

struct app { int signs, logs, applies; };

static int32_t apply(void *ctx, const char *s, char **err) { ((struct app *)ctx)->applies++; *err = strdup("no tunnel in this test"); return -1; }
static void release(void *ctx) {}
static int32_t public_key(void *ctx, uint8_t *out, int32_t cap, char **err) {
	if (cap < (int32_t)sizeof spki) { *err = strdup("buffer too small"); return -1; }
	memcpy(out, spki, sizeof spki);
	return sizeof spki;
}
static int32_t sign(void *ctx, const uint8_t *d, int32_t n, uint8_t *out, int32_t cap, char **err) {
	((struct app *)ctx)->signs++;
	*err = strdup(n == 32 ? "the user cancelled" : "not a SHA-256 digest");
	return -1;
}
static void logline(void *ctx, int32_t level, const char *line) { ((struct app *)ctx)->logs++; }

#define CHECK(c, ...) do { if (!(c)) { fprintf(stderr, "FAIL: " __VA_ARGS__); fputc('\n', stderr); exit(1); } } while (0)

static char *req(int64_t e, const char *m, const char *p, const char *body, int32_t *st) {
	return bg_request(e, m, p, (const uint8_t *)body, body ? (int32_t)strlen(body) : 0, st);
}

int main(int argc, char **argv) {
	struct app a = {0};
	bg_platform p = { .ctx = &a, .apply = apply, .release = release, .public_key = public_key, .sign = sign, .log = logline, .key_kind = "secure-enclave", .hardware_bound = 1 };
	char cfg[512];
	snprintf(cfg, sizeof cfg, "{\"state_dir\":\"%s\",\"platform\":\"ios\",\"name\":\"harness\",\"log_level\":\"debug\"}", argv[1]);
	char *err = NULL;
	int64_t e = bg_start(cfg, &p, &err);
	CHECK(e > 0, "bg_start: %s", err ? err : "?");

	int32_t st = 0;
	char *out = req(e, "GET", "/v1/status", NULL, &st);
	CHECK(st == 200 && strstr(out, "\"state\":\"unconfigured\"") && strstr(out, fingerprint) && strstr(out, "\"key_kind\":\"secure-enclave\"") && strstr(out, "\"hardware_bound\":true"), "status %d %s", st, out);
	bg_free(out);

	int64_t e2 = bg_start(cfg, &p, &err);
	CHECK(e2 == 0 && err && strstr(err, "embed: busy"), "second engine: %s", err ? err : "started");
	bg_free(err);
	err = NULL;

	out = req(e, "POST", "/v1/configure", "{\"control_addr\":\"127.0.0.1:1\"}", &st);
	CHECK(st == 500 && strstr(out, "the user cancelled"), "configure without a signature: %d %s", st, out);
	bg_free(out);
	CHECK(a.signs >= 1, "the device certificate was not signed through the callback");
	out = req(e, "GET", "/v1/status", NULL, &st);
	CHECK(st == 200 && strstr(out, "unconfigured"), "a node without a signature must not run: %s", out);
	bg_free(out);
	CHECK(a.logs > 0, "no log lines");

	out = req(e, "GET", "/v1/nothing", NULL, &st);
	CHECK(st == 409, "unknown path in setup mode: %d", st);
	bg_free(out);

	char *v = bg_version();
	CHECK(v && *v, "version");
	bg_free(v);
	CHECK(bg_utun_fd() == -1, "a utun outside a network extension");

	bg_stop(e);
	out = req(e, "GET", "/v1/status", NULL, &st);
	CHECK(st == 503, "stopped engine answered %d", st);
	bg_free(out);
	e = bg_start(cfg, &p, &err);
	CHECK(e > 0, "restart after stop: %s", err ? err : "?");
	bg_stop(e);
	puts("libboundgate: PASS");
	return 0;
}
