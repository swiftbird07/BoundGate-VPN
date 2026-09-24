// JNI glue for the Android app (docs/ANDROID.md): the functions of
// boundgate.h as the native methods of com.net407.boundgate.Core, and the
// bg_platform callbacks as calls on the app's Core.Platform object. Part of
// libboundgate.so (go build -buildmode=c-shared, GOOS=android), so the app
// loads one library.
//
// The callbacks run on threads of the Go runtime. Each attaches to the VM for
// the call and detaches again if it attached: a thread that exits while
// attached aborts the VM, and Go does not say when its threads end. The
// method IDs are looked up once in start, on the app's thread: FindClass from
// a Go thread would see the system class loader, not the app's.

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define BG_TYPES_ONLY
#include "boundgate.h"
#include "_cgo_export.h"

static JavaVM *vm;

JNIEXPORT jint JNI_OnLoad(JavaVM *v, void *reserved) {
	vm = v;
	return JNI_VERSION_1_6;
}

typedef struct jplatform {
	jobject obj; // global reference to the Core.Platform
	jmethodID apply, release, public_key, sign, log, status_changed;
	int64_t engine;
	struct jplatform *next;
} jplatform;

// the platforms of running engines, freed in stop
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static jplatform *platforms;

static JNIEnv *attach(int *attached) {
	JNIEnv *env = NULL;
	*attached = 0;
	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) return NULL;
		*attached = 1;
	}
	return env;
}

static void detach(int attached) {
	if (attached) (*vm)->DetachCurrentThread(vm);
}

// Turns a pending Java exception into *err (malloc'ed; the core frees it).
// Returns 1 if there was one.
static int caught(JNIEnv *env, char **err) {
	jthrowable ex = (*env)->ExceptionOccurred(env);
	if (!ex) return 0;
	(*env)->ExceptionClear(env);
	if (err) {
		*err = NULL;
		jclass c = (*env)->GetObjectClass(env, ex);
		jmethodID ts = (*env)->GetMethodID(env, c, "toString", "()Ljava/lang/String;");
		jstring s = ts ? (jstring)(*env)->CallObjectMethod(env, ex, ts) : NULL;
		if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
		if (s) {
			const char *u = (*env)->GetStringUTFChars(env, s, NULL);
			if (u) {
				*err = strdup(u);
				(*env)->ReleaseStringUTFChars(env, s, u);
			}
			(*env)->DeleteLocalRef(env, s);
		}
		(*env)->DeleteLocalRef(env, c);
		if (!*err) *err = strdup("the app's callback threw");
	}
	(*env)->DeleteLocalRef(env, ex);
	return 1;
}

// UTF-8 as a Java String without JNI's modified UTF-8 (NewStringUTF rejects
// characters outside the BMP): through new String(bytes, UTF_8).
static jstring jstr(JNIEnv *env, const char *s) {
	jsize n = (jsize)strlen(s);
	jbyteArray b = (*env)->NewByteArray(env, n);
	if (!b) return NULL;
	(*env)->SetByteArrayRegion(env, b, 0, n, (const jbyte *)s);
	jclass sc = (*env)->FindClass(env, "java/lang/String"); // bootstrap class: any loader finds it
	jmethodID ctor = (*env)->GetMethodID(env, sc, "<init>", "([BLjava/lang/String;)V");
	jstring cs = (*env)->NewStringUTF(env, "UTF-8");
	jstring r = (jstring)(*env)->NewObject(env, sc, ctor, b, cs);
	(*env)->DeleteLocalRef(env, cs);
	(*env)->DeleteLocalRef(env, sc);
	(*env)->DeleteLocalRef(env, b);
	return r;
}

static int32_t cb_apply(void *ctx, const char *settings, char **err) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) { *err = strdup("cannot attach to the VM"); return -1; }
	jstring s = jstr(env, settings);
	jint fd = s ? (*env)->CallIntMethod(env, p->obj, p->apply, s) : -1;
	if (caught(env, err)) fd = -1;
	else if (fd < 0) *err = strdup("the app returned no tunnel descriptor");
	if (s) (*env)->DeleteLocalRef(env, s);
	detach(attached);
	return fd;
}

static void cb_release(void *ctx) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) return;
	(*env)->CallVoidMethod(env, p->obj, p->release);
	caught(env, NULL);
	detach(attached);
}

// copies a byte[] the app returned into out; -1 with *err on failure
static int32_t take_bytes(JNIEnv *env, jbyteArray a, uint8_t *out, int32_t cap, char **err, const char *what) {
	if (caught(env, err)) return -1;
	if (!a) { *err = strdup(what); return -1; }
	jsize n = (*env)->GetArrayLength(env, a);
	if (n > cap) { (*env)->DeleteLocalRef(env, a); *err = strdup("the app's answer is too long"); return -1; }
	(*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)out);
	(*env)->DeleteLocalRef(env, a);
	return n;
}

static int32_t cb_public_key(void *ctx, uint8_t *out, int32_t cap, char **err) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) { *err = strdup("cannot attach to the VM"); return -1; }
	jbyteArray a = (jbyteArray)(*env)->CallObjectMethod(env, p->obj, p->public_key);
	int32_t n = take_bytes(env, a, out, cap, err, "the device key has no public key");
	detach(attached);
	return n;
}

static int32_t cb_sign(void *ctx, const uint8_t *digest, int32_t len, uint8_t *out, int32_t cap, char **err) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) { *err = strdup("cannot attach to the VM"); return -1; }
	jbyteArray d = (*env)->NewByteArray(env, len);
	int32_t n = -1;
	if (d) {
		(*env)->SetByteArrayRegion(env, d, 0, len, (const jbyte *)digest);
		jbyteArray a = (jbyteArray)(*env)->CallObjectMethod(env, p->obj, p->sign, d);
		n = take_bytes(env, a, out, cap, err, "the device key did not sign");
		(*env)->DeleteLocalRef(env, d);
	} else {
		caught(env, err);
	}
	detach(attached);
	return n;
}

static void cb_log(void *ctx, int32_t level, const char *line) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) return;
	jstring s = jstr(env, line);
	if (s) {
		(*env)->CallVoidMethod(env, p->obj, p->log, (jint)level, s);
		(*env)->DeleteLocalRef(env, s);
	}
	caught(env, NULL);
	detach(attached);
}

static void cb_status_changed(void *ctx, const char *status) {
	jplatform *p = ctx;
	int attached;
	JNIEnv *env = attach(&attached);
	if (!env) return;
	jstring s = jstr(env, status);
	if (s) {
		(*env)->CallVoidMethod(env, p->obj, p->status_changed, s);
		(*env)->DeleteLocalRef(env, s);
	}
	caught(env, NULL);
	detach(attached);
}

static void throw_state(JNIEnv *env, const char *msg) {
	jclass c = (*env)->FindClass(env, "java/lang/IllegalStateException");
	if (c) (*env)->ThrowNew(env, c, msg);
}

// Core.start(config: ByteArray (UTF-8 JSON), platform: Core.Platform, keyKind: String, hardwareBound: Boolean): Long
JNIEXPORT jlong JNICALL Java_com_net407_boundgate_Core_start(JNIEnv *env, jclass cls, jbyteArray config,
		jobject platform, jstring keyKind, jboolean hardwareBound) {
	jclass pc = (*env)->GetObjectClass(env, platform);
	jplatform *p = calloc(1, sizeof *p);
	if (!p) { throw_state(env, "out of memory"); return 0; }
	p->apply = (*env)->GetMethodID(env, pc, "apply", "(Ljava/lang/String;)I");
	p->release = (*env)->GetMethodID(env, pc, "release", "()V");
	p->public_key = (*env)->GetMethodID(env, pc, "publicKey", "()[B");
	p->sign = (*env)->GetMethodID(env, pc, "sign", "([B)[B");
	p->log = (*env)->GetMethodID(env, pc, "log", "(ILjava/lang/String;)V");
	p->status_changed = (*env)->GetMethodID(env, pc, "statusChanged", "(Ljava/lang/String;)V");
	(*env)->DeleteLocalRef(env, pc);
	if ((*env)->ExceptionCheck(env)) { free(p); return 0; } // NoSuchMethodError stays pending
	p->obj = (*env)->NewGlobalRef(env, platform);

	jsize n = (*env)->GetArrayLength(env, config);
	char *cfg = calloc(1, (size_t)n + 1);
	if (!cfg) { (*env)->DeleteGlobalRef(env, p->obj); free(p); throw_state(env, "out of memory"); return 0; }
	(*env)->GetByteArrayRegion(env, config, 0, n, (jbyte *)cfg);
	const char *kind = (*env)->GetStringUTFChars(env, keyKind, NULL);
	bg_platform bp = {
		.ctx = p, .apply = cb_apply, .release = cb_release, .public_key = cb_public_key,
		.sign = cb_sign, .log = cb_log, .key_kind = kind, .hardware_bound = hardwareBound ? 1 : 0,
		.status_changed = cb_status_changed,
	};
	char *err = NULL;
	int64_t h = bg_start(cfg, &bp, &err);
	(*env)->ReleaseStringUTFChars(env, keyKind, kind);
	free(cfg);
	if (h == 0) {
		(*env)->DeleteGlobalRef(env, p->obj);
		free(p);
		throw_state(env, err ? err : "the core did not start");
		free(err);
		return 0;
	}
	p->engine = h;
	pthread_mutex_lock(&mu);
	p->next = platforms;
	platforms = p;
	pthread_mutex_unlock(&mu);
	return (jlong)h;
}

// Core.request(engine: Long, method: String, path: String, body: ByteArray?, status: IntArray): ByteArray
JNIEXPORT jbyteArray JNICALL Java_com_net407_boundgate_Core_request(JNIEnv *env, jclass cls, jlong engine,
		jstring method, jstring path, jbyteArray body, jintArray status) {
	const char *m = (*env)->GetStringUTFChars(env, method, NULL);
	const char *pa = (*env)->GetStringUTFChars(env, path, NULL);
	jbyte *b = NULL;
	jsize n = 0;
	if (body) {
		n = (*env)->GetArrayLength(env, body);
		b = (*env)->GetByteArrayElements(env, body, NULL);
	}
	int32_t code = 0;
	char *out = bg_request(engine, (char *)m, (char *)pa, (uint8_t *)b, (int32_t)n, &code);
	if (b) (*env)->ReleaseByteArrayElements(env, body, b, JNI_ABORT);
	(*env)->ReleaseStringUTFChars(env, path, pa);
	(*env)->ReleaseStringUTFChars(env, method, m);
	jint c = code;
	(*env)->SetIntArrayRegion(env, status, 0, 1, &c);
	jsize len = out ? (jsize)strlen(out) : 0;
	jbyteArray r = (*env)->NewByteArray(env, len);
	if (r && len) (*env)->SetByteArrayRegion(env, r, 0, len, (const jbyte *)out);
	free(out);
	return r;
}

JNIEXPORT void JNICALL Java_com_net407_boundgate_Core_networkChanged(JNIEnv *env, jclass cls, jlong engine) {
	bg_network_changed(engine);
}

JNIEXPORT void JNICALL Java_com_net407_boundgate_Core_stop(JNIEnv *env, jclass cls, jlong engine) {
	bg_stop(engine); // the callbacks are done when it returns
	pthread_mutex_lock(&mu);
	jplatform **pp = &platforms, *p = NULL;
	while (*pp) {
		if ((*pp)->engine == engine) { p = *pp; *pp = p->next; break; }
		pp = &(*pp)->next;
	}
	pthread_mutex_unlock(&mu);
	if (p) {
		(*env)->DeleteGlobalRef(env, p->obj);
		free(p);
	}
}

JNIEXPORT jstring JNICALL Java_com_net407_boundgate_Core_version(JNIEnv *env, jclass cls) {
	char *v = bg_version();
	jstring s = jstr(env, v);
	free(v);
	return s;
}
