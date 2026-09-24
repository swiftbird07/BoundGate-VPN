package com.net407.boundgate

/**
 * libboundgate (cmd/libboundgate, docs/EMBED.md) through its JNI glue
 * (jni_android.c). One engine runs in the app's process; the VpnService
 * lives in the same process and only answers [Platform.apply].
 */
object Core {
    init {
        System.loadLibrary("boundgate")
    }

    /** What the core asks of the app. Called on the core's threads; may block. */
    interface Platform {
        /** Installs the network settings (JSON: address, mtu, routes, excluded); returns the tunnel's descriptor, which the core then owns. */
        fun apply(settingsJson: String): Int

        /** The overlay went down; the core closed the descriptor. */
        fun release()

        /** DER SubjectPublicKeyInfo of the device key (ECDSA P-256). */
        fun publicKey(): ByteArray

        /** ASN.1 DER ECDSA signature of a SHA-256 digest. */
        fun sign(digest: ByteArray): ByteArray

        /** One log line; level as in Go's log/slog (-4 debug, 0 info, 4 warn, 8 error). */
        fun log(level: Int, line: String)

        /** The node's status (JSON of GET /v1/status) whenever its state, enrollment, need for a sign-in or hub connection changed. */
        fun statusChanged(statusJson: String)
    }

    /** Starts an engine (config: embed.Config as UTF-8 JSON); throws IllegalStateException with the core's reason. */
    @JvmStatic external fun start(config: ByteArray, platform: Platform, keyKind: String, hardwareBound: Boolean): Long

    /** One request of the daemon's API; status[0] gets the HTTP status, the answer is UTF-8 JSON. */
    @JvmStatic external fun request(engine: Long, method: String, path: String, body: ByteArray?, status: IntArray): ByteArray

    @JvmStatic external fun networkChanged(engine: Long)

    @JvmStatic external fun stop(engine: Long)

    @JvmStatic external fun version(): String
}
