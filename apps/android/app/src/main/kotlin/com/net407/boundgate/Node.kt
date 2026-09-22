package com.net407.boundgate

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * The node of this phone: one engine for the process (docs/EMBED.md, "One
 * engine per state directory"), the device key, and the platform side the
 * core calls. The screen talks to it with the daemon's requests; the
 * VpnService registers itself so that [apply] can hand out the tunnel.
 */
class Node(private val context: Context) : Core.Platform {

    /** An error answer of the node; controlPin is set when enrolling needs the user to accept that key first. */
    class Refused(message: String, val controlPin: String?) : Exception(message)

    @Volatile private var engine = 0L
    @Volatile var startError: String? = null
        private set
    @Volatile var service: TunnelService? = null
    /** Why the tunnel ended on its own the last time; the screen shows it once. */
    @Volatile var tunnelError: String? = null
    private var key: DeviceKey? = null

    val keyKind: String? get() = key?.kind

    /** Starts the engine once (creates the device key the first time). Blocks; not on the main thread. */
    @Synchronized
    fun ensureStarted(): Boolean {
        if (engine != 0L) return true
        return try {
            val k = key ?: DeviceKey.loadOrCreate().also { key = it }
            engine = Core.start(config().toString().toByteArray(), this, k.kind, k.hardwareBound)
            startError = null
            true
        } catch (e: Throwable) {
            startError = e.message ?: e.toString()
            Log.e(TAG, "the core did not start", e)
            false
        }
    }

    private fun config() = JSONObject()
        .put("state_dir", File(context.filesDir, "boundgate").absolutePath)
        .put("platform", "android")
        .put("name", deviceName())
        .put("log_level", "info")

    private fun deviceName(): String =
        Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() } ?: Build.MODEL

    /** One request of the daemon's API; the answer as JSON (an array comes wrapped as {"items": …}). */
    fun request(method: String, path: String, body: JSONObject? = null): Pair<Int, JSONObject> {
        if (!ensureStarted()) return 503 to JSONObject().put("error", startError ?: "the core did not start")
        val status = IntArray(1)
        val out = String(Core.request(engine, method, path, body?.toString()?.toByteArray(), status), Charsets.UTF_8)
        val json = when {
            out.trimStart().startsWith("{") -> JSONObject(out)
            out.trimStart().startsWith("[") -> JSONObject().put("items", org.json.JSONArray(out))
            else -> JSONObject().put("error", out)
        }
        return status[0] to json
    }

    /** request, but an answer other than 200 throws [Refused]. */
    fun call(method: String, path: String, body: JSONObject? = null): JSONObject {
        val (code, json) = request(method, path, body)
        if (code != 200) {
            throw Refused(json.optString("error").ifEmpty { "HTTP $code" }, json.optString("control_pin").ifEmpty { null })
        }
        return json
    }

    fun networkChanged() {
        if (engine != 0L) Core.networkChanged(engine)
    }

    // Core.Platform

    override fun apply(settingsJson: String): Int {
        val s = service ?: throw IllegalStateException("the VPN service is not running")
        return s.establish(JSONObject(settingsJson))
    }

    override fun release() {
        service?.released()
    }

    override fun publicKey(): ByteArray = key!!.publicKey

    override fun sign(digest: ByteArray): ByteArray = key!!.sign(digest)

    override fun log(level: Int, line: String) {
        val priority = when {
            level >= 8 -> Log.ERROR
            level >= 4 -> Log.WARN
            level >= 0 -> Log.INFO
            else -> Log.DEBUG
        }
        Log.println(priority, TAG, line)
    }

    companion object {
        const val TAG = "BoundGate"
    }
}
