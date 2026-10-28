package com.net407.boundgate

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
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
    /** The routing profile the person chose (docs/PROFILES.md): "" is full, the node's default. */
    var profile: String
        get() = context.getSharedPreferences("settings", Context.MODE_PRIVATE).getString("profile", "") ?: ""
        set(v) = context.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().putString("profile", v).apply()
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
            DebugLog.log("node", "engine start key=${k.kind} hardware=${k.hardwareBound}")
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
        .put("log_level", if (DebugLog.enabled) "debug" else "info")

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

    /** The debug log was switched: the core logs at debug while it is on. */
    fun setDebug(on: Boolean) {
        if (engine == 0L) return
        Core.setLogLevel(engine, if (on) "debug" else "info")?.let { Log.w(TAG, "log level: $it") }
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

    /**
     * The session ended (24 h by default) while the phone was in a pocket:
     * the tunnel stays up and carries nothing until the person signs in
     * again. Tell them once per occasion (channel "attention"; the activity
     * asks for the permission on its first start).
     */
    override fun statusChanged(statusJson: String) {
        val s = try { JSONObject(statusJson) } catch (e: Exception) { return }
        if (DebugLog.enabled) {
            val hubs = s.optJSONArray("hubs")?.let { h -> (0 until h.length()).map { h.getJSONObject(it) } }.orEmpty()
            DebugLog.log("status", "state=${s.optString("state")} profile=${s.optString("profile")} routes=${s.optJSONArray("routes")?.length() ?: 0} " +
                "login_required=${s.optBoolean("login_required")} hubs=${hubs.joinToString(" ") { "${it.optString("name")}:${it.optString("state")}${it.optString("transport").let { t -> if (t.isEmpty()) "" else "/$t" }}${it.optString("error").let { e -> if (e.isEmpty()) "" else "(${e.take(120)})" }}" }} " +
                "last_error=${s.optString("last_error").take(160)} control_error=${s.optString("control_error").take(160)}")
        }
        VpnTileService.TileState.of(s).let { if (it != tileState) { tileState = it; VpnTileService.refresh(context) } }
        val hubs = s.optJSONArray("hubs")
        var connected = false
        for (i in 0 until (hubs?.length() ?: 0)) if (hubs!!.getJSONObject(i).optString("state") == "connected") connected = true
        val needsSignIn = s.optBoolean("login_required") && !connected
        // a node refused a connection that a signed-in user would be let
        // through (sign_in, only while nobody is signed in): once per refusal
        val hint = s.optJSONObject("sign_in")
        val hintAt = hint?.optString("at")?.takeIf { it.isNotEmpty() }
        val nm = context.getSystemService(NotificationManager::class.java)
        if (hint != null && hintAt != null && hintAt != signInHintAt) {
            val port = hint.optInt("port")
            val addr = if (port != 0) "${hint.optString("dst")}:$port" else hint.optString("dst")
            notifySignIn(nm, "Sign in to reach ${hint.optString("name").ifEmpty { addr }}",
                "The network lets this through only for a signed-in user. Tap to sign in.")
        } else if (needsSignIn && !signInShown) {
            notifySignIn(nm, "Sign-in needed", "Your BoundGate session has ended. Tap to sign in again.")
        } else if (!needsSignIn && (signInShown || signInHintAt != null && hintAt == null)) {
            nm.cancel(SIGN_IN_ID)
        }
        signInShown = needsSignIn
        signInHintAt = hintAt
    }
    @Volatile private var signInShown = false
    @Volatile private var tileState: VpnTileService.TileState? = null
    @Volatile private var signInHintAt: String? = null

    /** Tapping it opens the app and starts the sign-in (MainActivity.ACTION_SIGN_IN). */
    private fun notifySignIn(nm: NotificationManager, title: String, text: String) {
        nm.createNotificationChannel(NotificationChannel(ATTENTION, "Sign-in", NotificationManager.IMPORTANCE_HIGH))
        val intent = LaunchToken.stamp(context, Intent(context, MainActivity::class.java).setAction(MainActivity.ACTION_SIGN_IN))
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val open = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(context, ATTENTION)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try { nm.notify(SIGN_IN_ID, n) } catch (e: SecurityException) { Log.w(TAG, "no notification: ${e.message}") }
    }

    override fun log(level: Int, line: String) {
        DebugLog.log("core", line)
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
        private const val ATTENTION = "attention"
        private const val SIGN_IN_ID = 2
    }
}
